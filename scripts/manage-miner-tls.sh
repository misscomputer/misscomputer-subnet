#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

# Generate and rotate self-signed, numeric-IP miner leaf certificates without
# ever printing private material. This tool only writes beneath the explicit
# operator-owned root passed as argument; repository-local output is refused.
umask 077

usage() {
  echo "usage: $0 issue ROOT NUMERIC_IP [DAYS]" >&2
  echo "       $0 rotate ROOT NUMERIC_IP [DAYS]" >&2
  echo "       $0 rollback ROOT" >&2
  echo "       $0 check ROOT [WARN_BEFORE_SECONDS]" >&2
  exit 2
}

fail() {
  echo "miner TLS: $*" >&2
  exit 1
}

command -v openssl >/dev/null 2>&1 || fail "openssl is required"
TLS_PYTHON=${PYTHON:-python3}
command -v "$TLS_PYTHON" >/dev/null 2>&1 || fail "python3 is required"

ACTION="${1:-}"
TLS_ROOT="${2:-}"
[ -n "$ACTION" ] && [ -n "$TLS_ROOT" ] || usage
case "$TLS_ROOT" in
  /*) ;;
  *) fail "ROOT must be an absolute path" ;;
esac

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TLS_ROOT_REAL=$("$TLS_PYTHON" - "$TLS_ROOT" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
)
case "$TLS_ROOT_REAL/" in
  "$REPOSITORY_ROOT/"*) fail "refusing to generate certificate material in the repository" ;;
esac

validate_root() {
  if [ -L "$TLS_ROOT" ]; then
    fail "ROOT must not be a symlink"
  fi
  install -d -m 0700 "$TLS_ROOT" "$TLS_ROOT/releases"
  "$TLS_PYTHON" - "$TLS_ROOT" <<'PY'
import os
import stat
import sys

for value in (sys.argv[1], os.path.join(sys.argv[1], "releases")):
    metadata = os.lstat(value)
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SystemExit("miner TLS: ROOT and releases must be real directories")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SystemExit("miner TLS: ROOT and releases must use mode 0700")
PY
}

canonical_ip() {
  "$TLS_PYTHON" - "$1" <<'PY'
import ipaddress
import sys

try:
    print(ipaddress.ip_address(sys.argv[1]))
except ValueError:
    raise SystemExit("miner TLS: certificate identity must be a numeric IPv4 or IPv6 address")
PY
}

validate_days() {
  case "$1" in
    ''|*[!0-9]*) fail "DAYS must be an integer in [1,825]" ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 825 ] || fail "DAYS must be in [1,825]"
}

validate_warn_seconds() {
  case "$1" in
    ''|*[!0-9]*) fail "WARN_BEFORE_SECONDS must be a non-negative integer" ;;
  esac
}

validate_release_target() {
  case "$1" in
    releases/*)
      case "${1#releases/}" in
        ''|*/*|*[!A-Za-z0-9._-]*) fail "managed release symlink is malformed" ;;
      esac
      ;;
    *) fail "managed release symlink escaped ROOT" ;;
  esac
  [ -d "$TLS_ROOT/$1" ] || fail "managed release does not exist"
  "$TLS_PYTHON" - "$TLS_ROOT/$1" <<'PY'
import os
import stat
import sys

metadata = os.lstat(sys.argv[1])
if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("miner TLS: managed release must be a real directory")
if stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("miner TLS: managed release must use mode 0700")
PY
}

fingerprint() {
  openssl x509 -in "$1" -outform DER |
    openssl dgst -sha256 -r |
    awk '{print $1}'
}

validate_pair() {
  release=$1
  cert="$release/miner.crt"
  key="$release/miner.key"
  "$TLS_PYTHON" - "$cert" "$key" <<'PY'
import os
import stat
import sys

cert_path, key_path = sys.argv[1:]
for path in (cert_path, key_path):
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SystemExit("miner TLS: release contains a non-regular or symlinked file")
if stat.S_IMODE(os.lstat(key_path).st_mode) != 0o600:
    raise SystemExit("miner TLS: private key must use mode 0600")
if os.lstat(key_path).st_mode & 0o077:
    raise SystemExit("miner TLS: private key grants group or other access")
PY
  openssl x509 -in "$cert" -noout >/dev/null 2>&1 || fail "certificate is malformed"
  openssl pkey -in "$key" -noout >/dev/null 2>&1 || fail "private key is malformed"
  cert_public=$(
    openssl x509 -in "$cert" -pubkey -noout |
      openssl pkey -pubin -outform DER 2>/dev/null |
      openssl dgst -sha256 -r |
      awk '{print $1}'
  )
  key_public=$(
    openssl pkey -in "$key" -pubout -outform DER 2>/dev/null |
      openssl dgst -sha256 -r |
      awk '{print $1}'
  )
  [ "$cert_public" = "$key_public" ] || fail "certificate and private key do not match"
  # checkend validates only NotAfter. Verification against the exact
  # self-signed leaf also checks NotBefore, NotAfter, signature, and server
  # purpose without introducing a public CA dependency.
  openssl verify -purpose sslserver -CAfile "$cert" "$cert" >/dev/null 2>&1 ||
    fail "certificate is not currently valid and self-verifiable"
  extensions=$(openssl x509 -in "$cert" -noout -text)
  printf '%s\n' "$extensions" | grep -q 'CA:FALSE' || fail "certificate must declare CA:FALSE"
  printf '%s\n' "$extensions" | grep -q 'TLS Web Server Authentication' ||
    fail "certificate must permit TLS server authentication"
}

publish_link() {
  tls_link_name=$1
  tls_link_target=$2
  tls_temporary="$TLS_ROOT/.${tls_link_name}.$$.tmp"
  [ ! -e "$tls_temporary" ] && [ ! -L "$tls_temporary" ] ||
    fail "temporary link already exists"
  ln -s "$tls_link_target" "$tls_temporary"
  "$TLS_PYTHON" - "$tls_temporary" "$TLS_ROOT/$tls_link_name" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY
}

issue_or_rotate() {
  mode=$1
  ip_value=$2
  days=$3
  [ -n "$ip_value" ] || usage
  validate_days "$days"
  ip=$(canonical_ip "$ip_value")
  validate_root
  if [ "$mode" = issue ]; then
    [ ! -e "$TLS_ROOT/current" ] && [ ! -L "$TLS_ROOT/current" ] ||
      fail "current release already exists; use rotate"
  else
    [ -L "$TLS_ROOT/current" ] || fail "rotate requires an existing current release"
  fi

  staging=$(mktemp -d "$TLS_ROOT/releases/.staging.XXXXXX")
  cleanup_staging() {
    case "${staging:-}" in
      "$TLS_ROOT/releases/.staging."*)
        rm -f "$staging/miner.crt" "$staging/miner.key"
        rmdir "$staging" 2>/dev/null || true
        ;;
    esac
  }
  trap cleanup_staging EXIT
  trap 'cleanup_staging; exit 1' INT TERM

  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes \
    -days "$days" \
    -subj "/CN=$ip" \
    -addext "subjectAltName=critical,IP:$ip" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "$staging/miner.key" \
    -out "$staging/miner.crt" >/dev/null 2>&1 || fail "certificate generation failed"
  chmod 0600 "$staging/miner.key"
  chmod 0644 "$staging/miner.crt"
  validate_pair "$staging"

  release_name="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  release="$TLS_ROOT/releases/$release_name"
  [ ! -e "$release" ] || fail "release name collision"
  mv "$staging" "$release"
  staging=
  target="releases/$release_name"
  if [ "$mode" = rotate ]; then
    old_target=$(readlink "$TLS_ROOT/current")
    validate_release_target "$old_target"
    publish_link previous "$old_target"
  fi
  publish_link current "$target"
  trap - EXIT INT TERM

  echo "miner TLS $mode complete"
  echo "certificate: $TLS_ROOT/current/miner.crt"
  echo "private key: $TLS_ROOT/current/miner.key"
  echo "leaf sha256: $(fingerprint "$release/miner.crt")"
  openssl x509 -in "$release/miner.crt" -noout -startdate -enddate
  echo "restart the miner and require a fresh validator capability handshake"
}

check_current() {
  warn_seconds=${3:-604800}
  validate_warn_seconds "$warn_seconds"
  validate_root
  [ -L "$TLS_ROOT/current" ] || fail "current release is missing"
  target=$(readlink "$TLS_ROOT/current")
  validate_release_target "$target"
  release="$TLS_ROOT/$target"
  validate_pair "$release"
  echo "miner TLS current release is structurally valid"
  echo "certificate: $TLS_ROOT/current/miner.crt"
  echo "leaf sha256: $(fingerprint "$release/miner.crt")"
  openssl x509 -in "$release/miner.crt" -noout -startdate -enddate
  if ! openssl x509 -in "$release/miner.crt" -checkend "$warn_seconds" -noout \
    >/dev/null 2>&1; then
    fail "certificate expires within the configured warning window"
  fi
}

rollback() {
  validate_root
  [ -L "$TLS_ROOT/current" ] || fail "current release is missing"
  [ -L "$TLS_ROOT/previous" ] || fail "previous release is missing"
  current_target=$(readlink "$TLS_ROOT/current")
  previous_target=$(readlink "$TLS_ROOT/previous")
  validate_release_target "$current_target"
  validate_release_target "$previous_target"
  validate_pair "$TLS_ROOT/$previous_target"
  publish_link current "$previous_target"
  publish_link previous "$current_target"
  echo "miner TLS rollback complete"
  echo "certificate: $TLS_ROOT/current/miner.crt"
  echo "private key: $TLS_ROOT/current/miner.key"
  echo "leaf sha256: $(fingerprint "$TLS_ROOT/$previous_target/miner.crt")"
  echo "restart the miner and require a fresh validator capability handshake"
}

case "$ACTION" in
  issue|rotate)
    [ "$#" -ge 3 ] && [ "$#" -le 4 ] || usage
    issue_or_rotate "$ACTION" "${3:-}" "${4:-30}"
    ;;
  check)
    [ "$#" -le 3 ] || usage
    check_current "$@"
    ;;
  rollback)
    [ "$#" -eq 2 ] || usage
    rollback
    ;;
  *) usage ;;
esac
