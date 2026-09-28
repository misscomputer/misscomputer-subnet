#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
set -eu

# Report only paths/key names. Never print a matched value or file contents.
repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

private_marker='PRIVATE KEY'
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  private_paths=$(git grep -Il -E \
    -e "-----BEGIN ([A-Z0-9]+ )*${private_marker}-----" -- . || true)
else
  private_paths=$(find . -type f -size -16M -exec grep -Il -E \
    -e "-----BEGIN ([A-Z0-9]+ )*${private_marker}-----" {} + || true)
fi
if [ -n "$private_paths" ]; then
  echo "tracked private-key marker detected" >&2
  printf '%s\n' "$private_paths" >&2
  exit 1
fi

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  certificate_paths=$(git ls-files '*.key' '*.pem' '*.crt' '*.cer' '*.p12' '*.pfx')
else
  certificate_paths=$(find . -type f \
    \( -name '*.key' -o -name '*.pem' -o -name '*.crt' -o -name '*.cer' -o -name '*.p12' -o -name '*.pfx' \) -print)
fi
if [ -n "$certificate_paths" ]; then
  echo "tracked key or generated-certificate filename detected" >&2
  printf '%s\n' "$certificate_paths" >&2
  exit 1
fi

python_command=${PYTHON:-python3}
command -v "$python_command" >/dev/null 2>&1 || {
  echo "python3 is required for configured-secret scanning" >&2
  exit 1
}
"$python_command" - <<'PY'
from __future__ import annotations

import re
import subprocess
from pathlib import Path

names = (
    "S3_SECRET_ACCESS_KEY",
    "S3_READ_SECRET_ACCESS_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "MINIO_ROOT_PASSWORD",
    "MINIO_SECRET_KEY",
    "MISS_BRIDGE_SECRET",
)
assignment = re.compile(
    rf"(?im)(?<![\w${{])(?P<name>{'|'.join(names)})\b\s*(?:=|:)\s*"
    rf"[\"']?(?P<value>[^\s\"',}}]+)"
)
allowed_literals = {
    "local-development-secret",
    "secret-sentinel",
    "tunnel-sentinel",
    "api-sentinel",
    "r2-sentinel",
    "admin-sentinel",
}
listed = subprocess.run(
    ["git", "ls-files", "-z"],
    check=False,
    capture_output=True,
)
tracked = (
    listed.stdout.split(b"\0")
    if listed.returncode == 0
    else [str(path).encode() for path in Path(".").rglob("*") if path.is_file()]
)
findings: list[tuple[str, str]] = []
for raw_path in tracked:
    if not raw_path:
        continue
    path = Path(raw_path.decode())
    try:
        text = path.read_text()
    except (OSError, UnicodeDecodeError):
        continue
    for match in assignment.finditer(text):
        value = match.group("value").rstrip(";)")
        if (
            value in allowed_literals
            or value.startswith(("$", "${", "<"))
            or "${" in value
        ):
            continue
        findings.append((str(path), match.group("name")))
if findings:
    print("literal configured-secret value detected", flush=True)
    for path, name in sorted(set(findings)):
        print(f"{path}: {name}", flush=True)
    raise SystemExit(1)
PY

echo "repository secret scan passed"
