# SPDX-License-Identifier: AGPL-3.0-only
# shellcheck shell=bash disable=SC2034
# Shared helpers for the disposable sandbox-host provisioning and conformance
# scripts. Sourced, never executed. See docs/sandbox-host-enforcement.md.

# Pinned inputs. A change here is a reviewed change to the proven host.
readonly MCSBX_RUNSC_RELEASE=release-20261005.0
readonly MCSBX_RUNSC_ARCHIVE_SHA256=bd4eb2ca0ee74f0fbbb5f5273ba011e79c56a29fbb047393b88b981cd3230ede
readonly MCSBX_DOCKER_VERSION=28.0.4
readonly MCSBX_CONTAINERD_SERIES=v2.3.
readonly MCSBX_IMAGE=docker.io/library/busybox@sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f
readonly MCSBX_IMAGE_DIGEST=sha256:b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f

# Fixed names. They contain no '-' so systemd creates no implicit parent
# slices (mc.slice, mc-sandbox.slice, ...) that cleanup would have to find.
readonly MCSBX_LEASE_SLICE=mcsbxlease.slice
readonly MCSBX_ENGINE_SLICE=mcsbxengine.slice
readonly MCSBX_CONTAINERD_UNIT=mcsbxcontainerd.service
readonly MCSBX_DOCKERD_UNIT=mcsbxdockerd.service
readonly MCSBX_NAMESPACE=mc-sandbox
readonly MCSBX_PLUGINS_NAMESPACE=mc-sandbox-plugins

mcsbx_die() { echo "SANDBOX-HOST FAILED: $*" >&2; exit 1; }

mcsbx_report() {
  echo "$*"
  if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then echo "$*" >> "$GITHUB_STEP_SUMMARY"; fi
}

# Accident guard, not a security boundary: every variable is caller-controlled.
# These scripts change mounts, loop devices, systemd units and cgroups, so they
# refuse anything but a disposable GitHub-hosted VM running the workflow.
mcsbx_require_disposable() {
  [[ ${MC_SANDBOX_HOST_DISPOSABLE:-} == 1 && ${GITHUB_ACTIONS:-} == true &&
     ${RUNNER_ENVIRONMENT:-} == github-hosted && -n ${ImageOS:-} && -n ${ImageVersion:-} && $EUID == 0 ]] || {
    echo 'This requires the contained GitHub-hosted sandbox-host workflow as root.' >&2
    exit 1
  }
  # Refuse containers and anything that looks like a Miss Computer host
  # (runner, miner, validator, origin), even if the variables were forged.
  local marker
  for marker in /run/.containerenv /.dockerenv /etc/misscomputer /root/.bittensor /home/ubuntu/.bittensor /opt/misscomputer-*; do
    [[ -e $marker ]] && { echo "Refusing: production or container marker $marker exists." >&2; exit 1; }
  done
  if systemctl list-units --all --no-legend 'misscomputer-*' 2>/dev/null | grep -q .; then
    echo 'Refusing: misscomputer-* systemd units exist on this host.' >&2
    exit 1
  fi
  return 0
}

mcsbx_root() {
  local root=${MC_SANDBOX_HOST_ROOT:-${RUNNER_TEMP:-/nonexistent}/mcsbx}
  [[ $root == /* && $root != *[[:space:]]* && ${#root} -le 48 ]] || mcsbx_die "root path $root must be absolute, without spaces, at most 48 bytes (unix socket length)"
  printf '%s\n' "$root"
}

mcsbx_require_tools() {
  local tool
  for tool in "$@"; do command -v "$tool" >/dev/null || mcsbx_die "missing $tool"; done
}

# A cgroup v2 file holding a single finite positive integer.
mcsbx_finite() { [[ $1 =~ ^[1-9][0-9]*$ ]]; }
