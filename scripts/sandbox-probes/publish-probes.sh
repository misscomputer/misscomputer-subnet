#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Publish the nine sandbox probe images byte for byte (docs/sandbox-probe-images.md).
#
#   publish-probes.sh layout OUT_DIR
#       Rebuild the OCI layout from build_probe_images.py, require --verify,
#       and require its nine references to equal the committed pins.
#   publish-probes.sh push OUT_DIR REPOSITORY
#       Copy every pinned manifest from the layout to REPOSITORY:<probe>-v1
#       with oras (already logged in), then resolve each pin by digest and
#       by tag. An existing tag that names another digest is never
#       overwritten. REPOSITORY may be oci-layout:<dir> for a local dry run.
#   publish-probes.sh check-public REPOSITORY
#       Without credentials, fetch every pinned manifest and every blob it
#       names from the public registry and require their SHA-256 digests.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
manifest="$here/probe-images.manifest.json"
builder="$here/build_probe_images.py"
expected_count=9

die() {
	echo "publish-probes: $*" >&2
	exit 1
}

# pins prints "<probe> <manifest digest>" for every committed pin, sorted.
pins() {
	jq -r '.images | to_entries[] | "\(.key) \(.value.manifest_digest)"' "$manifest" | LC_ALL=C sort
}

check_pins() {
	local count
	count=$(pins | wc -l)
	[ "$count" -eq "$expected_count" ] || die "committed manifest pins $count images, want $expected_count"
	if pins | awk '$2 !~ /^sha256:[0-9a-f]{64}$/ { bad = 1 } END { exit !bad }'; then
		die "committed manifest has a malformed digest"
	fi
}

cmd_layout() {
	local out=$1
	[ ! -e "$out" ] || die "$out already exists"
	check_pins
	python3 -I "$builder" "$out" >/dev/null
	python3 -I "$builder" --verify "$out"
	local refs
	refs=$(jq -r '.manifests[] | "\(.annotations["org.opencontainers.image.ref.name"]) \(.digest)"' "$out/index.json" | LC_ALL=C sort)
	[ "$refs" = "$(pins)" ] || die "layout references differ from the committed pins"
	echo "layout index sha256:$(sha256sum "$out/index.json" | cut -d' ' -f1)"
	pins
}

cmd_push() {
	local out=$1 repository=$2
	command -v oras >/dev/null || die "oras is required"
	check_pins
	local -a target_flag=()
	local target=$repository
	case "$repository" in
	oci-layout:*)
		target=${repository#oci-layout:}
		target_flag=(--oci-layout)
		;;
	esac
	local name digest tag existing got
	while read -r name digest; do
		tag="$name-v1"
		if existing=$(oras resolve "${target_flag[@]}" "$target:$tag" 2>/dev/null); then
			[ "$existing" = "$digest" ] || die "$target:$tag already names $existing, not $digest; refusing to overwrite"
		fi
		if [ ${#target_flag[@]} -gt 0 ]; then
			oras cp --from-oci-layout "$out:$name" --to-oci-layout "$target:$tag" >/dev/null
		else
			oras cp --from-oci-layout "$out:$name" "$target:$tag" >/dev/null
		fi
		got=$(oras resolve "${target_flag[@]}" "$target@$digest")
		[ "$got" = "$digest" ] || die "$target@$digest resolves to $got"
		got=$(oras resolve "${target_flag[@]}" "$target:$tag")
		[ "$got" = "$digest" ] || die "$target:$tag resolves to $got, not $digest"
		echo "pushed $target:$tag $digest"
	done < <(pins)
}

cmd_check_public() {
	local repository=$1
	local registry=${repository%%/*} path=${repository#*/}
	[ "$registry" != "$repository" ] || die "repository must be <registry>/<path>"
	local token
	token=$(curl -sSf "https://$registry/token?scope=repository:$path:pull" | jq -r .token) ||
		die "no anonymous pull token for $repository (the package is not public yet)"
	local accept="application/vnd.oci.image.manifest.v1+json"
	local name digest raw blob tmp
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' RETURN
	while read -r name digest; do
		curl -sSf -H "Authorization: Bearer $token" -H "Accept: $accept" -o "$tmp/manifest" \
			"https://$registry/v2/$path/manifests/$digest" || die "$name: manifest $digest not readable anonymously"
		raw="sha256:$(sha256sum "$tmp/manifest" | cut -d' ' -f1)"
		[ "$raw" = "$digest" ] || die "$name: manifest bytes hash to $raw, not $digest"
		for blob in $(jq -r '.config.digest, .layers[].digest' "$tmp/manifest"); do
			curl -sSfL -H "Authorization: Bearer $token" -o "$tmp/blob" \
				"https://$registry/v2/$path/blobs/$blob" || die "$name: blob $blob not readable anonymously"
			raw="sha256:$(sha256sum "$tmp/blob" | cut -d' ' -f1)"
			[ "$raw" = "$blob" ] || die "$name: blob bytes hash to $raw, not $blob"
		done
		echo "public $repository@$digest $name"
	done < <(pins)
}

case "${1:-}" in
layout)
	[ $# -eq 2 ] || die "usage: $0 layout OUT_DIR"
	cmd_layout "$2"
	;;
push)
	[ $# -eq 3 ] || die "usage: $0 push OUT_DIR REPOSITORY"
	cmd_push "$2" "$3"
	;;
check-public)
	[ $# -eq 2 ] || die "usage: $0 check-public REPOSITORY"
	cmd_check_public "$2"
	;;
*)
	die "usage: $0 {layout OUT_DIR | push OUT_DIR REPOSITORY | check-public REPOSITORY}"
	;;
esac
