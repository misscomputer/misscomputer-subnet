#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build the lane-1 D23/D11 probe images as one OCI image layout, reproducibly.

Standard library only, no network, no credentials, no container engine. Every
byte is a function of this file: tar headers carry fixed mode/uid/gid/mtime,
layers are uncompressed OCI tar layers (no gzip, whose output depends on the
zlib build), JSON is canonical (sorted keys, no spaces) and the ELF binaries
are assembled here from fixed instruction bytes. Rebuilding anywhere must
reproduce the manifest digests in probe-images.manifest.json.

Usage:
  build_probe_images.py OUT_DIR            build OUT_DIR (an OCI image layout)
  build_probe_images.py --verify OUT_DIR   rebuild in memory and compare with
                                           OUT_DIR and the committed manifest
"""

import hashlib
import json
import os
import struct
import sys

PATH_ENV = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PASSWD = b"root:x:0:0:root:/root:/sbin/nologin\n"
GROUP = b"root:x:0:\n"


# ---- ELF ------------------------------------------------------------------

BASE = 0x400000
EM_X86_64, EM_AARCH64 = 0x3E, 0xB7


def elf(machine, code, interp=None):
    """A static ELF64 ET_EXEC mapping the whole file read+execute at BASE,
    entering at code. interp adds a PT_INTERP naming that loader."""
    phnum = 2 if interp else 1
    header_size = 64 + 56 * phnum
    interp_bytes = (interp.encode() + b"\0") if interp else b""
    interp_off = header_size
    code_off = header_size + len(interp_bytes)
    size = code_off + len(code)
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    ehdr = ident + struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, BASE + code_off, 64, 0, 0, 64, 56, phnum, 0, 0, 0)
    phdrs = b""
    if interp:
        phdrs += struct.pack("<IIQQQQQQ", 3, 4, interp_off, BASE + interp_off, BASE + interp_off,
                             len(interp_bytes), len(interp_bytes), 1)
    phdrs += struct.pack("<IIQQQQQQ", 1, 5, 0, BASE, BASE, size, size, 0x1000)
    return ehdr + phdrs + interp_bytes + code


# x86-64: mov eax, 60 (exit); xor edi, edi; syscall
X86_EXIT0 = bytes.fromhex("b83c000000" "31ff" "0f05")
# x86-64: loop: mov eax, 34 (pause); syscall; jmp loop
X86_PAUSE = bytes.fromhex("b822000000" "0f05" "ebf7")
# aarch64: mov x8, #93 (exit); mov x0, #0; svc #0
ARM64_EXIT0 = struct.pack("<III", 0xD2800BA8, 0xD2800000, 0xD4000001)


# ---- tar ------------------------------------------------------------------

def tar_header(name, size, mode, typeflag):
    fields = [
        name.encode().ljust(100, b"\0"),
        b"%07o\0" % mode,
        b"%07o\0" % 0,
        b"%07o\0" % 0,
        b"%011o\0" % size,
        b"%011o\0" % 0,
        b" " * 8,
        typeflag,
        b"\0" * 100,
        b"ustar\0",
        b"00",
        b"\0" * 32,
        b"\0" * 32,
        b"%07o\0" % 0,
        b"%07o\0" % 0,
        b"\0" * 155,
    ]
    header = b"".join(fields).ljust(512, b"\0")
    checksum = sum(header)
    return header[:148] + b"%06o\0 " % checksum + header[156:]


def tar(entries):
    """entries: (name, mode, data or None for a directory), in this order."""
    out = b""
    for name, mode, data in entries:
        if data is None:
            out += tar_header(name.rstrip("/") + "/", 0, mode, b"5")
            continue
        out += tar_header(name, len(data), mode, b"0")
        out += data + b"\0" * (-len(data) % 512)
    return out + b"\0" * 1024


# ---- OCI ------------------------------------------------------------------

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# name -> (layer files beyond /etc, Entrypoint or None, User or None,
#          expected outcome under contract v0.6.0-candidate D23 / v0.5.3)
PROBES = {
    "probe-pause": ([("probe-pause", 0o755, elf(EM_X86_64, X86_PAUSE))], ["/probe-pause"], None,
                    "positive control: runs; Create ready"),
    "probe-exits": ([("probe-exits", 0o755, elf(EM_X86_64, X86_EXIT0))], ["/probe-exits"], None,
                    "D11: starts and exits 0; served, not a fault"),
    "probe-no-command": ([("probe-exits", 0o755, elf(EM_X86_64, X86_EXIT0))], None, None,
                         "D19: no Entrypoint/Cmd; image_unavailable before container create"),
    "probe-missing-command": ([], ["/no/such/command"], None,
                              "D23: never started (observed run 38661083069 via docker run)"),
    "probe-noexec": ([("probe-noexec", 0o644, elf(EM_X86_64, X86_EXIT0))], ["/probe-noexec"], None,
                     "D23: never started (observed run 38661083069 via docker run)"),
    "probe-arm64-elf": ([("probe-arm64", 0o755, elf(EM_AARCH64, ARM64_EXIT0))], ["/probe-arm64"], None,
                        "D23: never started (observed run 38661083069 via docker run)"),
    "probe-missing-interpreter": ([("probe-script", 0o755, b"#!/no/such/interpreter\n")], ["/probe-script"], None,
                                  "D23 expected: never started (NOT yet observed)"),
    "probe-missing-elf-loader": ([("probe-dynamic", 0o755, elf(EM_X86_64, X86_EXIT0, interp="/lib/no-such-loader.so"))],
                                 ["/probe-dynamic"], None, "D23 expected: never started (NOT yet observed)"),
    "probe-unknown-user": ([("probe-exits", 0o755, elf(EM_X86_64, X86_EXIT0))], ["/probe-exits"], "probe-nosuchuser",
                           "D23 expected: never started; dockerd resolves the user at start (NOT yet observed)"),
}


def build():
    blobs, manifests, records = {}, [], {}
    for name in sorted(PROBES):
        files, entrypoint, user, expected = PROBES[name]
        layer = tar([("etc", 0o755, None), ("etc/group", 0o644, GROUP), ("etc/passwd", 0o644, PASSWD)] + files)
        container = {"Env": [PATH_ENV]}
        if entrypoint is not None:
            container["Entrypoint"] = entrypoint
        if user is not None:
            container["User"] = user
        config = canonical({"architecture": "amd64", "os": "linux", "config": container,
                            "rootfs": {"type": "layers", "diff_ids": [digest(layer)]}})
        manifest = canonical({
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": digest(config), "size": len(config)},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": digest(layer), "size": len(layer)}],
        })
        for raw in (layer, config, manifest):
            blobs[digest(raw)] = raw
        manifests.append({"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": digest(manifest),
                          "size": len(manifest), "annotations": {"org.opencontainers.image.ref.name": name}})
        records[name] = {"manifest_digest": digest(manifest), "config_digest": digest(config),
                         "layer_digest": digest(layer), "layer_media_type": "application/vnd.oci.image.layer.v1.tar",
                         "entrypoint": entrypoint, "user": user, "platform": "linux/amd64 (config)",
                         "expected": expected}
    index = canonical({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": manifests})
    return blobs, index, records


def write(out):
    blobs, index, records = build()
    os.makedirs(os.path.join(out, "blobs", "sha256"), exist_ok=True)
    with open(os.path.join(out, "oci-layout"), "wb") as f:
        f.write(canonical({"imageLayoutVersion": "1.0.0"}))
    with open(os.path.join(out, "index.json"), "wb") as f:
        f.write(index)
    for name, raw in blobs.items():
        with open(os.path.join(out, "blobs", "sha256", name.split(":", 1)[1]), "wb") as f:
            f.write(raw)
    return index, records


def verify(out, committed):
    blobs, index, records = build()
    problems = []
    with open(os.path.join(out, "index.json"), "rb") as f:
        if f.read() != index:
            problems.append("index.json differs from a rebuild")
    present = set(os.listdir(os.path.join(out, "blobs", "sha256")))
    for name, raw in blobs.items():
        hexname = name.split(":", 1)[1]
        path = os.path.join(out, "blobs", "sha256", hexname)
        if hexname not in present:
            problems.append("missing blob " + name)
            continue
        with open(path, "rb") as f:
            data = f.read()
        if data != raw or digest(data) != name:
            problems.append("blob differs " + name)
    for extra in present - {n.split(":", 1)[1] for n in blobs}:
        problems.append("unexpected blob sha256:" + extra)
    with open(committed) as f:
        pinned = json.load(f)["images"]
    for name, record in records.items():
        if pinned.get(name, {}).get("manifest_digest") != record["manifest_digest"]:
            problems.append(f"{name}: rebuild {record['manifest_digest']} != committed {pinned.get(name, {}).get('manifest_digest')}")
    return problems


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    committed = os.path.join(here, "probe-images.manifest.json")
    if len(sys.argv) == 3 and sys.argv[1] == "--verify":
        problems = verify(sys.argv[2], committed)
        print("\n".join(problems) if problems else "verified: layout and committed digests reproduce")
        sys.exit(1 if problems else 0)
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    index, records = write(sys.argv[1])
    print(json.dumps({"index_digest": digest(index), "images": records}, indent=1, sort_keys=True))
