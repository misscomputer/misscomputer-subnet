# Production release verifier runbook and threat boundary

This runbook covers the offline, non-activating verifier for a production
(`finney`, netuid 24) release. The verifier answers one narrow question: do two
independent local artifact trees, the pinned source inputs, the public-key trust
policy, current approved revocations, and the cryptographic authorization
envelopes all agree exactly?

An authorized report is evidence. It does not publish an artifact, access a
registry, install a file, change a host, start a service, edit cloud or DNS
state, use a wallet, submit an RPC or chain transaction, or launch mainnet.

## Prerequisites and ownership

Use a dedicated offline verification account. Prepare six inputs:

1. The canonical launch-authorization bundle.
2. The canonical release-revocation list.
3. A source root containing every `dependency_inputs[].path` byte.
4. The exact source archive named by `source.source_archive_sha256`.
5. A candidate artifact root.
6. A separately materialized recomputed artifact root.

Every path passed to the CLI must be absolute and lexically normalized. Every
input file must:

- be a regular file owned by the effective verifier user;
- have exactly one hard link;
- grant no group or other permissions;
- be non-empty and within its type-specific size cap; and
- remain the same inode, metadata, path mapping, and bytes throughout two read
  passes.

Use mode `0400` or `0600` for JSON/data and `0500` or `0700` only where an
artifact is itself executable. Ancestor directories must be owned by root or
the verifier user and must not be group/world writable. A sticky shared
directory is accepted only as an ancestor, never as the final parent. The
loader opens every path component with no-follow `openat` semantics, keeps the
complete directory chain pinned, and revalidates the chain before accepting
the bytes.

Do not hardlink candidate and recomputed files. Equal content must reside in
distinct inodes; this is what makes the second tree independent evidence.
Symlinks, archive links, path traversal, duplicate logical paths, and inode
aliases between inputs are rejected.

Canonical verifier JSON is ASCII, key-sorted, compact JSON with no duplicate
keys, no NaN or infinity, and exactly one trailing newline. Noncanonical input
is rejected even if a permissive parser would produce the same object.

## Artifact-root contents

Both artifact roots must independently contain every path declared by:

- `python_distributions` (one wheel and one sdist);
- `go_binaries` (control API, miner agent, and workload);
- `container_images`;
- `workload_artifacts[].descriptor_path`;
- `release_files` (production config, systemd unit, and contract schema bytes);
- `sbom_references` and `provenance_references`; and
- `rollback_bytes`.

Build/test fixtures that influence output must be declared under
`dependency_inputs` in the source root. This gives fixture bytes the same
signed digest and local recomputation treatment as Dockerfiles, `go.mod`,
`go.sum`, and `pyproject.toml`.

The verifier checks both trees against the manifest, not merely against each
other. A consistently wrong pair therefore fails. A missing file, different
length, digest mismatch, hardlink alias, duplicated subject, incomplete subject
set, or ambiguous platform selection fails closed.

### OCI image exports

Each `container_images[].archive_path` must be an uncompressed OCI image-layout
tar archive. The verifier requires:

- a valid `oci-layout` v1 document and `index.json`;
- exactly one index descriptor matching the declared immutable manifest digest
  and platform;
- the manifest and config blobs at their digest-derived paths;
- byte-valid SHA-256 manifest and config digests;
- immutable SHA-256 layer descriptors whose blobs are present; and
- only regular files and directories, with no symlink, hardlink, device, or
  other special archive entry.

A tag annotation may accompany a digest, but a tag cannot replace the digest.

### Workload descriptors

The v1 canonical workload-export descriptor is accepted as the immutable
descriptor alternative to a duplicated workload export. It binds:

- artifact and container artifact IDs;
- workload kind;
- logical export SHA-256 and byte length; and
- the exact OCI container manifest digest.

`mutable_tag` must be `null`. The descriptor's own bytes must match
`descriptor_sha256` in both artifact trees.

### SBOM and provenance

SPDX evidence must be canonical SPDX 2.3 JSON with one SHA-256 checksum for
every declared subject name. SLSA evidence must be a canonical in-toto
Statement v1 using the SLSA provenance v1 predicate. Its subjects must contain
only immutable SHA-256 digests and cover exactly the declared artifact IDs.
Reference IDs must be sorted and unique within each list and globally unique
across the SBOM and provenance lists.

The SLSA `predicate.buildDefinition.externalParameters` object must exactly
bind the manifest repository, commit OID, tree OID, and source-archive SHA-256.
This is the local source/digest guard. The verifier also recomputes the source
archive and every dependency-input byte directly.

## Trust anchors, signing, and revocation

The bundle's embedded trust policy is untrusted until its exact digest equals
the separately approved policy digest supplied to the CLI. The revocation list
is likewise untrusted until its digest equals a separately approved revocation
digest. Obtain those two 64-character lowercase SHA-256 values through the
organization's protected, out-of-band approval channel. Do not copy them from
the bundle being verified, and do not derive them from an environment
variable.

The revocation list binds one trust-policy digest, a monotonic sequence, an
issuance/expiry window, and sorted key revocations. A key whose revocation is
effective at or before evaluation is not counted. A stale list, a list for a
different policy, a changed digest, an expired signature/key/policy/release, or
insufficient non-revoked signatures fails authorization.

The tool reads public keys only. Production signing is performed by a separate
offline signer under the owners' controls. No private-key path or signing
operation is accepted by this CLI.

### Exact Ed25519 message

Each signature uses Ed25519 over these bytes:

```text
ASCII("miss.computer/misscomputer-subnet/launch-authorization/v1")
|| 0x00
|| canonical_json({
  "algorithm": "ed25519",
  "bundle_id": <bundle ID>,
  "expires_at_epoch": <bundle expiry>,
  "issued_at_epoch": <bundle issuance>,
  "netuid": 24,
  "payload_digest_sha256": <authorization payload digest>,
  "purpose": "production_mainnet_launch_authorization",
  "release_manifest_digest_sha256": <manifest digest>,
  "signer_key_id": <approved key ID>,
  "target_network": "finney",
  "trust_policy_digest_sha256": <policy digest>
})
```

The canonical JSON in the signing frame has no trailing newline. The fixed
domain prefix and embedded purpose prevent cross-protocol use. The bundle ID,
issuance/expiry, source/release payload, policy, network, netuid, key ID, and
algorithm prevent replay into another authorization context.

The repository pins `cryptography==50.0.0`; the verifier uses only its Ed25519
public-key construction and verification API. Packaging validation must retain
that exact dependency pin and the `misscomputer-release-verify` entry point.

## Reproducible staging

The verifier intentionally does not run build commands. Build execution can
have network, credential, container, toolchain, or host consequences and is a
separate owner-authorized boundary. Materialize candidate and recomputed trees
with the reviewed release build procedure, from the same signed source and
pinned toolchains, in independent clean environments. Copy the resulting files
without hardlinks to the offline verifier host.

Before verification:

1. Confirm the manifest commit and tree with the release owners.
2. Confirm the source archive and all dependency inputs came from that source.
3. Confirm the candidate and recomputed builds ran independently with the
   manifest's pinned dependency/toolchain inputs.
4. Confirm rollback bytes are the tested predecessor bytes, not copies of the
   replacement.
5. Obtain fresh approved policy and revocation-list digests out of band.
6. Obtain a trusted evaluation epoch from the approved time source.
7. Apply owner-only modes and move the evidence host offline.

The explicit evaluation epoch makes repeated verification byte-deterministic.
The verifier does not establish wall-clock truth. A caller could supply an old
epoch, so the operator and every downstream report consumer must compare the
report epoch with a trusted current-time source and enforce the organization's
maximum report age. This is part of the trust boundary, not an optional check.

## Authorize and verify a report

Run the installed entry point with only absolute paths:

```sh
misscomputer-release-verify authorize \
  --bundle /offline/release/launch-authorization-bundle.json \
  --revocations /offline/release/release-revocations.json \
  --source-root /offline/release/source \
  --source-archive /offline/release/source-archive.tar \
  --artifact-root /offline/release/candidate \
  --recomputed-artifact-root /offline/release/recomputed \
  --approved-policy-digest 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --approved-revocations-digest abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 \
  --evaluated-at-epoch 1800003601 \
  --report /offline/release/launch-authorization-report.json
```

The output report is created with mode `0600`, using exclusive creation. The
command refuses to overwrite an existing path. Preserve the report bytes as an
immutable review artifact.

Each `verified_inputs[].input_id` is category-bound. `source_archive` is the
only fixed ID; every other value is `<category>_<source-id>`, where `category`
is the entry's exact `category` field and `source-id` is the complete manifest
`RecordID`. Report IDs therefore accept the full 64-character source boundary
without truncation and cannot be reinterpreted as a different input category.

To recompute every input and compare the report byte-for-byte, rerun the same
arguments with the `verify-report` subcommand and the saved report path.

Status codes are stable:

- `0`: authorization/report verification succeeded;
- `2`: evidence, trust, signature, expiry, revocation, reproducibility, or
  report verification was rejected;
- `64`: command-line shape was invalid; and
- `70`: an unexpected internal failure was sanitized.

Failures never print input bytes, absolute paths, parser values, public keys,
signatures, credentials, or exception details. A rejection code and fixed safe
message are written to standard error. Success prints only the report digest.

## Threat model

### In scope

The verifier is designed to fail closed against:

- symlink, hardlink, traversal, non-regular-file, unsafe-mode, owner, inode,
  metadata, byte, and parent-directory races;
- oversized inputs, duplicate JSON keys, non-finite numbers, noncanonical JSON,
  duplicate IDs/paths/subjects/signers, and aliased files;
- missing, ambiguous, changed, or nonreproducible release and rollback bytes;
- mutable-tag-only image/workload/provenance claims;
- OCI manifest/config/layer and platform-selection inconsistencies;
- SBOM/provenance subject omissions, duplicates, digest mismatches, and source
  rebinding;
- an unapproved trust policy or revocation view;
- unknown, expired, revoked, wrong-algorithm, wrong-key, invalid, replayed, or
  insufficient signatures and missing role coverage;
- manifest/bundle/policy/source/digest substitution; and
- credential/path leakage in CLI errors.

### Outside scope

The verifier cannot defend against a compromised kernel, filesystem, Python or
cryptography runtime, effective verifier account, or root on the verification
host. It cannot prove that an externally supplied approved digest or evaluation
epoch was obtained honestly. It cannot prove organizational signing intent
beyond valid signature bytes, or that the external build environments followed
their claimed process. It does not scan undeclared files in a staging directory;
use dedicated roots containing only release evidence. It does not establish
artifact safety, business approval, or operational readiness from digest
equality alone.

Most importantly, the report consumer must independently pin the expected
policy and revocation digests, enforce trusted current time/report age, confirm
human release approval, and use a separate explicitly authorized activation
workflow. No report field is permission for this verifier to perform a live
action.
