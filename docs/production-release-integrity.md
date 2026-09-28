# Production release integrity contracts

The production release contracts are deterministic, offline data models for
mainnet release review. They describe evidence; they do not build, fetch,
publish, install, verify, approve, or launch anything.

## Release manifest

`production-release-manifest.v2` binds one production candidate to:

- the exact `misscomputer/misscomputer-subnet` Git commit and tree;
- pinned Python, Go, and container-builder toolchains plus hashed dependency
  inputs;
- one wheel and one sdist, the complete production Go-binary set (control API
  and miner agent), and the neuron image's OCI manifest, config, and archive
  digests;
- immutable SBOM and SLSA provenance references covering every declared
  artifact;
- config, systemd unit, and contract-schema bytes; and
- different, exact rollback bytes for every deployable artifact.

Identifiers, paths, evidence subjects, and rollback records are unique and
canonically ordered. SBOM and provenance reference identifiers are also unique
across both evidence lists, so one logical reference cannot ambiguously name two
evidence formats. Required artifact categories and supply-chain subject coverage
must be complete. Absolute paths, traversal, credential/wallet path components,
unknown fields, mismatched digests, and incomplete rollback coverage are
rejected.

The canonical representation is ASCII JSON with sorted keys, no insignificant
whitespace, and one trailing newline. `digest_sha256` covers the same canonical
object without the digest field. The manifest has an explicit validity window,
mainnet target (`finney`, netuid 24), completeness and uniqueness states, and
states whether build recomputation and artifact verification have occurred.

## Launch-authorization bundle

`launch-authorization-bundle.v1` embeds the exact release manifest and a
versioned public-key trust policy. Its non-circular authorization payload binds
the bundle ID, release and policy digests, source commit/tree, mainnet target,
and issuance/expiry window. Canonical Ed25519 signature envelopes bind that
payload to unique trusted key IDs. The structural model enforces threshold,
required-role coverage, public-key fingerprints, validity windows, expiry, and
consistent pending/rejected/expired/authorized state.

Model validation is not signature verification. In particular, a serialized
`signature_verification_state` assertion is untrusted until the separate
cryptographic verifier from commit B reproduces it. The committed golden bundle
uses `not_performed`, `pending_signature_verification`, and
`launch_authorized: false`. The fixtures are deterministic schema examples,
not production artifact evidence or an authorization to launch.

## Offline verifier

The separate `production_release_verifier` module implements the deferred
offline verification layer without changing the commit-A structural contracts.
It requires two independently materialized artifact trees and recomputes every
declared byte length and SHA-256 digest for the wheel, sdist, production Go
binaries, OCI exports, SPDX SBOM, SLSA provenance,
config/unit/schema files, and rollback bytes. It also verifies the source
archive and every declared dependency input. Contract fixtures needed by the
release or build must be declared as dependency inputs and are checked the same
way.

OCI inputs must be uncompressed OCI image-layout archives. The verifier binds
the archive bytes, index platform selection, immutable manifest and config
digests, and referenced layer presence; linked archive entries and mutable-tag-
only claims are rejected.

Manifest v1 also released the synthetic workload binary, workload image, and a
`workload-export-descriptor` v1. The synthetic flow was never live and is
retired (organic deployment contract §13): manifest v2 has no
`workload_artifacts`, refuses a `workload` binary or image, and the verifier
has no workload-descriptor category. Customer applications are not release
artifacts; they arrive as content-addressed `artifact-manifest` v2 images.

Signature verification uses the already pinned `cryptography==50.0.0`
dependency and its reviewed Ed25519 public-key API. It has no signing API.
Signature bytes cover the fixed algorithm, purpose, domain, signer key ID,
bundle ID, release and policy digests, authorization-payload digest, mainnet
target, netuid, and issuance/expiry window. The authorization-payload digest in
turn binds the source commit/tree, bundle, manifest, and trust policy. Exact
locally approved policy and revocation-list digests are mandatory; verified
signers alone determine threshold and required-role coverage.

The verifier produces a canonical `launch-authorization-report.v1` and can
recompute all evidence to verify a saved report byte-for-byte. The report
uses a separate, bounded `input_id` contract: `source_archive` is fixed, and
every manifest-derived entry is `<category>_<source-id>` using its exact report
category. The maximum is 84 characters, so every valid 64-character source
`RecordID` is preserved without hashing, truncation, collision, or loss of type
binding. The report records `live_actions: false`. `launch_authorized: true`
means only that the supplied offline evidence passed at the supplied trusted
evaluation epoch; it does not perform or permit an implicit side effect.

See [the production release verifier runbook](production-release-verifier-runbook.md)
for staging rules, exact commands, exit statuses, signature framing, and the
full threat-model boundary.

## Capability boundary

The verifier has no subprocess, network/provider/registry, private-key,
artifact-publication, host/service, cloud/DNS, wallet, RPC/chain, apply, or
activation capability. It never discovers trust anchors, paths, credentials,
or time from environment variables. Builds and signing remain separate,
owner-authorized workflows. Publication, installation, service changes, and
mainnet activation remain outside this repository tool even after a report is
authorized.
