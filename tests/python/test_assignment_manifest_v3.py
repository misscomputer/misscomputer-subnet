# SPDX-License-Identifier: AGPL-3.0-only
"""Public assignment manifest v3: OCI and static deployments (static-site contract §11.1).

v3 reuses the v2 header, trust policy, envelope, chain state and lease rules
under its own purpose and signing domain. These tests pin what is new: the
explicit ``workload_kind`` bindings, the domain separation from v2, OCI v3/v2
parity, and the static targets a validator derives from a verified v3.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any

import pytest
from assignment_probe_context import BASE_EPOCH, FINALIZED_HEIGHT, build_policy, signer_keys
from organic_context import BLOG, SHOP, build_deployment, build_manifest, sign_manifest
from static_context import SERVER, manifest_document, release_bytes, site_digest, stored
from static_context import trust_policy as static_trust_policy

from misscomputer_subnet.assignment_probe import (
    MANIFEST_PURPOSE,
    MANIFEST_SIGNATURE_ENVELOPE_SCHEMA,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    AssignmentProbeError,
    build_initial_manifest_chain_state,
)
from misscomputer_subnet.contract_codec import digest, model_document
from misscomputer_subnet.organic_contracts import (
    ActiveAssignmentManifestV2,
    ActiveAssignmentManifestV3,
    OciDeploymentAssignmentV3,
    StaticDeploymentAssignmentV3,
    oci_deployment_assignment_v2,
    parse_canonical_document,
)
from misscomputer_subnet.organic_manifest import (
    ASSIGNMENT_MANIFEST_V3_SIGNATURE_DOMAIN_SEPARATOR,
    ORGANIC_MANIFEST_SIGNATURE_DOMAIN_SEPARATOR,
    anchor_assignment_manifest_v3_chain_state,
    assignment_manifest_v3_bytes,
    assignment_manifest_v3_signature_message,
    parse_assignment_manifest_v3,
    verify_assignment_manifest_v3,
)
from misscomputer_subnet.static_index import (
    VerifiedStaticIndex,
    ingest_static_index,
    static_deployment_targets,
)

CONTRACTS = Path(__file__).resolve().parents[2] / "contracts"
#: SHA-256 of the golden v3 signature message; the Go suite pins the same value.
GOLDEN_V3_MESSAGE_SHA256 = "a184d1ffff628b6074911d87c32812e2f3497e24b1b0941b8723122ebe24e967"
STATIC = "docs-q8w2e4r6t0"
SITE_MANIFEST = stored(manifest_document())
SITE = site_digest(SITE_MANIFEST)
RELEASE = release_bytes(SITE)
RELEASE_DIGEST = "sha256:" + hashlib.sha256(RELEASE).hexdigest()


def golden(stem: str) -> bytes:
    return (CONTRACTS / "fixtures" / f"{stem}.json").read_bytes()


def static_deployment(
    deployment_id: str = STATIC, hotkeys: tuple[str, ...] = ("MinerA", "MinerD"), **changes: Any
) -> dict[str, Any]:
    document = model_document(build_deployment(deployment_id, list(hotkeys)))
    document.update(
        workload_kind="static-site-v1",
        artifact_digest=None,
        health=None,
        site_digest=SITE,
        release_digest=RELEASE_DIGEST,
        server_implementation_digest=SERVER,
        **changes,
    )
    return document


def oci_deployment(v2: dict[str, Any]) -> dict[str, Any]:
    return {
        **v2,
        "workload_kind": "oci-image-v1",
        "site_digest": None,
        "release_digest": None,
        "server_implementation_digest": None,
    }


def v3_manifest(
    policy: AssignmentManifestTrustPolicy,
    static: list[dict[str, Any]] | None = None,
    **header: Any,
) -> ActiveAssignmentManifestV3:
    """The organic test v2 manifest's OCI deployments plus static ones, as v3."""

    v2 = build_manifest(policy, [build_deployment(SHOP, ["MinerA", "MinerB", "MinerC"])])
    document = model_document(v2)
    deployments = [oci_deployment(item) for item in document["deployments"]]
    deployments += [static_deployment()] if static is None else static
    resealed = []
    for item in sorted(deployments, key=lambda value: value["deployment_id"]):
        unsigned = {k: v for k, v in item.items() if k != "assignment_digest_sha256"}
        resealed.append({**unsigned, "assignment_digest_sha256": digest(unsigned)})
    unsigned = {
        **{k: v for k, v in document.items() if k != "manifest_digest_sha256"},
        "schema_version": 3,
        "purpose": "active_assignment_manifest_publication_v3",
        "deployments": resealed,
        "assignment_vector_digest_sha256": digest(resealed),
        **header,
    }
    return ActiveAssignmentManifestV3.model_validate(
        {**unsigned, "manifest_digest_sha256": digest(unsigned)}
    )


def sign_v3(
    manifest: ActiveAssignmentManifestV3, *, message: bytes | None = None
) -> list[AssignmentManifestSignatureEnvelope]:
    """Envelopes that bind the v3 message digest; ``message`` is what the keys sign."""

    bound = assignment_manifest_v3_signature_message(manifest)
    keys = signer_keys()
    return [
        AssignmentManifestSignatureEnvelope.model_validate(
            {
                "schema": MANIFEST_SIGNATURE_ENVELOPE_SCHEMA,
                "schema_version": 1,
                "purpose": MANIFEST_PURPOSE,
                "algorithm": "ed25519",
                "signer_key_id": key_id,
                "manifest_digest_sha256": manifest.manifest_digest_sha256,
                "signed_message_digest_sha256": hashlib.sha256(bound).hexdigest(),
                "signature_base64": base64.b64encode(
                    keys[key_id].sign(bound if message is None else message)
                ).decode("ascii"),
            }
        )
        for key_id in ("auditor", "issuer")
    ]


def verify(
    manifest: ActiveAssignmentManifestV3,
    policy: AssignmentManifestTrustPolicy,
    signatures: list[AssignmentManifestSignatureEnvelope] | None = None,
) -> Any:
    return verify_assignment_manifest_v3(
        manifest,
        sign_v3(manifest) if signatures is None else signatures,
        policy,
        build_initial_manifest_chain_state(policy),
        evaluation_epoch=BASE_EPOCH,
        current_finalized_height=FINALIZED_HEIGHT,
    )


def test_golden_v3_signs_under_its_own_domain() -> None:
    manifest = parse_assignment_manifest_v3(golden("active-assignment-manifest.v3"))
    message = assignment_manifest_v3_signature_message(manifest)

    assert assignment_manifest_v3_bytes(manifest) == golden("active-assignment-manifest.v3")
    assert message.startswith(ASSIGNMENT_MANIFEST_V3_SIGNATURE_DOMAIN_SEPARATOR + b"\x00")
    assert ASSIGNMENT_MANIFEST_V3_SIGNATURE_DOMAIN_SEPARATOR == (
        b"miss.computer/misscomputer-subnet/active-assignment-manifest/v3/ed25519"
    )
    assert hashlib.sha256(message).hexdigest() == GOLDEN_V3_MESSAGE_SHA256


def test_golden_v3_oci_deployment_is_the_golden_v2_deployment() -> None:
    v2 = parse_canonical_document(
        golden("active-assignment-manifest.v2"), ActiveAssignmentManifestV2
    )
    v3 = parse_assignment_manifest_v3(golden("active-assignment-manifest.v3"))
    oci, static = v3.deployments

    assert isinstance(oci, OciDeploymentAssignmentV3)
    assert oci_deployment_assignment_v2(oci) == v2.deployments[0]
    assert isinstance(static, StaticDeploymentAssignmentV3)
    assert (static.site_digest, static.release_digest) == (
        "sha256:9db3b2a4b3f18c1d31fd7d3348f83e1dfde21163d5aca540fd2f63d6b88ab77f",
        "sha256:9b03cbef4e0731b17c1a6bc81a1942e9cab32ca96445a4c48a3efcb65fbdbc9e",
    )


def test_versions_do_not_parse_as_each_other() -> None:
    with pytest.raises(ValueError):
        parse_canonical_document(
            golden("active-assignment-manifest.v3"), ActiveAssignmentManifestV2
        )
    with pytest.raises(ValueError):
        parse_assignment_manifest_v3(golden("active-assignment-manifest.v2"))


def test_live_v3_verifies_and_yields_only_static_targets() -> None:
    policy = build_policy(signer_keys())
    manifest = v3_manifest(policy)

    verification = verify(manifest, policy)
    targets = static_deployment_targets(verification)

    assert verification.next_chain_state.last_manifest_digest_sha256 == (
        manifest.manifest_digest_sha256
    )
    assert [target.deployment_id for target in targets] == [STATIC]
    (target,) = targets
    static = next(item for item in manifest.deployments if item.deployment_id == STATIC)
    assert (target.site_digest, target.release_digest, target.server_implementation_digest) == (
        SITE,
        RELEASE_DIGEST,
        SERVER,
    )
    assert [
        (e.endpoint_id, e.generation, e.miner_uid, e.miner_hotkey, e.ticket_digest)
        for e in target.endpoints
    ] == [
        (r.endpoint_id, r.generation, r.miner_uid, r.miner_hotkey, r.ticket_digest)
        for r in static.replicas
    ]


def test_static_target_from_verified_v3_ingests_the_contract_index() -> None:
    policy = build_policy(signer_keys())
    (target,) = static_deployment_targets(verify(v3_manifest(policy), policy))

    index = ingest_static_index(
        target,
        SITE_MANIFEST,
        RELEASE,
        static_trust_policy(),
        pinned_server_implementation_digest=SERVER,
    )

    assert isinstance(index, VerifiedStaticIndex)
    assert index.target == target


def test_a_v2_domain_signature_never_verifies_a_v3_manifest() -> None:
    policy = build_policy(signer_keys())
    manifest = v3_manifest(policy)
    v2_domain_message = ORGANIC_MANIFEST_SIGNATURE_DOMAIN_SEPARATOR + (
        assignment_manifest_v3_signature_message(manifest).removeprefix(
            ASSIGNMENT_MANIFEST_V3_SIGNATURE_DOMAIN_SEPARATOR
        )
    )
    v2_manifest = build_manifest(policy, [build_deployment(SHOP, ["MinerA", "MinerB", "MinerC"])])

    with pytest.raises(AssignmentProbeError) as forged:
        verify(manifest, policy, sign_v3(manifest, message=v2_domain_message))
    with pytest.raises(AssignmentProbeError) as foreign:
        verify(manifest, policy, sign_manifest(v2_manifest, signer_keys()))

    assert forged.value.code == "signature_invalid"
    assert foreign.value.code == "signature_binding_mismatch"


def test_identity_rules_span_oci_and_static_replicas() -> None:
    policy = build_policy(signer_keys())
    shop = model_document(build_deployment(SHOP, ["MinerA", "MinerB", "MinerC"]))
    nonce = shop["replicas"][0]["assignment_nonce"]
    reused = static_deployment()
    replica = reused["replicas"][0]
    replica.update(
        assignment_nonce=nonce,
        endpoint_id=f"{replica['replica_id']}-g{replica['generation']}-{nonce}",
    )
    conflicting = static_deployment()
    conflicting["replicas"][0]["miner_service_public_key"] = "11" * 32

    for static, code in (
        (reused, "manifest_assignment_nonce_duplicate"),
        (conflicting, "manifest_miner_identity_conflict"),
    ):
        manifest = v3_manifest(policy, [static])
        with pytest.raises(ValueError, match=code):
            verify(manifest, policy)


def test_v3_chain_state_anchors_and_advances_independently_of_v2() -> None:
    policy = build_policy(signer_keys())
    genesis = build_initial_manifest_chain_state(policy)
    head = v3_manifest(
        policy, sequence=7, previous_manifest_digest_sha256=hashlib.sha256(b"v3-6").hexdigest()
    )

    anchored = anchor_assignment_manifest_v3_chain_state(
        head,
        sign_v3(head),
        policy,
        genesis,
        evaluation_epoch=BASE_EPOCH,
        current_finalized_height=FINALIZED_HEIGHT,
    )

    assert (anchored.next_chain_state.last_sequence, anchored.reprobe) == (7, False)
    assert anchored.next_chain_state.last_manifest_digest_sha256 == head.manifest_digest_sha256


def test_oci_only_v3_carries_no_static_target() -> None:
    policy = build_policy(signer_keys())

    assert static_deployment_targets(verify(v3_manifest(policy, []), policy)) == []


def test_static_deployment_cannot_be_projected_to_v2() -> None:
    manifest = parse_assignment_manifest_v3(golden("active-assignment-manifest.v3"))

    with pytest.raises(ValueError):
        oci_deployment_assignment_v2(manifest.deployments[1])  # type: ignore[arg-type]


def test_static_route_host_keeps_the_v2_rule() -> None:
    policy = build_policy(signer_keys())
    static = static_deployment(BLOG, route_host=f"{BLOG}.other.local")

    with pytest.raises(ValueError, match="manifest_route_host_invalid"):
        v3_manifest(policy, [static])
