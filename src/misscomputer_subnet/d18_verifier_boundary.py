# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded, one-shot D18 capture verification across the public/private process boundary.

This command accepts only canonical JSON and base64-encoded capture bytes. It
re-authenticates the publications and static index, replays the score, checks
the journal chain, and derives the three D18 metrics. It has no network or
activation capability. The caller must separately bind capture hashes and
release provenance before invoking it.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Final, cast

from . import (
    assignment_probe,
    organic_manifest,
    organic_scoring,
    static_evidence,
    static_index,
    static_scoring,
)

PROTOCOL: Final = "misscomputer.d18-verifier-boundary.v1"
MAX_REQUEST_BYTES: Final = 4 << 20
MAX_CAPTURE_BYTES: Final = 1 << 20
CAPTURES: Final = frozenset(
    {
        "v2-policy",
        "v2-manifest",
        "v2-auditor",
        "v2-issuer",
        "v3-manifest",
        "v3-auditor",
        "v3-issuer",
        "release-policy",
        "release-index",
        "site-manifest",
        "old-score",
        "new-score",
        "journal",
    }
)


class VerificationError(ValueError):
    """Safe refusal with a fixed, non-sensitive code."""


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode()


def _read_request(path: Path) -> dict[str, object]:
    with path.open("rb") as stream:
        payload = stream.read(MAX_REQUEST_BYTES + 1)
    if len(payload) > MAX_REQUEST_BYTES:
        raise VerificationError("request_too_large")
    value = json.loads(payload)
    if not isinstance(value, dict) or canonical_bytes(value) != payload:
        raise VerificationError("request_invalid")
    return value


def _captures(value: object) -> dict[str, bytes]:
    if not isinstance(value, dict) or set(value) != CAPTURES:
        raise VerificationError("request_invalid")
    decoded: dict[str, bytes] = {}
    for key, encoded in value.items():
        if not isinstance(encoded, str) or len(encoded) > 2 * MAX_CAPTURE_BYTES:
            raise VerificationError("request_invalid")
        try:
            rendered = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise VerificationError("request_invalid") from error
        if len(rendered) > MAX_CAPTURE_BYTES or base64.b64encode(rendered).decode() != encoded:
            raise VerificationError("request_invalid")
        decoded[key] = rendered
    return decoded


def verify(request: dict[str, object]) -> dict[str, object]:
    if (
        set(request)
        != {
            "protocol",
            "captures",
            "epoch_index",
            "site_digest",
            "faulty_endpoint_id",
            "network",
            "netuid",
            "started_at",
            "finished_at",
        }
        or request["protocol"] != PROTOCOL
    ):
        raise VerificationError("request_invalid")
    epoch_index = request["epoch_index"]
    if type(epoch_index) is not int or epoch_index < 0:
        raise VerificationError("request_invalid")
    for key in ("site_digest", "faulty_endpoint_id", "network", "started_at", "finished_at"):
        if not isinstance(request[key], str):
            raise VerificationError("request_invalid")
    if type(request["netuid"]) is not int:
        raise VerificationError("request_invalid")
    captures = _captures(request["captures"])
    try:
        started = datetime.fromisoformat(cast(str, request["started_at"]).replace("Z", "+00:00"))
        finished = datetime.fromisoformat(cast(str, request["finished_at"]).replace("Z", "+00:00"))
        if started.tzinfo is None or finished.tzinfo is None or not started < finished:
            raise ValueError("invalid window")
        policy = assignment_probe.parse_assignment_manifest_trust_policy(captures["v2-policy"])
        v2 = organic_manifest.parse_organic_assignment_manifest(captures["v2-manifest"])
        v3 = organic_manifest.parse_assignment_manifest_v3(captures["v3-manifest"])
        v2_signatures = [
            assignment_probe.parse_assignment_manifest_signature_envelope(captures[key])
            for key in ("v2-auditor", "v2-issuer")
        ]
        v3_signatures = [
            assignment_probe.parse_assignment_manifest_signature_envelope(captures[key])
            for key in ("v3-auditor", "v3-issuer")
        ]
        evaluation = epoch_index * 300 + 1
        old_verified = organic_manifest.verify_organic_assignment_manifest(
            v2,
            v2_signatures,
            policy,
            assignment_probe.build_initial_manifest_chain_state(policy),
            evaluation_epoch=evaluation,
            current_finalized_height=v2.finalized_height,
        )
        new_verified = organic_manifest.verify_assignment_manifest_v3(
            v3,
            v3_signatures,
            policy,
            assignment_probe.build_initial_manifest_chain_state(policy),
            evaluation_epoch=evaluation,
            current_finalized_height=v3.finalized_height,
        )
        targets = static_index.static_deployment_targets(new_verified)
        if len(targets) != 1 or request["site_digest"] != targets[0].site_digest:
            raise ValueError("target binding invalid")
        target = targets[0]
        release_policy = static_index.parse_static_site_release_trust_policy(
            captures["release-policy"]
        )
        index = static_index.ingest_static_index(
            target,
            captures["site-manifest"],
            captures["release-index"],
            release_policy,
            pinned_server_implementation_digest=target.server_implementation_digest,
        )
        if not isinstance(index, static_index.VerifiedStaticIndex):
            raise ValueError("index unverified")
        old_score = organic_scoring.parse_organic_epoch_score(captures["old-score"])
        new_score = static_scoring.parse_static_epoch_score(captures["new-score"])
        static_scoring.replay_static_epoch_score(new_score, [index])
        if (
            old_score.epoch_index != epoch_index
            or new_score.epoch_index != epoch_index
            or old_score.epoch_status != "scored"
            or new_score.epoch_status != "scored"
            or old_score.manifest_digests != [old_verified.manifest.manifest_digest_sha256]
            or new_score.targets != targets
            or new_score.validator_hotkey != old_score.validator_hotkey
        ):
            raise ValueError("score binding invalid")
        with tempfile.TemporaryDirectory(prefix="misscomputer-d18-verify-") as directory:
            journal_path = Path(directory) / "journal.jsonl"
            journal_path.write_bytes(captures["journal"])
            journal_path.chmod(0o600)
            with static_evidence.StaticEvidenceJournal(str(journal_path)) as journal:
                if sorted(
                    item.observation_digest_sha256 for item in journal.observations
                ) != sorted(item.observation_digest_sha256 for item in new_score.observations):
                    raise ValueError("journal score mismatch")
        for old_observation in old_score.observations:
            issued = datetime.fromisoformat(old_observation.issued_at.replace("Z", "+00:00"))
            if not started <= issued <= finished:
                raise ValueError("observation outside window")
        for new_observation in new_score.observations:
            issued = datetime.fromisoformat(new_observation.issued_at.replace("Z", "+00:00"))
            if not started <= issued <= finished:
                raise ValueError("observation outside window")
        if (
            request["faulty_endpoint_id"] not in {item.endpoint_id for item in target.endpoints}
            or request["site_digest"] != target.site_digest
            or request["network"] != new_score.network
            or request["netuid"] != new_score.netuid
        ):
            raise ValueError("fault binding invalid")
    except (ValueError, TypeError, KeyError, OSError) as error:
        raise VerificationError("verification_invalid") from error
    old_names = {item.deployment_id for item in old_verified.manifest.deployments}
    old_scored = {item.deployment_id for item in old_score.endpoints}
    if not old_scored or old_scored != old_names or target.deployment_id in old_names:
        raise VerificationError("old_validator_abstention_unproven")
    faults = [
        item
        for item in new_score.endpoint_actions
        if item.endpoint_id == request["faulty_endpoint_id"]
        and item.reason == "content_fault"
        and item.quarantine
    ]
    if len(faults) != 1 or not new_score.content_fault_evidence:
        raise VerificationError("wrong_bytes_detection_unproven")
    if new_score.fraud_evidence:
        raise VerificationError("fraud_classification_conflict")
    return {
        "protocol": PROTOCOL,
        "status": "verified",
        "metrics": {
            "old_validator_abstained": 1,
            "wrong_bytes_detected": 1,
            "false_penalties": sum(item.trust_zero for item in new_score.endpoint_actions),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--response", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        response = verify(_read_request(arguments.request))
    except (VerificationError, OSError, ValueError, TypeError) as error:
        code = error.args[0] if isinstance(error, VerificationError) else "request_invalid"
        response = {"protocol": PROTOCOL, "status": "rejected", "code": code}
    target = arguments.response
    if not target.is_absolute() or target.parent.resolve() != target.parent:
        raise SystemExit("response path must have a resolved absolute parent")
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(response))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
