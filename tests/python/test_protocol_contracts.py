# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json
from pathlib import Path

import bittensor as bt
import pytest
from pydantic import ValidationError

from misscomputer_subnet.auth import sign_service_binding, verify_service_binding
from misscomputer_subnet.protocol import (
    BridgeDeactivateRequest,
    CapabilitiesResponse,
    CapabilitiesSynapse,
    ChainState,
    DeactivateSynapse,
    DeployResponse,
    DeploySynapse,
    HealthObservation,
    MinerRegistration,
    MinerSet,
    RecoveryResponse,
    ServiceKeyBinding,
    StatusSynapse,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("fixture", "model"),
    [
        ("capabilities.v2.json", CapabilitiesSynapse),
        ("deploy.v2.json", DeploySynapse),
        ("status.v2.json", StatusSynapse),
        ("deactivate.v2.json", DeactivateSynapse),
        ("capabilities-response.v2.json", CapabilitiesResponse),
        ("deploy-response.v2.json", DeployResponse),
        ("miner-registration.v2.json", MinerRegistration),
        ("miner-set.v2.json", MinerSet),
        ("chain-state.v2.json", ChainState),
        ("health-observation.v2.json", HealthObservation),
        ("recovery-response.v2.json", RecoveryResponse),
        ("bridge-deactivate.v2.json", BridgeDeactivateRequest),
    ],
)
def test_shared_go_python_contract_fixtures(fixture: str, model: type[object]) -> None:
    payload = (ROOT / "contracts" / "fixtures" / fixture).read_text()
    parsed = model.model_validate_json(payload)  # type: ignore[attr-defined]
    original = json.loads(payload)
    encoded = parsed.model_dump(mode="json", exclude_unset=True)  # type: ignore[attr-defined]
    assert encoded["protocol"] == "subnet-synapse.v2"
    assert encoded == original


def test_v2_schemas_require_transport_identity_and_encode_role_policy() -> None:
    deploy_schema = json.loads(
        (ROOT / "contracts" / "schemas" / "deploy.v2.schema.json").read_text()
    )
    subnet = deploy_schema["$defs"]["SubnetBinding"]
    assert {"miner_axon_url", "miner_transport", "miner_tls_certificate_sha256"} <= set(
        subnet["required"]
    )
    assert subnet["allOf"]

    service_binding = deploy_schema["$defs"]["ServiceKeyBinding"]
    assert "transport_certificate_sha256" in service_binding["required"]
    assert service_binding["allOf"]

    registration_schema = json.loads(
        (ROOT / "contracts" / "schemas" / "miner-registration.v2.schema.json").read_text()
    )
    assert "transport_certificate_der_base64" in registration_schema["required"]
    assert registration_schema["allOf"]

    deactivate_schema = json.loads(
        (ROOT / "contracts" / "schemas" / "bridge-deactivate.v2.schema.json").read_text()
    )
    assert "miner_tls_certificate_sha256" in deactivate_schema["required"]
    assert deactivate_schema["allOf"]


def test_hotkey_signed_service_binding_is_challenge_and_block_bound() -> None:
    signer = bt.sp_core.Keypair.create_from_uri("//Alice")
    binding = sign_service_binding(
        ServiceKeyBinding(
            role="miner",
            transport="https",
            transport_certificate_sha256="22" * 32,
            network="test",
            netuid=24,
            hotkey=signer.ss58_address,
            uid=7,
            service_public_key="11" * 32,
            generation=2,
            valid_from_block=100,
            expires_at_block=120,
            challenge="fresh-challenge",
        ),
        signer,
    )
    verify_service_binding(
        binding,
        expected_hotkey=signer.ss58_address,
        expected_role="miner",
        expected_network="test",
        expected_netuid=24,
        expected_challenge="fresh-challenge",
        expected_transport="https",
        expected_transport_certificate_sha256="22" * 32,
        current_block=101,
    )
    with pytest.raises(ValueError, match="challenge"):
        verify_service_binding(
            binding,
            expected_hotkey=signer.ss58_address,
            expected_role="miner",
            expected_network="test",
            expected_netuid=24,
            expected_challenge="captured-old-challenge",
            expected_transport="https",
            expected_transport_certificate_sha256="22" * 32,
            current_block=101,
        )
    with pytest.raises(ValueError, match="current"):
        verify_service_binding(
            binding,
            expected_hotkey=signer.ss58_address,
            expected_role="miner",
            expected_network="test",
            expected_netuid=24,
            expected_challenge="fresh-challenge",
            expected_transport="https",
            expected_transport_certificate_sha256="22" * 32,
            current_block=120,
        )
    wrong_signer = bt.sp_core.Keypair.create_from_uri("//Bob")
    with pytest.raises(ValueError, match="signing wallet"):
        sign_service_binding(binding.model_copy(update={"signature": ""}), wrong_signer)


@pytest.mark.parametrize(
    "update",
    [
        {"protocol": "service-binding.v1"},
        {"transport_certificate_sha256": None},
        {"transport_certificate_sha256": "AA" * 32},
        {"transport_certificate_sha256": "22" * 31},
        {"transport": "http", "transport_certificate_sha256": "22" * 32},
    ],
)
def test_live_miner_binding_rejects_legacy_or_noncanonical_transport_pin(
    update: dict[str, object],
) -> None:
    value = {
        "protocol": "service-binding.v2",
        "role": "miner",
        "transport": "https",
        "transport_certificate_sha256": "22" * 32,
        "network": "test",
        "netuid": 24,
        "hotkey": "miner-hotkey",
        "uid": 7,
        "service_public_key": "11" * 32,
        "generation": 2,
        "valid_from_block": 100,
        "expires_at_block": 120,
        "challenge": "fresh-challenge",
        "signature": "",
    }
    value.update(update)
    with pytest.raises(ValidationError):
        ServiceKeyBinding.model_validate(value)


def test_validator_binding_is_pinless_local_and_live_ticket_rejects_downgrade() -> None:
    validator_binding = json.loads(
        (ROOT / "contracts" / "fixtures" / "chain-state.v2.json").read_text()
    )["validator_binding"]
    validator_binding["transport"] = "https"
    validator_binding["transport_certificate_sha256"] = "22" * 32
    with pytest.raises(ValidationError, match="pinless local"):
        ServiceKeyBinding.model_validate(validator_binding)

    deploy = json.loads((ROOT / "contracts" / "fixtures" / "deploy.v2.json").read_text())
    deploy["ticket"]["version"] = "deployment.v2"
    with pytest.raises(ValidationError):
        DeploySynapse.model_validate(deploy)
    deploy["ticket"]["version"] = "deployment.v3"
    deploy["ticket"]["subnet"]["miner_tls_certificate_sha256"] = None
    with pytest.raises(ValidationError, match="requires a TLS certificate fingerprint"):
        DeploySynapse.model_validate(deploy)


def test_deploy_fixture_rejects_wrong_ticket_uid() -> None:
    value = json.loads((ROOT / "contracts" / "fixtures" / "deploy.v2.json").read_text())
    value["ticket"]["subnet"]["miner_uid"] = 70_000
    with pytest.raises(ValidationError):
        DeploySynapse.model_validate(value)


@pytest.mark.parametrize("fraction_digits", range(10))
def test_signed_go_rfc3339nano_timestamps_round_trip_byte_exactly(
    fraction_digits: int,
) -> None:
    value = json.loads((ROOT / "contracts" / "fixtures" / "deploy.v2.json").read_text())
    fraction = f".{('123456789')[:fraction_digits]}" if fraction_digits else ""
    value["ticket"]["issued_at"] = f"2026-08-22T08:00:00{fraction}Z"
    value["ticket"]["expires_at"] = f"2026-08-22T08:00:01{fraction}Z"
    parsed = DeploySynapse.model_validate(value)
    encoded = parsed.model_dump(mode="json")
    assert encoded["ticket"]["issued_at"] == value["ticket"]["issued_at"]
    assert encoded["ticket"]["expires_at"] == value["ticket"]["expires_at"]


def test_rfc3339nano_ordering_preserves_submicrosecond_precision() -> None:
    value = json.loads((ROOT / "contracts" / "fixtures" / "deploy.v2.json").read_text())
    value["ticket"]["issued_at"] = "2026-08-22T08:00:00.123456788Z"
    value["ticket"]["expires_at"] = "2026-08-22T08:00:00.123456789Z"
    DeploySynapse.model_validate(value)

    for invalid_expiry in (
        "2026-08-22T08:00:00.123456788Z",
        "2026-08-22T08:00:00.123456787Z",
    ):
        value["ticket"]["expires_at"] = invalid_expiry
        with pytest.raises(ValidationError, match="expires_at must follow issued_at"):
            DeploySynapse.model_validate(value)


@pytest.mark.parametrize(
    "invalid_timestamp",
    [
        "2026-08-22T08:00:00.1234567890Z",
        "2026-08-22T08:00:00.123456789",
        "2026-02-29T08:00:00Z",
        "2026-08-22T08:00:00+24:00",
        "٢٠٢٦-08-22T08:00:00Z",
    ],
)
def test_ticket_rejects_non_go_rfc3339nano_timestamps(invalid_timestamp: str) -> None:
    value = json.loads((ROOT / "contracts" / "fixtures" / "deploy.v2.json").read_text())
    value["ticket"]["issued_at"] = invalid_timestamp
    with pytest.raises(ValidationError, match="timestamp"):
        DeploySynapse.model_validate(value)
