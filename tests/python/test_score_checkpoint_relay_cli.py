# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import ast
import base64
import errno
import hashlib
import json
import os
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import misscomputer_subnet.score_checkpoint_relay_cli as relay_cli
from misscomputer_subnet.chain import MetagraphSnapshot, NeuronRecord
from misscomputer_subnet.score_checkpoint_relay import (
    ExternalValidatorRelayPlan,
    external_validator_relay_plan_bytes,
    parse_external_validator_relay_plan,
    parse_external_validator_verification_report,
)
from misscomputer_subnet.score_checkpoint_relay_cli import (
    CheckpointLedger,
    CheckpointRelayCLIConfig,
    CheckpointRelayCLIError,
    CheckpointRelayInputFiles,
    ExternalValidatorWeightPlanPreparation,
    InputFile,
    RelayOutputPaths,
    build_bound_weight_plan,
    execute_checkpoint_relay,
    parse_checkpoint_ledger_pointer,
    parse_checkpoint_ledger_record,
    run_cli,
)
from misscomputer_subnet.weight_executor import (
    WeightExecutionError,
    derive_execution_vector,
    validate_execution_preflight,
)
from misscomputer_subnet.weight_plan import (
    WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
    load_weight_plan,
    snapshot_identity_fingerprint,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "contracts" / "fixtures"


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def digest_document(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def changed_digest(value: str) -> str:
    replacement = "0" if value[0] != "0" else "1"
    return replacement + value[1:]


def changed_binding(field: str, value: object) -> object:
    if field == "weights" and isinstance(value, list):
        changed_weights = [dict(item) for item in value]
        changed_weights[0]["source_canonical_score_ppm"] -= 1
        return changed_weights
    if field == "weight_plan" and isinstance(value, dict):
        return {**value, "version_key": WEIGHT_PLAN_PROTOCOL_VERSION_KEY + 1}
    if field == "network":
        return "test"
    if field == "validator_hotkey" and isinstance(value, str):
        return f"{value}B"
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str) and len(value) == 64:
        return changed_digest(value)
    raise AssertionError(f"no binding mutation for {field}")


def secure_write(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    path.chmod(0o600)
    return path


def input_file(path: Path) -> InputFile:
    return InputFile(str(path), hashlib.sha256(path.read_bytes()).hexdigest())


def fixture_config(tmp_path: Path) -> CheckpointRelayCLIConfig:
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    publication = tmp_path / "publication"
    publication.mkdir(mode=0o700)
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    verification_input = json.loads(
        (FIXTURES / "external-validator-verification-input.v1.json").read_bytes()
    )
    paths = {
        "policy": secure_write(
            publication / "policy.json",
            (FIXTURES / "score-checkpoint-trust-policy.v1.json").read_bytes(),
        ),
        "checkpoint": secure_write(
            publication / "checkpoint.json",
            (FIXTURES / "central-score-checkpoint.v1.json").read_bytes(),
        ),
        "report": secure_write(
            publication / "report.json",
            (FIXTURES / "canonical-synthetic-score-report.v1.json").read_bytes(),
        ),
        "metagraph": secure_write(
            publication / "metagraph.json",
            (FIXTURES / "relay-finalized-metagraph-snapshot.v1.json").read_bytes(),
        ),
    }
    signature_paths = tuple(
        secure_write(
            publication / f"signature-{index}.json",
            canonical(signature) + b"\n",
        )
        for index, signature in enumerate(verification_input["signatures"])
    )
    return CheckpointRelayCLIConfig(
        inputs=CheckpointRelayInputFiles(
            trust_policy=input_file(paths["policy"]),
            checkpoint=input_file(paths["checkpoint"]),
            signatures=tuple(input_file(path) for path in signature_paths),
            canonical_score_report=input_file(paths["report"]),
            finalized_metagraph=input_file(paths["metagraph"]),
        ),
        evaluation_epoch=verification_input["evaluation_epoch"],
        validator_uid=verification_input["validator"]["uid"],
        validator_hotkey=verification_input["validator"]["hotkey"],
        state_root=str(tmp_path / "state"),
        trusted_ledger_anchor_digest_sha256="genesis",
        weight_plan_tempo=360,
        weight_plan_snapshot_identity_sha256=hashlib.sha256(
            b"trusted-full-metagraph-identity"
        ).hexdigest(),
        outputs=RelayOutputPaths(
            verification_report=str(output / "verification.json"),
            relay_plan=str(output / "relay.json"),
            weight_plan=str(output / "weight-plan.json"),
            preparation=str(output / "preparation.json"),
        ),
    )


def config_argv(config: CheckpointRelayCLIConfig) -> list[str]:
    values = [
        "--trust-policy",
        config.inputs.trust_policy.path,
        "--trust-policy-sha256",
        config.inputs.trust_policy.sha256,
        "--checkpoint",
        config.inputs.checkpoint.path,
        "--checkpoint-sha256",
        config.inputs.checkpoint.sha256,
    ]
    for signature in config.inputs.signatures:
        values.extend(("--signature", signature.path))
    for signature in config.inputs.signatures:
        values.extend(("--signature-sha256", signature.sha256))
    values.extend(
        (
            "--score-report",
            config.inputs.canonical_score_report.path,
            "--score-report-sha256",
            config.inputs.canonical_score_report.sha256,
            "--metagraph",
            config.inputs.finalized_metagraph.path,
            "--metagraph-sha256",
            config.inputs.finalized_metagraph.sha256,
            "--evaluation-epoch",
            str(config.evaluation_epoch),
            "--validator-uid",
            str(config.validator_uid),
            "--validator-hotkey",
            config.validator_hotkey,
            "--state-root",
            config.state_root,
            "--trusted-ledger-anchor",
            config.trusted_ledger_anchor_digest_sha256,
            "--weight-plan-tempo",
            str(config.weight_plan_tempo),
            "--weight-plan-snapshot-identity-sha256",
            config.weight_plan_snapshot_identity_sha256,
            "--verification-report-output",
            config.outputs.verification_report,
            "--relay-plan-output",
            config.outputs.relay_plan,
            "--weight-plan-output",
            config.outputs.weight_plan,
            "--preparation-output",
            config.outputs.preparation,
        )
    )
    return values


def test_end_to_end_outputs_ledger_and_idempotent_restart(tmp_path: Path) -> None:
    config = fixture_config(tmp_path)
    first = execute_checkpoint_relay(config)
    output_bytes = tuple(
        Path(path).read_bytes()
        for path in (
            config.outputs.verification_report,
            config.outputs.relay_plan,
            config.outputs.weight_plan,
            config.outputs.preparation,
        )
    )
    assert first.replayed is False
    assert parse_external_validator_verification_report(output_bytes[0])
    assert parse_external_validator_relay_plan(output_bytes[1])
    weight_plan = load_weight_plan(config.outputs.weight_plan)
    preparation = ExternalValidatorWeightPlanPreparation.model_validate_json(output_bytes[3])
    assert preparation.submission_authorized is False
    assert weight_plan.version_key == WEIGHT_PLAN_PROTOCOL_VERSION_KEY == 2
    assert preparation.weight_plan_digest_sha256 == weight_plan.digest_sha256
    assert [round(item.weight * 65_535) for item in weight_plan.weights] == [
        item.weight_u16 for item in first.relay_plan.weights if item.weight_u16 > 0
    ]

    state_root = Path(config.state_root)
    assert stat.S_IMODE(state_root.stat().st_mode) == 0o700
    assert {item.name for item in state_root.iterdir()} == {
        "anchor.json",
        "head.json",
        "ledger.lock",
        "record-00000000000000000001.json",
    }
    for item in state_root.iterdir():
        assert stat.S_IMODE(item.stat().st_mode) == 0o600
        assert item.stat().st_nlink == 1
    record = parse_checkpoint_ledger_record(
        (state_root / "record-00000000000000000001.json").read_bytes()
    )
    head = parse_checkpoint_ledger_pointer((state_root / "head.json").read_bytes())
    anchor = parse_checkpoint_ledger_pointer((state_root / "anchor.json").read_bytes())
    assert record.record_digest_sha256 == head.last_record_digest_sha256
    assert record.record_digest_sha256 == anchor.last_record_digest_sha256
    assert preparation.ledger_head_digest_sha256 == head.pointer_digest_sha256
    assert preparation.ledger_anchor_digest_sha256 == anchor.pointer_digest_sha256

    second = execute_checkpoint_relay(config)
    assert second.replayed is True
    assert output_bytes == tuple(
        Path(path).read_bytes()
        for path in (
            config.outputs.verification_report,
            config.outputs.relay_plan,
            config.outputs.weight_plan,
            config.outputs.preparation,
        )
    )


def test_deterministic_bytes_across_roots_and_input_order(tmp_path: Path) -> None:
    first = fixture_config(tmp_path / "first")
    second = fixture_config(tmp_path / "second")
    second = replace(
        second,
        inputs=replace(second.inputs, signatures=tuple(reversed(second.inputs.signatures))),
    )
    first_result = execute_checkpoint_relay(first)
    second_result = execute_checkpoint_relay(second)
    assert first_result == second_result
    for first_path, second_path in zip(
        (
            first.outputs.verification_report,
            first.outputs.relay_plan,
            first.outputs.weight_plan,
            first.outputs.preparation,
        ),
        (
            second.outputs.verification_report,
            second.outputs.relay_plan,
            second.outputs.weight_plan,
            second.outputs.preparation,
        ),
        strict=True,
    ):
        assert Path(first_path).read_bytes() == Path(second_path).read_bytes()
    assert [
        hashlib.sha256(Path(path).read_bytes()).hexdigest()
        for path in (
            first.outputs.verification_report,
            first.outputs.relay_plan,
            first.outputs.weight_plan,
            first.outputs.preparation,
        )
    ] == [
        "2676e5b407426a994aeda5a6868f55073b5d7f3d0e933728bc93590df48f867c",
        "051923a3fe842fb049d0afc32842ce45bffcbfe28aef5929e3c13e6ab0b3a9a9",
        "bad7871898bc6ad6901f0aaba1e50c0fcc02e1aedff5eadd7ddc1b7b849d8f82",
        "2a47e653e2697d861d2f30a78755fab3a5f6d0a5744505f65eb9dcd76778760a",
    ]


@pytest.mark.parametrize("attack", ["mode", "symlink", "hardlink", "digest", "duplicate"])
def test_loader_rejects_metadata_alias_and_canonical_attacks(
    tmp_path: Path,
    attack: str,
) -> None:
    config = fixture_config(tmp_path)
    checkpoint = Path(config.inputs.checkpoint.path)
    if attack == "mode":
        checkpoint.chmod(0o644)
    elif attack == "symlink":
        target = checkpoint.with_name("checkpoint-target.json")
        checkpoint.rename(target)
        checkpoint.symlink_to(target)
    elif attack == "hardlink":
        checkpoint.with_name("checkpoint-alias.json").hardlink_to(checkpoint)
    elif attack == "digest":
        config = replace(
            config,
            inputs=replace(
                config.inputs,
                checkpoint=replace(config.inputs.checkpoint, sha256="0" * 64),
            ),
        )
    else:
        document = json.loads(checkpoint.read_bytes())
        rendered = checkpoint.read_bytes().rstrip()
        key = next(iter(document))
        secure_write(checkpoint, rendered[:-1] + f',"{key}":null}}\n'.encode())
        config = replace(
            config,
            inputs=replace(config.inputs, checkpoint=input_file(checkpoint)),
        )
    with pytest.raises(CheckpointRelayCLIError):
        execute_checkpoint_relay(config)
    assert not Path(config.state_root).exists()


def test_signature_tamper_threshold_path_is_rejected_before_commit(tmp_path: Path) -> None:
    config = fixture_config(tmp_path)
    signature_path = Path(config.inputs.signatures[0].path)
    document = json.loads(signature_path.read_bytes())
    signature = bytearray(base64.b64decode(document["signature_base64"]))
    signature[-1] ^= 1
    document["signature_base64"] = base64.b64encode(signature).decode("ascii")
    secure_write(signature_path, canonical(document) + b"\n")
    signatures = list(config.inputs.signatures)
    signatures[0] = input_file(signature_path)
    config = replace(config, inputs=replace(config.inputs, signatures=tuple(signatures)))
    with pytest.raises(Exception, match="signature_invalid"):
        execute_checkpoint_relay(config)
    state_root = Path(config.state_root)
    assert not state_root.exists() or not list(state_root.glob("record-*.json"))


@pytest.mark.parametrize("failed_pointer", ["head.json", "anchor.json"])
def test_record_and_pointer_torn_write_forward_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_pointer: str,
) -> None:
    config = fixture_config(tmp_path)
    original = relay_cli._replace_state_file
    failed = False

    def fail_once(
        directory_fd: int,
        name: Any,
        install_name: Any,
        rendered: bytes,
    ) -> None:
        nonlocal failed
        if name == failed_pointer and not failed:
            failed = True
            raise CheckpointRelayCLIError("injected_crash")
        original(directory_fd, name, install_name, rendered)

    monkeypatch.setattr(relay_cli, "_replace_state_file", fail_once)
    with pytest.raises(CheckpointRelayCLIError, match="injected_crash"):
        execute_checkpoint_relay(config)
    monkeypatch.setattr(relay_cli, "_replace_state_file", original)
    recovered = execute_checkpoint_relay(config)
    assert recovered.replayed is True
    assert (
        parse_checkpoint_ledger_pointer(
            (Path(config.state_root) / "head.json").read_bytes()
        ).record_count
        == 1
    )
    assert (
        parse_checkpoint_ledger_pointer(
            (Path(config.state_root) / "anchor.json").read_bytes()
        ).record_count
        == 1
    )


def test_valid_install_residue_recovers_but_arbitrary_temp_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = fixture_config(tmp_path / "recover")
    original_replace = os.replace
    failed = False

    def interrupt_replace(
        source: Any,
        destination: Any,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        nonlocal failed
        if source == relay_cli.HEAD_INSTALL_NAME and not failed:
            failed = True
            raise OSError(5, "injected")
        original_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(os, "replace", interrupt_replace)
    with pytest.raises(CheckpointRelayCLIError):
        execute_checkpoint_relay(config)
    monkeypatch.setattr(os, "replace", original_replace)
    assert (Path(config.state_root) / relay_cli.HEAD_INSTALL_NAME).exists()
    assert execute_checkpoint_relay(config).replayed is True
    assert not (Path(config.state_root) / relay_cli.HEAD_INSTALL_NAME).exists()

    rejected = fixture_config(tmp_path / "reject")
    execute_checkpoint_relay(rejected)
    temporary = Path(rejected.state_root) / relay_cli.HEAD_INSTALL_NAME
    secure_write(temporary, b"{}\n")
    with pytest.raises(CheckpointRelayCLIError):
        execute_checkpoint_relay(rejected)
    assert temporary.exists()


def test_concurrent_lock_and_output_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = fixture_config(tmp_path / "lock")
    result = execute_checkpoint_relay(config)
    policy = result.preparation
    del policy
    loaded = relay_cli.load_checkpoint_relay_inputs(config.inputs)
    with CheckpointLedger(
        config.state_root,
        loaded.trust_policy,
        trusted_anchor_digest_sha256=result.preparation.ledger_anchor_digest_sha256,
    ):
        with pytest.raises(CheckpointRelayCLIError, match="ledger_busy"):
            execute_checkpoint_relay(
                replace(
                    config,
                    trusted_ledger_anchor_digest_sha256=(
                        result.preparation.ledger_anchor_digest_sha256
                    ),
                )
            )

    interrupted = fixture_config(tmp_path / "outputs")
    original = relay_cli._write_output
    calls = 0

    def fail_after_one(*args: Any, **kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise CheckpointRelayCLIError("injected_output_crash")
        original(*args, **kwargs)

    monkeypatch.setattr(relay_cli, "_write_output", fail_after_one)
    with pytest.raises(CheckpointRelayCLIError, match="injected_output_crash"):
        execute_checkpoint_relay(interrupted)
    monkeypatch.setattr(relay_cli, "_write_output", original)
    assert Path(interrupted.outputs.verification_report).exists()
    assert execute_checkpoint_relay(interrupted).replayed is True
    assert all(
        Path(path).exists()
        for path in (
            interrupted.outputs.verification_report,
            interrupted.outputs.relay_plan,
            interrupted.outputs.weight_plan,
            interrupted.outputs.preparation,
        )
    )


@pytest.mark.parametrize("attack", ["clobber", "symlink", "world", "hardlink"])
def test_output_targets_fail_closed(tmp_path: Path, attack: str) -> None:
    config = fixture_config(tmp_path)
    target = Path(config.outputs.verification_report)
    if attack == "clobber":
        secure_write(target, b"occupied\n")
    elif attack == "symlink":
        other = secure_write(target.with_name("other.json"), b"occupied\n")
        target.symlink_to(other)
    elif attack == "world":
        secure_write(target, b"occupied\n").chmod(0o644)
    else:
        secure_write(target, b"occupied\n")
        target.with_name("alias.json").hardlink_to(target)
    with pytest.raises(CheckpointRelayCLIError):
        execute_checkpoint_relay(config)
    assert not list(Path(config.state_root).glob("record-*.json"))


def test_weight_plan_conversion_excludes_zero_without_substitution() -> None:
    relay = parse_external_validator_relay_plan(
        (FIXTURES / "external-validator-score-relay-plan.v1.json").read_bytes()
    )
    document = relay.model_dump(mode="json", by_alias=True)
    weights = document["weights"]
    weights[0]["source_eligibility_status"] = "ineligible"
    weights[0]["source_canonical_score_ppm"] = 0
    weights[0]["weight_u16"] = 0
    weights[1]["weight_u16"] += 16_384
    document["weight_vector_digest_sha256"] = digest_document(weights)
    document.pop("plan_digest_sha256")
    document["plan_digest_sha256"] = digest_document(document)
    changed = ExternalValidatorRelayPlan.model_validate(document)
    policy = relay_cli.parse_checkpoint_trust_policy(
        (FIXTURES / "score-checkpoint-trust-policy.v1.json").read_bytes()
    )
    plan = build_bound_weight_plan(
        changed,
        policy,
        record_index=1,
        prior_record_digest_sha256=None,
        tempo=360,
        snapshot_identity_fingerprint_sha256="1" * 64,
    )
    assert [item.hotkey for item in plan.weights] == [
        item.miner_hotkey for item in changed.weights if item.weight_u16 > 0
    ]
    assert [round(item.weight * 65_535) for item in plan.weights] == [
        item.weight_u16 for item in changed.weights if item.weight_u16 > 0
    ]
    assert plan.version_key == WEIGHT_PLAN_PROTOCOL_VERSION_KEY


def test_verified_relay_plan_is_accepted_by_existing_executor_preflight(
    tmp_path: Path,
) -> None:
    config = fixture_config(tmp_path)
    relay_metagraph = json.loads(
        (FIXTURES / "relay-finalized-metagraph-snapshot.v1.json").read_bytes()
    )
    validator = relay_metagraph["validator"]
    snapshot = MetagraphSnapshot(
        network=relay_metagraph["network"],
        netuid=relay_metagraph["netuid"],
        block=relay_metagraph["finalized_height"],
        tempo=config.weight_plan_tempo,
        neurons=(
            NeuronRecord(
                uid=validator["uid"],
                hotkey=validator["hotkey"],
                validator_permit=True,
                tao_stake=1.0,
                axon=None,
                active=True,
            ),
            *(
                NeuronRecord(
                    uid=item["uid"],
                    hotkey=item["hotkey"],
                    validator_permit=False,
                    tao_stake=0.0,
                    axon=None,
                    active=True,
                )
                for item in relay_metagraph["miner_mappings"]
            ),
        ),
        finalized=True,
    )
    config = replace(
        config,
        weight_plan_snapshot_identity_sha256=snapshot_identity_fingerprint(snapshot),
    )

    result = execute_checkpoint_relay(config)
    plan = result.weight_plan
    assert plan.version_key == WEIGHT_PLAN_PROTOCOL_VERSION_KEY == 2
    assert plan.snapshot.identity_fingerprint == snapshot_identity_fingerprint(snapshot)

    validate_execution_preflight(
        plan,
        snapshot,
        network=snapshot.network,
        netuid=snapshot.netuid,
        validator_hotkey=validator["hotkey"],
    )
    vector = derive_execution_vector(
        plan,
        snapshot,
        network=snapshot.network,
        netuid=snapshot.netuid,
        validator_hotkey=validator["hotkey"],
    )
    assert vector.plan_digest_sha256 == plan.digest_sha256
    assert vector.version_key == WEIGHT_PLAN_PROTOCOL_VERSION_KEY
    assert [(item.uid, item.hotkey) for item in vector.weights] == [
        (item.uid, item.hotkey) for item in plan.weights
    ]

    with pytest.raises(WeightExecutionError) as error:
        validate_execution_preflight(
            replace(plan, version_key=WEIGHT_PLAN_PROTOCOL_VERSION_KEY + 1),
            snapshot,
            network=snapshot.network,
            netuid=snapshot.netuid,
            validator_hotkey=validator["hotkey"],
        )
    assert error.value.code == "unsupported_version_key"


def test_relay_cli_rejects_external_version_key_override(
    tmp_path: Path,
    capsys: Any,
) -> None:
    config = fixture_config(tmp_path)
    assert run_cli([*config_argv(config), "--version-key", "3"]) == 64
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "REJECTED usage\n"
    assert not Path(config.state_root).exists()
    assert not any(
        Path(path).exists()
        for path in (
            config.outputs.verification_report,
            config.outputs.relay_plan,
            config.outputs.weight_plan,
            config.outputs.preparation,
        )
    )


def test_canonical_ledger_artifact_cannot_override_protocol_version(
    tmp_path: Path,
) -> None:
    config = fixture_config(tmp_path)
    result = execute_checkpoint_relay(config)
    record_path = Path(config.state_root) / "record-00000000000000000001.json"
    record_document = json.loads(record_path.read_bytes())
    unsupported_plan = replace(
        result.weight_plan,
        version_key=WEIGHT_PLAN_PROTOCOL_VERSION_KEY + 1,
    )
    record_document["weight_plan"] = unsupported_plan.document()
    record_document["weight_plan_digest_sha256"] = unsupported_plan.digest_sha256
    unsigned = {
        key: value for key, value in record_document.items() if key != "record_digest_sha256"
    }
    record_document["record_digest_sha256"] = digest_document(unsigned)
    secure_write(record_path, canonical(record_document) + b"\n")
    assert parse_checkpoint_ledger_record(record_path.read_bytes())

    with pytest.raises(CheckpointRelayCLIError, match="ledger_weight_plan_invalid"):
        execute_checkpoint_relay(config)


def test_relay_and_preparation_digests_reject_identity_binding_tampering(
    tmp_path: Path,
) -> None:
    result = execute_checkpoint_relay(fixture_config(tmp_path))
    relay_document = result.relay_plan.model_dump(mode="json", by_alias=True)
    relay_bindings = (
        "network",
        "netuid",
        "validator_uid",
        "validator_hotkey",
        "finalized_height",
        "finalized_block_hash",
        "finalized_epoch",
        "checkpoint_digest_sha256",
        "canonical_score_report_digest_sha256",
        "input_snapshot_digest_sha256",
        "score_vector_digest_sha256",
        "metagraph_snapshot_digest_sha256",
        "verification_input_digest_sha256",
        "verification_report_digest_sha256",
        "next_chain_state_digest_sha256",
        "weights",
        "weight_vector_digest_sha256",
    )
    for field in relay_bindings:
        tampered = {
            **relay_document,
            field: changed_binding(field, relay_document[field]),
        }
        unsigned = {key: value for key, value in tampered.items() if key != "plan_digest_sha256"}
        assert digest_document(unsigned) != relay_document["plan_digest_sha256"], field
        with pytest.raises(ValidationError):
            ExternalValidatorRelayPlan.model_validate(tampered)

    preparation_document = result.preparation.model_dump(mode="json", by_alias=True)
    preparation_bindings = (
        "network",
        "netuid",
        "validator_uid",
        "validator_hotkey",
        "finalized_height",
        "finalized_block_hash",
        "finalized_epoch",
        "checkpoint_digest_sha256",
        "canonical_score_report_digest_sha256",
        "input_snapshot_digest_sha256",
        "central_scoring_policy_digest_sha256",
        "trust_policy_digest_sha256",
        "metagraph_snapshot_digest_sha256",
        "verification_input_digest_sha256",
        "verification_report_digest_sha256",
        "relay_plan_digest_sha256",
        "next_chain_state_digest_sha256",
        "ledger_record_index",
        "ledger_record_digest_sha256",
        "ledger_head_digest_sha256",
        "ledger_anchor_digest_sha256",
        "normalized_weight_vector_digest_sha256",
        "weight_plan",
        "weight_plan_digest_sha256",
        "submission_authorized",
    )
    for field in preparation_bindings:
        tampered = {
            **preparation_document,
            field: changed_binding(field, preparation_document[field]),
        }
        unsigned = {
            key: value for key, value in tampered.items() if key != "preparation_digest_sha256"
        }
        assert digest_document(unsigned) != preparation_document["preparation_digest_sha256"], field
        with pytest.raises(ValidationError):
            ExternalValidatorWeightPlanPreparation.model_validate(tampered)


def test_cli_statuses_are_stable_and_sanitized(tmp_path: Path, capsys: Any) -> None:
    config = fixture_config(tmp_path)
    assert run_cli(config_argv(config)) == 0
    captured = capsys.readouterr()
    assert captured.out == "VERIFIED\n"
    assert captured.err == ""
    opaque_path = "/do-not-echo/private-input.json"
    assert run_cli(["--checkpoint", opaque_path]) == 64
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "REJECTED usage\n"
    assert opaque_path not in captured.err


def test_source_has_no_live_or_secret_capability() -> None:
    source_path = ROOT / "src" / "misscomputer_subnet" / "score_checkpoint_relay_cli.py"
    source = source_path.read_text()
    tree = ast.parse(source)
    imported: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                called.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                called.add(node.func.attr)
    assert not imported & {
        "bittensor",
        "httpx",
        "requests",
        "socket",
        "subprocess",
        "urllib",
    }
    assert not called & {
        "connect",
        "create_subprocess_exec",
        "getenv",
        "set_weights",
        "sign",
        "submit",
        "system",
        "urlopen",
    }
    lowered = source.lower()
    for forbidden in (
        "ed25519privatekey",
        "os.environ",
        ".sign(",
        "import bittensor",
        "import socket",
        "import subprocess",
    ):
        assert forbidden not in lowered

    weight_plan_tree = ast.parse(
        (ROOT / "src" / "misscomputer_subnet" / "weight_plan.py").read_text()
    )
    assert not any(
        isinstance(node, ast.ImportFrom) and node.module == "chain"
        for node in weight_plan_tree.body
    )


def test_fixture_relay_stays_canonical() -> None:
    relay = parse_external_validator_relay_plan(
        (FIXTURES / "external-validator-score-relay-plan.v1.json").read_bytes()
    )
    assert (
        external_validator_relay_plan_bytes(relay)
        == (FIXTURES / "external-validator-score-relay-plan.v1.json").read_bytes()
    )


def test_unnamed_file_installs_survive_unprivileged_linkat(
    tmp_path: Path,
    unprivileged_linkat: list[int],
) -> None:
    """Linux before 6.10 refuses ``linkat(AT_EMPTY_PATH)`` without
    ``CAP_DAC_READ_SEARCH``; the ``/proc/self/fd`` form must install the very
    same pinned inode with unchanged mode, link-count, and replay semantics."""

    tmp_path.chmod(0o700)
    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        relay_cli._install_new_file(directory_fd, "record.json", b"one\n")
        assert unprivileged_linkat == [relay_cli._AT_EMPTY_PATH, relay_cli._AT_SYMLINK_FOLLOW]
        installed = tmp_path / "record.json"
        assert installed.read_bytes() == b"one\n"
        assert stat.S_IMODE(installed.stat().st_mode) == 0o600
        assert installed.stat().st_nlink == 1

        with pytest.raises(CheckpointRelayCLIError, match="^file_exists$"):
            relay_cli._install_new_file(directory_fd, "record.json", b"two\n")
        assert installed.read_bytes() == b"one\n"

        relay_cli._replace_state_file(directory_fd, "head.json", ".head.install", b"head\n")
        relay_cli._replace_state_file(directory_fd, "head.json", ".head.install", b"head2\n")
        assert (tmp_path / "head.json").read_bytes() == b"head2\n"
        assert stat.S_IMODE((tmp_path / "head.json").stat().st_mode) == 0o600
        assert not (tmp_path / ".head.install").exists()
        assert {item.name for item in tmp_path.iterdir()} == {"record.json", "head.json"}
    finally:
        os.close(directory_fd)


def test_unnamed_file_link_reports_the_fallback_error_when_both_forms_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    calls: list[int] = []

    def refused(olddirfd: int, oldpath: bytes, newdirfd: int, newpath: bytes, flags: int) -> int:
        calls.append(flags)
        return errno.ENOENT if flags & relay_cli._AT_EMPTY_PATH else errno.EACCES

    monkeypatch.setattr(relay_cli, "_linkat", refused)
    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        with pytest.raises(CheckpointRelayCLIError, match="^file_create_failed$"):
            relay_cli._install_new_file(directory_fd, "record.json", b"one\n")
    finally:
        os.close(directory_fd)
    assert calls == [relay_cli._AT_EMPTY_PATH, relay_cli._AT_SYMLINK_FOLLOW]
    assert list(tmp_path.iterdir()) == []


def test_relay_ledger_and_outputs_work_without_cap_dac_read_search(
    tmp_path: Path,
    unprivileged_linkat: list[int],
) -> None:
    config = fixture_config(tmp_path)
    result = execute_checkpoint_relay(config)
    assert result.replayed is False
    assert relay_cli._AT_EMPTY_PATH in unprivileged_linkat
    assert relay_cli._AT_SYMLINK_FOLLOW in unprivileged_linkat
    state_root = Path(config.state_root)
    assert (
        parse_checkpoint_ledger_pointer((state_root / "anchor.json").read_bytes()).record_count == 1
    )
    for item in state_root.iterdir():
        assert stat.S_IMODE(item.stat().st_mode) == 0o600
        assert item.stat().st_nlink == 1
    assert execute_checkpoint_relay(config).replayed is True
