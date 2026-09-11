# SPDX-License-Identifier: AGPL-3.0-only
"""Executed terminal-review reproductions: cleanup and verifier composition."""

from __future__ import annotations

import copy
import errno
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from test_public_verifier import integration_inputs
from test_weight_executor import SimulatedCrash, persist_plan

import misscomputer_subnet.assignment_probe_cli as probe_cli
import misscomputer_subnet.weight_plan as plan_module
from misscomputer_subnet.assignment_probe import (
    assignment_manifest_chain_state_bytes,
    parse_validator_probe_report,
    validator_probe_report_bytes,
)
from misscomputer_subnet.public_verifier import PublicVerifierError, verify_public_relay_path


def assert_closed(descriptors: list[int]) -> None:
    leaked = []
    for descriptor in descriptors:
        try:
            os.fstat(descriptor)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            leaked.append(descriptor)
            os.close(descriptor)
    assert not leaked, "owned descriptors escaped cleanup"


@pytest.mark.parametrize("fault_type", [OSError, SimulatedCrash])
def test_target_close_failure_still_retires_reopened_directory_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault_type: type[BaseException]
) -> None:
    plan, path = persist_plan(tmp_path)
    chain = plan_module._pin_directory_chain(str(tmp_path))
    real_pin, real_close = plan_module._pin_directory_chain, os.close
    reopened_descriptors: list[int] = []

    def pin(parent: str) -> Any:
        result = real_pin(parent)
        reopened_descriptors.extend(result.descriptors)
        return result

    def close(descriptor: int) -> None:
        regular = stat.S_ISREG(os.fstat(descriptor).st_mode)
        real_close(descriptor)
        if regular:
            raise fault_type("private-target-close")

    try:
        with monkeypatch.context() as patch:
            patch.setattr(plan_module, "_pin_directory_chain", pin)
            patch.setattr(os, "close", close)
            with pytest.raises(fault_type):
                target = os.stat(path)
                plan_module._verify_configured_target(
                    chain,
                    Path(path).name,
                    identity=(target.st_dev, target.st_ino),
                    rendered=plan.canonical_bytes(),
                )
    finally:
        chain.close()
    assert_closed(list(set(reopened_descriptors)))


@pytest.mark.parametrize("fault_type", [OSError, SimulatedCrash])
def test_atomic_plan_unlink_failure_attempts_temporary_and_directory_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault_type: type[BaseException]
) -> None:
    plan, _ = persist_plan(tmp_path)
    descriptors: list[int] = []
    real_pin, real_prepare = plan_module._pin_directory_chain, plan_module._prepare_temporary_plan
    unlink_attempted = False

    def pin(parent: str) -> Any:
        chain = real_pin(parent)
        descriptors.extend(chain.descriptors)
        return chain

    def prepare(*args: Any) -> Any:
        temporary = real_prepare(*args)
        descriptors.append(temporary.descriptor)
        return temporary

    def replace(*args: Any, **kwargs: Any) -> None:
        raise fault_type("private-install-failure")

    def unlink(*args: Any, **kwargs: Any) -> None:
        nonlocal unlink_attempted
        unlink_attempted = True
        raise fault_type("private-unlink-failure")

    with monkeypatch.context() as patch:
        patch.setattr(plan_module, "_pin_directory_chain", pin)
        patch.setattr(plan_module, "_prepare_temporary_plan", prepare)
        patch.setattr(os, "replace", replace)
        patch.setattr(os, "unlink", unlink)
        with pytest.raises(fault_type):
            plan_module.write_weight_plan_atomic(plan, tmp_path / "second.json")
    assert unlink_attempted
    assert_closed(list(set(descriptors)))
    # Unlink refusal leaves only an owner-only, recoverable temporary artifact.
    for path in tmp_path.glob(".weight-plan.tmp-*"):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        path.unlink()


@pytest.mark.parametrize("stage", ["root_stat", "child_stat", "child_open"])
def test_directory_acquisition_baseexception_closes_every_acquired_fd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    descriptors: list[int] = []
    real_open, real_stat, real_close = os.open, os.fstat, os.close
    stat_count = 0

    def open_fd(*args: Any, **kwargs: Any) -> int:
        if stage == "child_open" and descriptors:
            raise SimulatedCrash("private-open-failure")
        descriptor = real_open(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    def fstat(descriptor: int) -> os.stat_result:
        nonlocal stat_count
        stat_count += 1
        if (stage == "root_stat" and stat_count == 1) or (
            stage == "child_stat" and stat_count == 2
        ):
            raise SimulatedCrash("private-stat-failure")
        return real_stat(descriptor)

    def close(descriptor: int) -> None:
        real_close(descriptor)
        if descriptor == descriptors[-1]:
            raise SimulatedCrash("private-cleanup-failure")

    with monkeypatch.context() as patch:
        patch.setattr(os, "open", open_fd)
        patch.setattr(os, "supports_dir_fd", {*os.supports_dir_fd, open_fd})
        patch.setattr(os, "fstat", fstat)
        patch.setattr(os, "close", close)
        with pytest.raises(SimulatedCrash, match="private-(open|stat)-failure"):
            plan_module._pin_directory_chain(str(tmp_path))
    assert_closed(descriptors)


@pytest.mark.parametrize("mode", ["catch_up", "direct", "reprobe"])
def test_verifier_result_persists_exact_live_head_under_probe_lock(
    tmp_path: Path, mode: str
) -> None:
    values = integration_inputs()
    verified = verify_public_relay_path(**values)
    if mode == "direct":
        from misscomputer_subnet.manifest_publication import replay_manifest_history

        values["prior_chain_state"] = replay_manifest_history(
            values["prior_chain_state"],
            values["history"],
            values["trust_policy"],
            evaluation_epoch=values["evaluation_epoch"],
        )
        values["history"] = ()
    elif mode == "reprobe":
        values["prior_chain_state"] = verified.manifest_verification.next_chain_state
        values["history"] = ()
    verified = verify_public_relay_path(**values)
    with probe_cli._StateRoot(str(tmp_path)) as root:
        root.replace_state(assignment_manifest_chain_state_bytes(values["prior_chain_state"]))
    expected = verified.manifest_verification.next_chain_state
    persisted = probe_cli.persist_assignment_manifest_catch_up(
        state_root=str(tmp_path),
        trust_policy=values["trust_policy"],
        history=values["history"],
        evaluation_epoch=values["evaluation_epoch"],
        expected_anchor_sha256=values["prior_chain_state"].state_digest_sha256,
        expected_next_state_sha256=expected.state_digest_sha256,
        head_manifest=values["head_manifest"],
        head_signatures=values["head_signatures"],
        current_finalized_height=values["current_finalized_height"],
    )
    assert persisted == expected
    assert persisted.last_sequence == 3
    with probe_cli._StateRoot(str(tmp_path)) as root:
        assert root.read_state() == expected


def test_retained_archive_stale_digest_rejected_before_submit_plan() -> None:
    values = integration_inputs()
    reports = copy.deepcopy(values["retained_probe_reports"])
    reports[0].observations.pop()
    with pytest.raises(ValueError, match="report_counts_invalid"):
        parse_validator_probe_report(validator_probe_report_bytes(reports[0]))
    values["retained_probe_reports"] = reports
    with pytest.raises(PublicVerifierError, match="^decision_probe_records_invalid$"):
        verify_public_relay_path(**values)


@pytest.mark.parametrize("fault", ["signature", "expired_head", "missing_height", "wrong_state"])
def test_live_head_handoff_refuses_invalid_input_without_state_write(
    tmp_path: Path, fault: str
) -> None:
    values = integration_inputs()
    verified = verify_public_relay_path(**values)
    prior = values["prior_chain_state"]
    expected = verified.manifest_verification.next_chain_state
    with probe_cli._StateRoot(str(tmp_path)) as root:
        root.replace_state(assignment_manifest_chain_state_bytes(prior))
    arguments = {
        "state_root": str(tmp_path),
        "trust_policy": values["trust_policy"],
        "history": values["history"],
        "evaluation_epoch": (
            values["evaluation_epoch"] + 100_000
            if fault == "expired_head"
            else values["evaluation_epoch"]
        ),
        "expected_anchor_sha256": prior.state_digest_sha256,
        "expected_next_state_sha256": expected.state_digest_sha256,
        "head_manifest": values["head_manifest"],
        "head_signatures": () if fault == "signature" else values["head_signatures"],
        "current_finalized_height": (
            None if fault == "missing_height" else values["current_finalized_height"]
        ),
    }
    if fault == "wrong_state":
        arguments["expected_next_state_sha256"] = prior.state_digest_sha256
    expected_code = "catch_up_state_mismatch" if fault == "wrong_state" else "catch_up_invalid"
    with pytest.raises(probe_cli.AssignmentProbeCLIError, match=f"^{expected_code}$"):
        probe_cli.persist_assignment_manifest_catch_up(**arguments)
    with probe_cli._StateRoot(str(tmp_path)) as root:
        assert root.read_state() == prior
