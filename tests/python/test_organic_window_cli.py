# SPDX-License-Identifier: AGPL-3.0-only
"""The organic scoring window coordinator (``misscomputer-organic-window``)."""

from __future__ import annotations

import asyncio
import functools
import hashlib
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from assignment_probe_context import FINALIZED_HEIGHT, signer_keys
from organic_context import (
    REGISTERED_BLOCK_HASH,
    VALIDATOR_HOTKEY,
    WINDOW_END,
    WindowContext,
    make_window_context,
    metagraph_snapshot,
    sign_manifest,
)

import misscomputer_subnet.assignment_probe_cli as probe_cli
import misscomputer_subnet.organic_window_cli as window_cli
from misscomputer_subnet.assignment_probe import (
    ProbeTransportFailure,
    assignment_manifest_chain_state_bytes,
    assignment_manifest_signature_envelope_bytes,
    assignment_manifest_trust_policy_bytes,
    build_initial_manifest_chain_state,
)
from misscomputer_subnet.assignment_probe_cli import (
    EXIT_DEGRADED,
    EXIT_OK,
    EXIT_REJECTED,
    AssignmentProbeCLIError,
    InputFile,
    ManifestSource,
    SignatureSource,
)
from misscomputer_subnet.chain import BittensorChain, MetagraphSnapshot, NeuronRecord
from misscomputer_subnet.organic_manifest import (
    organic_assignment_manifest_bytes,
    verify_organic_assignment_manifest,
)
from misscomputer_subnet.organic_scoring import organic_epoch_score_bytes
from misscomputer_subnet.organic_window_cli import (
    OrganicWindowConfig,
    execute_organic_window,
    run_cli,
)
from misscomputer_subnet.validator_decision import parse_validator_weight_decision
from misscomputer_subnet.weight_plan import (
    WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
    build_weight_plan_from_decision,
)

WINDOW_END_INDEX = WINDOW_END // 300


def secure_write(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


def input_file(path: Path) -> InputFile:
    return InputFile(str(path), hashlib.sha256(path.read_bytes()).hexdigest())


class FakeReader:
    def __init__(self, snapshot: MetagraphSnapshot, block_hash: str) -> None:
        self.snapshot, self.block_hash = snapshot, block_hash
        self.opened = self.closed = False

    async def open(self) -> None:
        self.opened = True

    async def close(self) -> None:
        self.closed = True

    async def finalized_view(self) -> tuple[MetagraphSnapshot, str]:
        return self.snapshot, self.block_hash


class DownTransport:
    """Every fetch fails in transit: the terminal manifest is unavailable."""

    def fetch(self, **_: Any) -> ProbeTransportFailure:
        return ProbeTransportFailure("connection_failed", 5)


@dataclass
class Layout:
    context: WindowContext
    config: OrganicWindowConfig
    reader: FakeReader


def make_layout(tmp_path: Path, *, signers: dict[str, Any] | None = None) -> Layout:
    context = make_window_context()
    for name in ("epochs", "manifests", "inputs", "output"):
        (tmp_path / name).mkdir(mode=0o700)
    for epoch in context.epochs:
        secure_write(
            tmp_path / "epochs" / f"{epoch.epoch_index}.json", organic_epoch_score_bytes(epoch)
        )
    manifest_bytes = organic_assignment_manifest_bytes(context.manifest)
    secure_write(
        tmp_path / "manifests" / f"{context.manifest.manifest_digest_sha256}.json", manifest_bytes
    )
    policy = secure_write(
        tmp_path / "inputs" / "policy.json", assignment_manifest_trust_policy_bytes(context.policy)
    )
    terminal = secure_write(tmp_path / "inputs" / "terminal.json", manifest_bytes)
    signatures = [
        secure_write(
            tmp_path / "inputs" / f"{item.signer_key_id}.signature.json",
            assignment_manifest_signature_envelope_bytes(item),
        )
        for item in sign_manifest(context.manifest, signers or signer_keys())
    ]
    config = OrganicWindowConfig(
        trust_policy=input_file(policy),
        terminal_manifest=ManifestSource(file=input_file(terminal)),
        terminal_signatures=tuple(SignatureSource(file=input_file(path)) for path in signatures),
        probe_state_root=str(tmp_path / "state"),
        epoch_dir=str(tmp_path / "epochs"),
        manifest_archive_dir=str(tmp_path / "manifests"),
        window_end_epoch_index=WINDOW_END_INDEX,
        window_epochs=2,
        validator_hotkey=VALIDATOR_HOTKEY,
        decision_output=str(tmp_path / "output" / "decision.json"),
        weight_plan_output=str(tmp_path / "output" / "plan.json"),
        min_scored_epochs=2,
    )
    # The probe CLI already accepted the window's manifest.
    accepted = verify_organic_assignment_manifest(
        context.manifest,
        sign_manifest(context.manifest, signer_keys()),
        context.policy,
        build_initial_manifest_chain_state(context.policy),
        evaluation_epoch=context.manifest.issued_at_epoch,
        current_finalized_height=FINALIZED_HEIGHT,
    ).next_chain_state
    with probe_cli._StateRoot(config.probe_state_root) as root:
        root.replace_state(assignment_manifest_chain_state_bytes(accepted))
    return Layout(context, config, FakeReader(metagraph_snapshot(), REGISTERED_BLOCK_HASH))


def run(layout: Layout, *, now: float = WINDOW_END + 5, **overrides: Any) -> Any:
    return execute_organic_window(
        replace(layout.config, **overrides),
        reader_factory=lambda *_: layout.reader,
        clock=lambda: now,
    )


def assert_rejected(code: str, function: Any) -> None:
    with pytest.raises(AssignmentProbeCLIError) as error:
        function()
    assert error.value.code == code


def test_a_closed_window_seals_a_submit_decision_and_its_plan(tmp_path: Path) -> None:
    layout = make_layout(tmp_path)
    result = run(layout)
    decision = parse_validator_weight_decision(Path(layout.config.decision_output).read_bytes())
    assert decision == result.decision
    assert (decision.decision, decision.scored_epoch_count) == ("submit", 2)
    assert decision.terminal_evaluated_at_epoch == WINDOW_END + 5
    expected = build_weight_plan_from_decision(
        decision,
        snapshot=metagraph_snapshot(),
        finalized_block_hash=REGISTERED_BLOCK_HASH,
        version_key=WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
    )
    plan_path = Path(layout.config.weight_plan_output)
    assert plan_path.read_bytes() == expected.canonical_bytes()
    assert stat.S_IMODE(plan_path.stat().st_mode) == 0o600
    assert {entry.hotkey for entry in expected.weights} == {"MinerA", "MinerB", "MinerC"}
    assert layout.reader.opened and layout.reader.closed


def test_the_coordinator_never_waits_for_the_next_epochs_probe_lock(tmp_path: Path) -> None:
    """The next probe epoch starts at window close and holds the lock for five minutes."""

    layout = make_layout(tmp_path)
    state_path = Path(layout.config.probe_state_root) / "state.json"
    before = state_path.read_bytes()
    with probe_cli._StateRoot(layout.config.probe_state_root):
        assert run(layout).decision.decision == "submit"
    assert state_path.read_bytes() == before


def test_an_unreachable_terminal_manifest_seals_abstain_and_writes_no_plan(
    tmp_path: Path,
) -> None:
    layout = make_layout(tmp_path)
    result = execute_organic_window(
        replace(
            layout.config,
            terminal_manifest=ManifestSource(url="https://publication.mock.local/manifest.json"),
        ),
        reader_factory=lambda *_: layout.reader,
        transport_factory=lambda _context: DownTransport(),
        clock=lambda: WINDOW_END + 5,
    )
    assert result.decision.abstain_reasons == ["terminal_manifest_unavailable"]
    assert result.weight_plan is None
    assert Path(layout.config.decision_output).exists()
    assert not Path(layout.config.weight_plan_output).exists()


def test_an_unverifiable_terminal_manifest_seals_abstain_without_advancing_state(
    tmp_path: Path,
) -> None:
    keys = signer_keys()
    layout = make_layout(tmp_path, signers={"auditor": keys["security"], "issuer": keys["issuer"]})
    result = run(layout)
    assert result.decision.terminal_manifest_status == "rejected"
    assert result.decision.terminal_manifest_rejection_code == "signature_invalid"
    assert result.decision.decision == "abstain"
    assert not Path(layout.config.weight_plan_output).exists()


def test_too_few_scored_epochs_in_the_window_abstain(tmp_path: Path) -> None:
    layout = make_layout(tmp_path)
    result = run(layout, window_epochs=3, min_scored_epochs=3)
    assert result.decision.abstain_reasons == ["insufficient_scored_epochs"]
    assert not Path(layout.config.weight_plan_output).exists()


def _tampered_epoch(layout: Layout, tmp_path: Path) -> None:
    epoch = layout.context.epochs[0]
    document = organic_epoch_score_bytes(epoch).replace(VALIDATOR_HOTKEY.encode(), b"SomeoneElse")
    secure_write(tmp_path / "epochs" / "tampered.json", document)


@pytest.mark.parametrize(
    ("code", "prepare", "overrides"),
    [
        ("window_not_closed", None, {"now": WINDOW_END - 1}),
        ("window_close_stale", None, {"now": WINDOW_END + 601}),
        (
            "epoch_record_duplicate",
            lambda layout, tmp: secure_write(
                tmp / "epochs" / "copy.json", organic_epoch_score_bytes(layout.context.epochs[0])
            ),
            {},
        ),
        ("epoch_record_invalid", _tampered_epoch, {}),
        (
            "manifest_archive_incomplete",
            lambda layout, tmp: next((tmp / "manifests").iterdir()).unlink(),
            {},
        ),
        (
            "output_exists",
            lambda layout, tmp: secure_write(Path(layout.config.decision_output), b"old"),
            {},
        ),
        ("validator_not_registered", None, {"validator_hotkey": "NotRegistered"}),
        (
            "state_missing",
            lambda layout, tmp: (tmp / "state" / "state.json").unlink(),
            {},
        ),
    ],
)
def test_untrustworthy_windows_are_refused_without_a_decision(
    tmp_path: Path, code: str, prepare: Any, overrides: dict[str, Any]
) -> None:
    layout = make_layout(tmp_path)
    if prepare is not None:
        prepare(layout, tmp_path)
    decision_existed = Path(layout.config.decision_output).exists()
    assert_rejected(code, lambda: run(layout, **overrides))
    assert Path(layout.config.decision_output).exists() == decision_existed
    assert not Path(layout.config.weight_plan_output).exists()


def test_run_cli_exit_codes_distinguish_submit_from_abstain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    layout = make_layout(tmp_path)
    monkeypatch.setattr(
        window_cli,
        "execute_organic_window",
        functools.partial(
            execute_organic_window,
            reader_factory=lambda *_: layout.reader,
            clock=lambda: WINDOW_END + 5,
        ),
    )
    config = layout.config
    argv = [
        "--trust-policy", config.trust_policy.path,
        "--trust-policy-sha256", config.trust_policy.sha256,
        "--manifest-file", str(config.terminal_manifest.file.path),  # type: ignore[union-attr]
        "--manifest-sha256", str(config.terminal_manifest.file.sha256),  # type: ignore[union-attr]
    ]  # fmt: skip
    for item in config.terminal_signatures:
        assert item.file is not None
        argv += ["--signature-file", item.file.path, "--signature-sha256", item.file.sha256]
    argv += [
        "--probe-state-root", config.probe_state_root,
        "--epoch-dir", config.epoch_dir,
        "--manifest-archive-dir", config.manifest_archive_dir,
        "--window-end-epoch-index", str(WINDOW_END_INDEX),
        "--window-epochs", "2",
        "--min-scored-epochs", "2",
        "--validator-hotkey", VALIDATOR_HOTKEY,
        "--decision-output", config.decision_output,
        "--weight-plan-output", config.weight_plan_output,
    ]  # fmt: skip
    assert run_cli(argv) == EXIT_OK
    assert capsys.readouterr().out.startswith("WINDOW decision=submit reasons=none")
    abstain = [*argv]
    abstain[abstain.index("--min-scored-epochs") + 1] = "3"
    abstain[abstain.index("--window-epochs") + 1] = "3"
    abstain[abstain.index(config.decision_output)] = str(tmp_path / "output" / "second.json")
    abstain[abstain.index(config.weight_plan_output)] = str(tmp_path / "output" / "plan2.json")
    assert run_cli(abstain) == EXIT_DEGRADED
    assert "decision=abstain reasons=insufficient_scored_epochs" in capsys.readouterr().out
    assert run_cli(abstain) == EXIT_REJECTED
    assert capsys.readouterr().err == "REJECTED output_exists\n"


def test_chain_adapter_reads_the_metagraph_at_the_finalized_head_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    head = "0x" + "AB" * 32

    class Raw:
        async def get_chain_finalised_head(self) -> str:
            return head

        async def get_block_number(self, block_hash: str) -> int:
            assert block_hash == head
            return 4_321

    class Neuron:
        uid, hotkey, validator_permit, tao_stake, axon, active = 7, "V", True, 1.0, None, True

    class Graph:
        block, tempo, neurons = 4_321, 100, [Neuron()]

    class Subnets:
        async def metagraph(self, *, netuid: int, block: int, commitments: bool) -> Graph:
            assert (netuid, block, commitments) == (24, 4_321, False)
            return Graph()

    class Client:
        _substrate = type("Substrate", (), {"raw": Raw()})()
        subnets = Subnets()

    async def run_read(_self: object, read: Any) -> Any:
        return await read(Client())

    monkeypatch.setattr(BittensorChain, "_run_read", run_read)
    snapshot, block_hash = asyncio.run(BittensorChain(network="finney", netuid=24).finalized_view())
    assert block_hash == "ab" * 32
    assert (snapshot.block, snapshot.finalized) == (4_321, True)
    assert snapshot.neurons == (
        NeuronRecord(
            uid=7, hotkey="V", validator_permit=True, tao_stake=1.0, axon=None, active=True
        ),
    )
