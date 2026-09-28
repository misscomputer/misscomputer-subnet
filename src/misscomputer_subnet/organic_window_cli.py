# SPDX-License-Identifier: AGPL-3.0-only
"""Organic scoring window coordinator: one closed window, one sealed decision.

``misscomputer-organic-window`` runs once per scoring window, after it closes
(contract §11, §17.2). It is the only production path from organic hidden
probes to a weight plan:

1. read the validator's own finalized chain view (metagraph at the finalized
   head plus that head's block hash) and derive the registered miner set the
   weight plan will cover;
2. collect the validator's sealed ``organic-epoch-score`` records inside the
   window from the probe CLI's epoch directory, and the manifests they probed
   from its verified-manifest archive;
3. fetch the terminal manifest at close and verify it live against a
   read-only copy of the probe CLI's accepted chain state: it must be that
   head again or its direct successor (a transport failure is
   ``unavailable``, an unverifiable publication ``rejected``; both seal an
   abstain decision). The coordinator never takes the probe lock, so the
   next epoch's probe run, which starts at the same instant, is never
   blocked, and it never advances chain state;
4. seal a ``validator-weight-decision`` v2 with ``decide_weight_submission``;
5. write the decision, and **only** for ``submit`` a ``WeightPlan`` built by
   ``build_weight_plan_from_decision`` for the separately gated one-shot
   executor.

Outputs are created exclusively as owner-only files and never overwritten.
It holds no wallet, signer, extrinsic, or submission capability, reads no Go
control-plane state, and never reads synthetic or volume data.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import stat
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final, NoReturn, Protocol, cast

from pydantic import ValidationError

from .assignment_probe import (
    AssignmentManifestChainState,
    AssignmentManifestTrustPolicy,
    AssignmentProbeError,
    parse_assignment_manifest_chain_state,
)
from .assignment_probe_cli import (
    EXIT_DEGRADED,
    EXIT_INTERNAL,
    EXIT_OK,
    EXIT_REJECTED,
    EXIT_USAGE,
    MAX_STATE_BYTES,
    STATE_FILE_MODE,
    STATE_NAME,
    STATE_ROOT_MODE,
    AssignmentProbeCLIError,
    ManifestSource,
    SignatureSource,
    TransportFactory,
    _default_transport_factory,
    _effective_uid,
    _load_publication,
    _load_trust_policy,
    _preflight_output,
    _unsigned_decimal,
    _write_output,
    build_probe_ssl_context,
)
from .chain import MetagraphSnapshot
from .organic_contracts import ActiveAssignmentManifestV2
from .organic_manifest import (
    parse_organic_assignment_manifest,
    verify_organic_assignment_manifest,
)
from .organic_probe import DEFAULT_EPOCH_SECONDS
from .organic_scoring import OrganicEpochScore, parse_organic_epoch_score
from .score_checkpoint_relay_cli import InputFile, _normalized_absolute_path
from .validator_decision import (
    RegisteredMiner,
    RegisteredMinerSet,
    TerminalManifestObservation,
    ValidatorWeightDecision,
    WeightDecisionPolicy,
    decide_weight_submission,
    validator_weight_decision_bytes,
)
from .weight_plan import (
    WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
    WeightPlan,
    build_weight_plan_from_decision,
    eligible_weight_targets,
    snapshot_identity_fingerprint,
)

#: A window is coordinated at most this long after it closes; later, the
#: terminal fetch no longer describes the close and the run is refused.
MAX_CLOSE_DELAY_SECONDS: Final = 600
MAX_WINDOW_EPOCHS: Final = 288
MAX_EPOCH_FILES: Final = 4_096
MAX_EPOCH_FILE_BYTES: Final = 32 * 1_024 * 1_024
MAX_MANIFEST_FILE_BYTES: Final = 16 * 1_024 * 1_024
_UNAVAILABLE_PREFIXES: Final = ("manifest_fetch_", "signature_fetch_")
_REJECTED_CODES: Final = frozenset(
    {"manifest_invalid", "signature_invalid", "signature_set_noncanonical"}
)


class FinalizedViewReader(Protocol):
    """The validator's own chain view: metagraph at the finalized head and its hash."""

    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def finalized_view(self) -> tuple[MetagraphSnapshot, str]: ...


ReaderFactory = Callable[[str, int, str | None], FinalizedViewReader]


@dataclass(frozen=True, slots=True)
class OrganicWindowConfig:
    trust_policy: InputFile
    terminal_manifest: ManifestSource
    terminal_signatures: tuple[SignatureSource, ...]
    #: The probe CLI's state root, read without its lock and never written.
    probe_state_root: str
    epoch_dir: str
    manifest_archive_dir: str
    #: The window is ``[end - epochs * 300, end)`` with ``end = window_end_epoch_index * 300``.
    window_end_epoch_index: int
    window_epochs: int
    validator_hotkey: str
    decision_output: str
    weight_plan_output: str
    min_scored_epochs: int = 6
    max_registered_height_gap: int = 600
    network: str = "finney"
    netuid: int = 24
    rpc_endpoint: str | None = None
    tls_ca_file: str | None = None


@dataclass(frozen=True, slots=True)
class OrganicWindowResult:
    decision: ValidatorWeightDecision
    weight_plan: WeightPlan | None


def _fail(code: str) -> NoReturn:
    raise AssignmentProbeCLIError(code)


def _default_reader_factory(network: str, netuid: int, rpc: str | None) -> FinalizedViewReader:
    from .chain import BittensorChain

    return BittensorChain(network=network, netuid=netuid, rpc_endpoint=rpc)


def _read_finalized_view(reader: FinalizedViewReader) -> tuple[MetagraphSnapshot, str]:
    async def run() -> tuple[MetagraphSnapshot, str]:
        await reader.open()
        try:
            return await reader.finalized_view()
        finally:
            await reader.close()

    try:
        return asyncio.run(run())
    except (RuntimeError, OSError, ValueError, TimeoutError) as exc:
        raise AssignmentProbeCLIError("finalized_view_unavailable") from exc


def registered_set_from_view(
    snapshot: MetagraphSnapshot, block_hash: str, *, validator_hotkey: str
) -> RegisteredMinerSet:
    """The exact set ``build_weight_plan_from_decision`` will require the rows to cover."""

    if snapshot.finalized is not True:
        _fail("finalized_view_not_finalized")
    validator = snapshot.by_hotkey(validator_hotkey)
    if validator is None or not validator.active:
        _fail("validator_not_registered")
    targets = sorted(eligible_weight_targets(snapshot, validator_hotkey=validator_hotkey))
    if not targets:
        _fail("no_registered_miners")
    try:
        return RegisteredMinerSet.model_validate(
            {
                "network": snapshot.network,
                "netuid": snapshot.netuid,
                "finalized": True,
                "finalized_height": snapshot.block,
                "finalized_block_hash": block_hash,
                "finalized_epoch": snapshot.epoch,
                "validator_uid": validator.uid,
                "validator_hotkey": validator_hotkey,
                "miners": [RegisteredMiner(uid=uid, hotkey=hotkey) for uid, hotkey in targets],
                "metagraph_identity_fingerprint_sha256": snapshot_identity_fingerprint(snapshot),
            }
        )
    except ValidationError as exc:
        raise AssignmentProbeCLIError("registered_set_invalid") from exc


def _open_private_directory(path: str, code: str) -> tuple[str, int]:
    normalized = _normalized_absolute_path(path, code=code)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(normalized, flags)
    except OSError as exc:
        raise AssignmentProbeCLIError(code) from exc
    metadata = os.fstat(descriptor)
    if metadata.st_uid != _effective_uid() or stat.S_IMODE(metadata.st_mode) & 0o022:
        os.close(descriptor)
        _fail(code)
    return normalized, descriptor


def _read_private_file(directory_fd: int, name: str, maximum: int, code: str) -> bytes:
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
    except OSError as exc:
        raise AssignmentProbeCLIError(code) from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != _effective_uid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size > maximum
        ):
            _fail(code)
        rendered = os.read(descriptor, maximum + 1)
        if len(rendered) > maximum or os.read(descriptor, 1):
            _fail(code)
        return rendered
    except OSError as exc:
        raise AssignmentProbeCLIError(code) from exc
    finally:
        os.close(descriptor)


def collect_window_epochs(
    epoch_dir: str,
    *,
    validator_hotkey: str,
    window_start_epoch: int,
    window_end_epoch: int,
) -> list[OrganicEpochScore]:
    """Every sealed epoch record of this validator inside the window.

    Every ``*.json`` entry must parse as this validator's record: a foreign,
    malformed, or duplicated epoch refuses the window rather than being
    silently skipped, so the evidence set cannot be curated by omission.
    """

    _, directory_fd = _open_private_directory(epoch_dir, "epoch_dir_unsafe")
    try:
        names = sorted(name for name in os.listdir(directory_fd) if name.endswith(".json"))
        if len(names) > MAX_EPOCH_FILES:
            _fail("epoch_dir_resource_limit")
        selected: dict[int, OrganicEpochScore] = {}
        for name in names:
            rendered = _read_private_file(
                directory_fd, name, MAX_EPOCH_FILE_BYTES, "epoch_record_unsafe"
            )
            try:
                epoch = parse_organic_epoch_score(rendered)
            except (ValueError, ValidationError, RecursionError) as exc:
                raise AssignmentProbeCLIError("epoch_record_invalid") from exc
            if epoch.validator_hotkey != validator_hotkey:
                _fail("epoch_record_foreign_validator")
            start = epoch.epoch_index * epoch.epoch_seconds
            if start < window_start_epoch or start + epoch.epoch_seconds > window_end_epoch:
                continue
            if epoch.epoch_index in selected:
                _fail("epoch_record_duplicate")
            selected[epoch.epoch_index] = epoch
        return [selected[index] for index in sorted(selected)]
    finally:
        os.close(directory_fd)


def collect_archived_manifests(
    archive_dir: str, digests: Sequence[str]
) -> list[ActiveAssignmentManifestV2]:
    _, directory_fd = _open_private_directory(archive_dir, "manifest_archive_unsafe")
    try:
        manifests = []
        for digest_value in sorted(set(digests)):
            try:
                rendered = _read_private_file(
                    directory_fd,
                    f"{digest_value}.json",
                    MAX_MANIFEST_FILE_BYTES,
                    "manifest_archive_incomplete",
                )
                manifest = parse_organic_assignment_manifest(rendered)
            except (ValueError, ValidationError, RecursionError) as exc:
                if isinstance(exc, AssignmentProbeCLIError):
                    raise
                raise AssignmentProbeCLIError("manifest_archive_invalid") from exc
            if manifest.manifest_digest_sha256 != digest_value:
                _fail("manifest_archive_invalid")
            manifests.append(manifest)
        return manifests
    finally:
        os.close(directory_fd)


def read_probe_state(
    probe_state_root: str, policy: AssignmentManifestTrustPolicy
) -> AssignmentManifestChainState:
    """Read the probe CLI's accepted chain state without its lock.

    The probe installs ``state.json`` by atomic rename, so an unlocked read
    sees one complete state. The same ownership, mode and size rules as the
    probe's own reader apply, and the state must be bound to the pinned policy.
    """

    _, directory_fd = _open_private_directory(probe_state_root, "state_root_unsafe")
    try:
        if stat.S_IMODE(os.fstat(directory_fd).st_mode) != STATE_ROOT_MODE:
            _fail("state_root_unsafe")
        try:
            descriptor = os.open(
                STATE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd
            )
        except FileNotFoundError as exc:
            raise AssignmentProbeCLIError("state_missing") from exc
        except OSError as exc:
            raise AssignmentProbeCLIError("state_file_unsafe") from exc
    finally:
        os.close(directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != _effective_uid()
            or stat.S_IMODE(metadata.st_mode) != STATE_FILE_MODE
            or not 0 < metadata.st_size <= MAX_STATE_BYTES
        ):
            _fail("state_file_unsafe")
        rendered = os.read(descriptor, MAX_STATE_BYTES + 1)
    except OSError as exc:
        raise AssignmentProbeCLIError("state_file_unsafe") from exc
    finally:
        os.close(descriptor)
    try:
        state = parse_assignment_manifest_chain_state(rendered)
    except (TypeError, ValueError, ValidationError, RecursionError) as exc:
        raise AssignmentProbeCLIError("state_file_invalid") from exc
    if (
        state.accepted_manifest_count == 0
        or state.trust_policy_digest_sha256 != policy.trust_policy_digest_sha256
        or state.central_authority_fingerprint_sha256 != policy.central_authority_fingerprint_sha256
    ):
        _fail("state_binding_mismatch")
    return state


def _terminal_observation(
    config: OrganicWindowConfig,
    policy: AssignmentManifestTrustPolicy,
    prior: AssignmentManifestChainState,
    transport_factory: TransportFactory,
    *,
    evaluated_at: int,
    current_finalized_height: int,
) -> TerminalManifestObservation:
    transport = transport_factory(build_probe_ssl_context(config.tls_ca_file))
    try:
        manifest, signatures = _load_publication(
            config.terminal_manifest, config.terminal_signatures, transport, policy
        )
    except AssignmentProbeCLIError as exc:
        if exc.code.startswith(_UNAVAILABLE_PREFIXES):
            return TerminalManifestObservation(
                status="unavailable", evaluated_at_epoch=evaluated_at
            )
        if exc.code in _REJECTED_CODES:
            return TerminalManifestObservation(
                status="rejected", evaluated_at_epoch=evaluated_at, rejection_code=exc.code
            )
        raise
    try:
        verification = verify_organic_assignment_manifest(
            manifest,
            signatures,
            policy,
            prior,
            evaluation_epoch=evaluated_at,
            current_finalized_height=current_finalized_height,
        )
    except AssignmentProbeError as exc:
        return TerminalManifestObservation(
            status="rejected", evaluated_at_epoch=evaluated_at, rejection_code=exc.code
        )
    except ValueError as exc:
        code = str(exc) if str(exc).replace("_", "").isalnum() else "manifest_invalid"
        return TerminalManifestObservation(
            status="rejected", evaluated_at_epoch=evaluated_at, rejection_code=code[:64]
        )
    return TerminalManifestObservation(
        status="verified", evaluated_at_epoch=evaluated_at, manifest=verification.manifest
    )


def execute_organic_window(
    config: OrganicWindowConfig,
    *,
    reader_factory: ReaderFactory = _default_reader_factory,
    transport_factory: TransportFactory = _default_transport_factory,
    clock: Callable[[], float] = time.time,
    read_view: Callable[[FinalizedViewReader], tuple[MetagraphSnapshot, str]] | None = None,
) -> OrganicWindowResult:
    """Coordinate one closed window; see the module docstring for the steps."""

    if (
        not 1 <= config.window_epochs <= MAX_WINDOW_EPOCHS
        or config.window_end_epoch_index <= config.window_epochs
        or not 1 <= config.min_scored_epochs <= config.window_epochs
    ):
        _fail("window_invalid")
    window_end = config.window_end_epoch_index * DEFAULT_EPOCH_SECONDS
    window_start = window_end - config.window_epochs * DEFAULT_EPOCH_SECONDS
    now = int(clock())
    if now < window_end:
        _fail("window_not_closed")
    if now - window_end > MAX_CLOSE_DELAY_SECONDS:
        _fail("window_close_stale")
    policy = _load_trust_policy(config.trust_policy)
    inputs = {
        _normalized_absolute_path(item.path, code="input_path_unsafe")
        for item in (
            config.trust_policy,
            *([config.terminal_manifest.file] if config.terminal_manifest.file else []),
            *(item.file for item in config.terminal_signatures if item.file is not None),
        )
    }
    outputs = {
        _normalized_absolute_path(config.decision_output, code="output_path_unsafe"),
        _normalized_absolute_path(config.weight_plan_output, code="output_path_unsafe"),
    }
    if len(outputs) != 2 or outputs & inputs:
        _fail("output_path_alias")
    guarded = _normalized_absolute_path(config.probe_state_root, code="state_root_path_unsafe")
    for path in (config.decision_output, config.weight_plan_output):
        _preflight_output(path, state_root=guarded)
    reader = reader_factory(config.network, config.netuid, config.rpc_endpoint)
    snapshot, block_hash = (read_view or _read_finalized_view)(reader)
    if snapshot.network != config.network or snapshot.netuid != config.netuid:
        _fail("finalized_view_network_mismatch")
    registered = registered_set_from_view(
        snapshot, block_hash, validator_hotkey=config.validator_hotkey
    )
    epochs = collect_window_epochs(
        config.epoch_dir,
        validator_hotkey=config.validator_hotkey,
        window_start_epoch=window_start,
        window_end_epoch=window_end,
    )
    manifests = collect_archived_manifests(
        config.manifest_archive_dir,
        [key for epoch in epochs for key in epoch.manifest_digests],
    )
    prior = read_probe_state(config.probe_state_root, policy)
    terminal = _terminal_observation(
        config,
        policy,
        prior,
        transport_factory,
        evaluated_at=now,
        current_finalized_height=snapshot.block,
    )
    decision = decide_weight_submission(
        epochs,
        manifests=manifests,
        terminal=terminal,
        registered=registered,
        trust_policies=[policy],
        window_start_epoch=window_start,
        window_end_epoch=window_end,
        decision_policy=WeightDecisionPolicy(
            min_scored_epochs=config.min_scored_epochs,
            max_registered_height_gap=config.max_registered_height_gap,
        ),
    )
    plan = None
    if decision.decision == "submit":
        plan = build_weight_plan_from_decision(
            decision,
            snapshot=snapshot,
            finalized_block_hash=block_hash,
            version_key=WEIGHT_PLAN_PROTOCOL_VERSION_KEY,
        )
    _write_output(
        config.decision_output, validator_weight_decision_bytes(decision), state_root=guarded
    )
    if plan is not None:
        _write_output(config.weight_plan_output, plan.canonical_bytes(), state_root=guarded)
    return OrganicWindowResult(decision=decision, weight_plan=plan)


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        raise AssignmentProbeCLIError("usage")


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="misscomputer-organic-window",
        description="Seal one closed organic scoring window and its submit-only weight plan.",
        allow_abbrev=False,
        add_help=False,
    )
    parser.add_argument("--trust-policy", required=True)
    parser.add_argument("--trust-policy-sha256", required=True)
    manifest = parser.add_mutually_exclusive_group(required=True)
    manifest.add_argument("--manifest-file")
    manifest.add_argument("--manifest-url")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--signature-file", action="append", default=[])
    parser.add_argument("--signature-sha256", action="append", default=[])
    parser.add_argument("--signature-url", action="append", default=[])
    parser.add_argument("--probe-state-root", required=True)
    parser.add_argument("--epoch-dir", required=True)
    parser.add_argument("--manifest-archive-dir", required=True)
    parser.add_argument("--window-end-epoch-index", required=True, type=_unsigned_decimal)
    parser.add_argument("--window-epochs", type=_unsigned_decimal, default=12)
    parser.add_argument("--min-scored-epochs", type=_unsigned_decimal, default=6)
    parser.add_argument("--max-registered-height-gap", type=_unsigned_decimal, default=600)
    parser.add_argument("--validator-hotkey", required=True)
    parser.add_argument("--decision-output", required=True)
    parser.add_argument("--weight-plan-output", required=True)
    parser.add_argument("--subtensor-network", default="finney")
    parser.add_argument("--netuid", type=_unsigned_decimal, default=24)
    parser.add_argument("--rpc-endpoint")
    parser.add_argument("--tls-ca-file")
    return parser


def _config_from_arguments(arguments: argparse.Namespace) -> OrganicWindowConfig:
    signature_files = cast(list[str], arguments.signature_file)
    signature_digests = cast(list[str], arguments.signature_sha256)
    if len(signature_files) != len(signature_digests):
        _fail("signature_count_invalid")
    manifest_file = cast(str | None, arguments.manifest_file)
    manifest_digest = cast(str | None, arguments.manifest_sha256)
    if (manifest_file is None) != (manifest_digest is None):
        _fail("usage")
    signatures = (
        *(
            SignatureSource(file=InputFile(path, digest))
            for path, digest in zip(signature_files, signature_digests, strict=True)
        ),
        *(SignatureSource(url=url) for url in cast(list[str], arguments.signature_url)),
    )
    if not signatures:
        _fail("usage")
    return OrganicWindowConfig(
        trust_policy=InputFile(
            cast(str, arguments.trust_policy), cast(str, arguments.trust_policy_sha256)
        ),
        terminal_manifest=(
            ManifestSource(file=InputFile(manifest_file, cast(str, manifest_digest)))
            if manifest_file is not None
            else ManifestSource(url=cast(str, arguments.manifest_url))
        ),
        terminal_signatures=signatures,
        probe_state_root=cast(str, arguments.probe_state_root),
        epoch_dir=cast(str, arguments.epoch_dir),
        manifest_archive_dir=cast(str, arguments.manifest_archive_dir),
        window_end_epoch_index=cast(int, arguments.window_end_epoch_index),
        window_epochs=cast(int, arguments.window_epochs),
        validator_hotkey=cast(str, arguments.validator_hotkey),
        decision_output=cast(str, arguments.decision_output),
        weight_plan_output=cast(str, arguments.weight_plan_output),
        min_scored_epochs=cast(int, arguments.min_scored_epochs),
        max_registered_height_gap=cast(int, arguments.max_registered_height_gap),
        network=cast(str, arguments.subtensor_network),
        netuid=cast(int, arguments.netuid),
        rpc_endpoint=cast(str | None, arguments.rpc_endpoint),
        tls_ca_file=cast(str | None, arguments.tls_ca_file),
    )


def run_cli(argv: Sequence[str]) -> int:
    """Run with stable statuses and without echoing arguments, paths, or content."""

    try:
        result = execute_organic_window(_config_from_arguments(_parser().parse_args(list(argv))))
        decision = result.decision
        reasons = ",".join(decision.abstain_reasons) or "none"
        sys.stdout.write(
            f"WINDOW decision={decision.decision} reasons={reasons} "
            f"scored_epochs={decision.scored_epoch_count} "
            f"plan={'written' if result.weight_plan is not None else 'none'} "
            f"decision_sha256={decision.decision_digest_sha256}\n"
        )
        return EXIT_OK if result.weight_plan is not None else EXIT_DEGRADED
    except AssignmentProbeCLIError as exc:
        sys.stderr.write(f"REJECTED {exc.code}\n")
        if exc.code == "usage":
            return EXIT_USAGE
        return EXIT_REJECTED
    except (AssignmentProbeError, ValidationError, TypeError, ValueError):
        sys.stderr.write("REJECTED input_contract_invalid\n")
        return EXIT_REJECTED
    except Exception:
        sys.stderr.write("ERROR internal_error\n")
        return EXIT_INTERNAL


def main() -> None:
    raise SystemExit(run_cli(sys.argv[1:]))


if __name__ == "__main__":
    main()
