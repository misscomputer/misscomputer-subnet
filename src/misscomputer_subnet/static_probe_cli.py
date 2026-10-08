# SPDX-License-Identifier: AGPL-3.0-only
"""One signed V3 static-site probe epoch without requiring an organic V2 head.

This is a purpose-limited validator entry point. It uses the same locked V3
chain state, index verification, hidden scheduler, journal, and scoring path as
``misscomputer-assignment-probe --static-sites on``. It cannot write weights.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import cast

from pydantic import ValidationError

from .assignment_probe import MAX_EPOCH, AssignmentProbeError
from .assignment_probe_cli import (
    _HOTKEY,
    _STATIC_SINGLE_OPTIONS,
    EXIT_BUSY,
    EXIT_DEGRADED,
    EXIT_INTERNAL,
    EXIT_OK,
    EXIT_REJECTED,
    EXIT_USAGE,
    AssignmentProbeCLIError,
    SignerFactory,
    TransportFactory,
    WalletSelector,
    _ArgumentParser,
    _default_signer_factory,
    _default_transport_factory,
    _fire_schedule,
    _load_file_bytes,
    _load_trust_policy,
    _static_config_from_arguments,
    _unsigned_decimal,
    _validated_edge_origin,
    build_probe_ssl_context,
)
from .organic_probe import DEFAULT_EPOCH_SECONDS, PROBE_SEED_BYTES, epoch_index_of
from .score_checkpoint_relay_cli import (
    CheckpointRelayCLIError,
    InputFile,
    _normalized_absolute_path,
)
from .static_probe import parse_static_public_transport_policy
from .static_runtime import (
    StaticEpochRun,
    StaticSitesConfig,
    abstain_static_epoch,
    finish_static_epoch,
    load_static_epoch,
    lock_static_epoch,
    preflight_static,
    static_probe_ceiling,
    static_probe_schedule,
    static_summary,
)


@dataclass(frozen=True, slots=True)
class StaticProbeCLIConfig:
    trust_policy: InputFile
    probe_seed: InputFile
    epoch_index: int
    current_finalized_height: int
    validator_hotkey: str
    wallet: WalletSelector
    static_sites: StaticSitesConfig
    edge_origin: str | None = None
    tls_ca_file: str | None = None
    public_transport_policy: InputFile | None = None


def execute_static_probe(
    config: StaticProbeCLIConfig,
    *,
    transport_factory: TransportFactory = _default_transport_factory,
    signer_factory: SignerFactory = _default_signer_factory,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> StaticEpochRun:
    """Verify one V3 head, probe its static index, and seal a separate epoch."""

    if (
        isinstance(config.epoch_index, bool)
        or not isinstance(config.epoch_index, int)
        or not 0 <= config.epoch_index <= MAX_EPOCH // DEFAULT_EPOCH_SECONDS
        or isinstance(config.current_finalized_height, bool)
        or not isinstance(config.current_finalized_height, int)
        or not 0 <= config.current_finalized_height <= MAX_EPOCH
        or not isinstance(config.validator_hotkey, str)
        or _HOTKEY.fullmatch(config.validator_hotkey) is None
    ):
        raise AssignmentProbeCLIError("operator_context_invalid")
    evaluation_epoch = int(clock())
    if epoch_index_of(evaluation_epoch) > config.epoch_index:
        raise AssignmentProbeCLIError("epoch_already_elapsed")
    edge_origin = (
        _validated_edge_origin(config.edge_origin) if config.edge_origin is not None else None
    )
    policy = _load_trust_policy(config.trust_policy)
    seed = _load_file_bytes(config.probe_seed, label="probe_seed", max_bytes=PROBE_SEED_BYTES)
    if len(seed) != PROBE_SEED_BYTES:
        raise AssignmentProbeCLIError("probe_seed_invalid")
    inputs = {
        _normalized_absolute_path(item.path, code="input_path_unsafe")
        for item in (config.trust_policy, config.probe_seed)
    }
    public_transport_policy = None
    if config.public_transport_policy is not None:
        inputs.add(
            _normalized_absolute_path(config.public_transport_policy.path, code="input_path_unsafe")
        )
        try:
            public_transport_policy = parse_static_public_transport_policy(
                _load_file_bytes(
                    config.public_transport_policy,
                    label="static_public_transport_policy",
                    max_bytes=4_096,
                )
            )
        except (TypeError, ValueError, ValidationError, RecursionError) as exc:
            raise AssignmentProbeCLIError("static_public_transport_policy_invalid") from exc
        if (
            (policy.network, policy.netuid) != ("test", 581)
            or public_transport_policy.manifest_trust_policy_digest_sha256
            != policy.trust_policy_digest_sha256
        ):
            raise AssignmentProbeCLIError("static_public_transport_policy_mismatch")
    release_policy, server_digest, index_origin = preflight_static(
        config.static_sites, organic_inputs=inputs
    )
    sign, signer_hotkey = signer_factory(config.wallet)
    if signer_hotkey != config.validator_hotkey:
        raise AssignmentProbeCLIError("wallet_hotkey_mismatch")
    transport = transport_factory(build_probe_ssl_context(config.tls_ca_file))
    run = lock_static_epoch(config.static_sites, policy)
    run.public_transport_policy = public_transport_policy
    try:
        try:
            load_static_epoch(
                run,
                transport=transport,
                policy=policy,
                release_policy=release_policy,
                server_digest=server_digest,
                index_origin=index_origin,
                epoch_index=config.epoch_index,
                evaluation_epoch=evaluation_epoch,
                current_finalized_height=config.current_finalized_height,
            )
            schedule = static_probe_schedule(
                run,
                transport,
                policy,
                seed=seed,
                validator_hotkey=config.validator_hotkey,
                sign=sign,
                epoch_index=config.epoch_index,
                edge_origin=edge_origin,
            )
            run.skipped = _fire_schedule(
                schedule, epoch_index=config.epoch_index, clock=clock, sleep=sleep
            )
            finish_static_epoch(
                run,
                validator_hotkey=config.validator_hotkey,
                epoch_index=config.epoch_index,
                probe_ceiling=static_probe_ceiling(policy),
            )
        except Exception as exc:
            abstain_static_epoch(run, exc)
    finally:
        run.close()
    return run


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="misscomputer-static-probe",
        description="One hidden validator epoch against signed static-site V3 assignments.",
        allow_abbrev=False,
        add_help=False,
    )
    parser.add_argument("--trust-policy", required=True)
    parser.add_argument("--trust-policy-sha256", required=True)
    parser.add_argument("--probe-seed-file", required=True)
    parser.add_argument("--probe-seed-sha256", required=True)
    parser.add_argument("--epoch-index", required=True, type=_unsigned_decimal)
    parser.add_argument("--finalized-height", required=True, type=_unsigned_decimal)
    parser.add_argument("--validator-hotkey", required=True)
    parser.add_argument("--wallet-name", required=True)
    parser.add_argument("--wallet-hotkey", required=True)
    parser.add_argument("--wallet-path", default="~/.bittensor/wallets")
    parser.add_argument("--edge-origin")
    parser.add_argument("--tls-ca-file")
    parser.add_argument("--public-transport-policy")
    parser.add_argument("--public-transport-policy-sha256")
    for name in _STATIC_SINGLE_OPTIONS:
        parser.add_argument(f"--{name}")
    parser.add_argument("--static-signature-file", action="append", default=[])
    parser.add_argument("--static-signature-sha256", action="append", default=[])
    parser.add_argument("--static-signature-url", action="append", default=[])
    return parser


def _config_from_arguments(arguments: argparse.Namespace) -> StaticProbeCLIConfig:
    arguments.static_sites = "on"
    static = _static_config_from_arguments(arguments)
    if static is None:
        raise AssignmentProbeCLIError("usage")
    if (arguments.public_transport_policy is None) != (
        arguments.public_transport_policy_sha256 is None
    ):
        raise AssignmentProbeCLIError("usage")
    return StaticProbeCLIConfig(
        trust_policy=InputFile(arguments.trust_policy, arguments.trust_policy_sha256),
        probe_seed=InputFile(arguments.probe_seed_file, arguments.probe_seed_sha256),
        epoch_index=cast(int, arguments.epoch_index),
        current_finalized_height=cast(int, arguments.finalized_height),
        validator_hotkey=cast(str, arguments.validator_hotkey),
        wallet=WalletSelector(
            name=cast(str, arguments.wallet_name),
            hotkey=cast(str, arguments.wallet_hotkey),
            path=cast(str, arguments.wallet_path),
        ),
        static_sites=static,
        edge_origin=cast(str | None, arguments.edge_origin),
        tls_ca_file=cast(str | None, arguments.tls_ca_file),
        public_transport_policy=(
            InputFile(arguments.public_transport_policy, arguments.public_transport_policy_sha256)
            if arguments.public_transport_policy is not None
            else None
        ),
    )


def run_cli(argv: Sequence[str]) -> int:
    """Run without logging input values, wallet material, or probe contents."""

    try:
        run = execute_static_probe(_config_from_arguments(_parser().parse_args(list(argv))))
        sys.stdout.write(static_summary(run))
        return (
            EXIT_OK
            if run.epoch is not None and run.epoch.epoch_status == "scored"
            else EXIT_DEGRADED
        )
    except AssignmentProbeError as exc:
        sys.stderr.write(f"REJECTED {exc.code}\n")
        return EXIT_REJECTED
    except AssignmentProbeCLIError as exc:
        sys.stderr.write(f"REJECTED {exc.code}\n")
        if exc.code == "usage":
            return EXIT_USAGE
        if exc.code == "probe_busy":
            return EXIT_BUSY
        return EXIT_REJECTED
    except CheckpointRelayCLIError as exc:
        sys.stderr.write(f"REJECTED {exc.code}\n")
        return EXIT_REJECTED
    except (ValidationError, TypeError, ValueError):
        sys.stderr.write("REJECTED input_contract_invalid\n")
        return EXIT_REJECTED
    except Exception:
        sys.stderr.write("ERROR internal_error\n")
        return EXIT_INTERNAL


def main() -> None:
    raise SystemExit(run_cli(sys.argv[1:]))


if __name__ == "__main__":
    main()
