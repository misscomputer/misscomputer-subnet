# SPDX-License-Identifier: AGPL-3.0-only
"""The packaged static-only validator probes a V3 head without organic V2."""

from __future__ import annotations

import functools
import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from assignment_probe_context import signer_keys
from organic_context import EPOCH_START
from static_cli_context import (
    FakeTime,
    alice_signer,
    build_v3_manifest,
    cli_config,
    config_argv,
    input_file,
    secure_write,
    sign_v3,
    write_static_publication,
)

import misscomputer_subnet.static_probe_cli as static_cli
from misscomputer_subnet.assignment_probe import (
    AssignmentManifestTrustPolicy,
    assignment_manifest_signature_envelope_bytes,
    assignment_manifest_trust_policy_bytes,
)
from misscomputer_subnet.assignment_probe_cli import EXIT_DEGRADED, EXIT_OK, EXIT_REJECTED
from misscomputer_subnet.contract_codec import digest, model_bytes, model_document
from misscomputer_subnet.organic_manifest import assignment_manifest_v3_bytes
from misscomputer_subnet.static_probe import StaticPublicTransportPolicy
from misscomputer_subnet.static_scoring import parse_static_epoch_score

_COMMON_OPTIONS = frozenset(
    {
        "--trust-policy",
        "--trust-policy-sha256",
        "--probe-seed-file",
        "--probe-seed-sha256",
        "--epoch-index",
        "--finalized-height",
        "--validator-hotkey",
        "--wallet-name",
        "--wallet-hotkey",
        "--wallet-path",
    }
)


def _static_only_argv(combined: list[str]) -> list[str]:
    return [
        value
        for option, value in zip(combined[::2], combined[1::2], strict=True)
        for value in (option, value)
        if option in _COMMON_OPTIONS
        or (option.startswith("--static-") and option != "--static-sites")
    ]


@pytest.mark.parametrize("valid_v3", [True, False])
def test_static_only_cli_uses_v3_without_an_organic_v2_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    valid_v3: bool,
) -> None:
    publication = write_static_publication(
        tmp_path / "publication", **({} if valid_v3 else {"v3_bytes": b"{}\n"})
    )
    combined = cli_config(publication, tmp_path / "run")
    static = combined.static_sites
    assert static is not None
    Path(publication.manifest_file.path).unlink()  # There is no organic V2 publication.
    fake = FakeTime(EPOCH_START)
    monkeypatch.setattr(
        static_cli,
        "execute_static_probe",
        functools.partial(
            static_cli.execute_static_probe,
            transport_factory=lambda _context: publication.world,
            signer_factory=alice_signer,
            clock=fake.clock,
            sleep=fake.sleep,
        ),
    )

    exit_code = static_cli.run_cli(_static_only_argv(config_argv(combined)))

    assert exit_code == (EXIT_OK if valid_v3 else EXIT_DEGRADED)
    assert not any(kind == "organic" for kind, _ in publication.world.calls)
    if valid_v3:
        epoch = parse_static_epoch_score(Path(static.epoch_output).read_bytes())
        assert epoch.epoch_status == "scored"
        assert len(epoch.observations) == 9
        assert {item.disposition for item in epoch.endpoints} == {"eligible"}
        assert capsys.readouterr().out.startswith("STATIC status=scored ")
    else:
        assert not Path(static.epoch_output).exists()
        assert not any(kind == "static" for kind, _ in publication.world.calls)
        assert capsys.readouterr().out.startswith("STATIC status=abstained ")


def test_static_only_cli_accepts_test581_v3_and_rejects_wrong_subnet_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publication = write_static_publication(tmp_path / "publication")
    mainnet_policy = publication.policy_file
    unsigned = model_document(publication.policy, exclude={"trust_policy_digest_sha256"})
    unsigned.update({"network": "test", "netuid": 581})
    policy = AssignmentManifestTrustPolicy.model_validate(
        {**unsigned, "trust_policy_digest_sha256": digest(unsigned)}
    )
    v3 = build_v3_manifest(policy, [model_document(item) for item in publication.v3.deployments])
    publication.policy_file = input_file(
        secure_write(
            tmp_path / "publication" / "test581-policy.json",
            assignment_manifest_trust_policy_bytes(policy),
        )
    )
    publication.v3_file = input_file(
        secure_write(tmp_path / "publication" / "test581-v3.json", assignment_manifest_v3_bytes(v3))
    )
    publication.v3_signature_files = tuple(
        input_file(
            secure_write(
                tmp_path / "publication" / f"test581-{item.signer_key_id}.json",
                assignment_manifest_signature_envelope_bytes(item),
            )
        )
        for item in sign_v3(v3, signer_keys())
    )
    fake = FakeTime(EPOCH_START)
    monkeypatch.setattr(
        static_cli,
        "execute_static_probe",
        functools.partial(
            static_cli.execute_static_probe,
            transport_factory=lambda _context: publication.world,
            signer_factory=alice_signer,
            clock=fake.clock,
            sleep=fake.sleep,
        ),
    )
    config = cli_config(publication, tmp_path / "test581")
    Path(publication.manifest_file.path).unlink()

    assert static_cli.run_cli(_static_only_argv(config_argv(config))) == EXIT_OK
    assert (
        parse_static_epoch_score(Path(config.static_sites.epoch_output).read_bytes()).netuid == 581
    )
    wrong = cli_config(publication, tmp_path / "wrong-policy")
    wrong = replace(wrong, trust_policy=mainnet_policy)
    assert static_cli.run_cli(_static_only_argv(config_argv(wrong))) == EXIT_DEGRADED
    assert not Path(wrong.static_sites.epoch_output).exists()


def test_public_framing_pin_refuses_mainnet_before_a_probe(tmp_path: Path) -> None:
    publication = write_static_publication(tmp_path / "publication")
    config = cli_config(publication, tmp_path / "run")
    unsigned = {
        "schema": "miss.computer/misscomputer-subnet/static-public-transport-policy",
        "schema_version": 1,
        "profile": "cloudflare-framing-v1",
        "network": "test",
        "netuid": 581,
        "route_host_suffix": "on.miss.computer",
        "manifest_trust_policy_digest_sha256": publication.policy.trust_policy_digest_sha256,
    }
    pinned = StaticPublicTransportPolicy.model_validate(
        {**unsigned, "policy_digest_sha256": digest(unsigned)}
    )
    raw = model_bytes(pinned, StaticPublicTransportPolicy)
    path = secure_write(tmp_path / "transport-policy.json", raw)
    argv = [
        *_static_only_argv(config_argv(config)),
        "--public-transport-policy",
        str(path),
        "--public-transport-policy-sha256",
        hashlib.sha256(raw).hexdigest(),
    ]
    assert static_cli.run_cli(argv) == EXIT_REJECTED
    assert not any(kind == "static" for kind, _ in publication.world.calls)
