# SPDX-License-Identifier: AGPL-3.0-only
"""Static release revocation (§7.3): cross-language vectors and the validator boundary."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Final

import pytest
from jsonschema import Draft202012Validator
from organic_context import EPOCH_START
from static_cli_context import (
    REVOCATION_ISSUED_EPOCH,
    FakeTime,
    StaticPublication,
    alice_signer,
    cli_config,
    config_argv,
    execute,
    retarget_test581,
    secure_write,
    write_static_publication,
)
from static_context import (
    RELEASE_KEY,
    RELEASE_KEY_ID,
    raw_public,
    revocation_policy_bytes,
    revocation_snapshot_bytes,
)
from static_context import trust_policy as static_trust_policy
from static_scoring_context import verified_site

import misscomputer_subnet.static_probe_cli as static_cli
from misscomputer_subnet.assignment_probe_cli import (
    EXIT_REJECTED,
    EXIT_USAGE,
    AssignmentProbeCLIError,
    AssignmentProbeCLIResult,
    run_cli,
)
from misscomputer_subnet.contract_codec import digest, model_document
from misscomputer_subnet.static_index import (
    StaticIndexAbstention,
    StaticReleaseKey,
    build_static_site_release_trust_policy,
)
from misscomputer_subnet.static_probe_cli import StaticProbeCLIConfig
from misscomputer_subnet.static_revocation import (
    StaticRevocationError,
    advance_static_site_release_revocation,
    parse_static_site_release_revocation_trust_policy,
    revocation_freshness,
    static_index_revoked,
    verify_static_site_release_revocation,
)
from misscomputer_subnet.static_runtime import REVOCATION_HIGH_WATER_NAME, StaticEpochRun
from misscomputer_subnet.static_scoring import (
    StaticScoringError,
    aggregate_static_window,
    parse_static_epoch_score,
    replay_static_epoch_score,
    score_static_epoch,
    static_epoch_score_bytes,
)

ROOT = Path(__file__).resolve().parents[2]
#: Produced by the Go reference verifier; Python must reach the same outcome on every case.
VECTORS: dict[str, Any] = json.loads(
    (ROOT / "contracts/fixtures/static-release-revocation-vectors.v1.json").read_bytes()
)
RELEASE_POLICY = build_static_site_release_trust_policy(
    policy_id="go-vector-release",
    trusted_keys=[
        StaticReleaseKey(
            key_id=f"release-{index}",
            algorithm="ed25519",
            public_key_hex=public,
            valid_from_epoch=0,
            valid_until_epoch=1 << 40,
        )
        for index, public in enumerate(VECTORS["release_trust_public_keys"])
    ],
)
POLICY = parse_static_site_release_revocation_trust_policy(
    VECTORS["policy"]["stored"].encode(),
    pinned_digest_sha256=VECTORS["policy"]["digest_sha256"],
    release_policy=RELEASE_POLICY,
)


def _code(call: Any) -> str:
    try:
        call()
    except StaticRevocationError as exc:
        return exc.code
    return ""


def test_worked_example_matches_the_go_signature_and_digest() -> None:
    example = VECTORS["example"]

    verified = verify_static_site_release_revocation(example["stored"].encode(), POLICY)

    assert (
        verified.snapshot_digest
        == example["snapshot_digest"]
        == ("sha256:3e6e81bf52c93d8c4637472356a8926552e7bf3117ab1bbe976957b746e28ea9")
    )
    assert verified.snapshot.signature == example["signature"]


@pytest.mark.parametrize("case", VECTORS["policy_cases"], ids=lambda case: case["name"])
def test_policy_outcome_matches_go(case: dict[str, str]) -> None:
    assert (
        _code(
            lambda: parse_static_site_release_revocation_trust_policy(
                case["stored"].encode(),
                pinned_digest_sha256=case["pin"],
                release_policy=RELEASE_POLICY,
            )
        )
        == case["code"]
    )


@pytest.mark.parametrize("case", VECTORS["verify_cases"], ids=lambda case: case["name"])
def test_verify_outcome_matches_go(case: dict[str, str]) -> None:
    assert (
        _code(lambda: verify_static_site_release_revocation(case["stored"].encode(), POLICY))
        == case["code"]
    )


@pytest.mark.parametrize("case", VECTORS["advance_cases"], ids=lambda case: case["name"])
def test_advance_outcome_matches_go(case: dict[str, Any]) -> None:
    held = verify_static_site_release_revocation(VECTORS["advance_held"].encode(), POLICY)
    offered = verify_static_site_release_revocation(case["offered"].encode(), POLICY)
    advances: list[bool] = []

    code = _code(lambda: advances.append(advance_static_site_release_revocation(held, offered)))

    assert (code, advances[0] if advances else False) == (case["code"], case["advances"])


@pytest.mark.parametrize("case", VECTORS["index_cases"], ids=lambda case: case["name"])
def test_index_outcome_matches_go(case: dict[str, Any]) -> None:
    held = verify_static_site_release_revocation(VECTORS["index_snapshot"].encode(), POLICY)

    revoked = held.release_revoked(case["release_digest"]) or held.signer_revoked(
        case["key_id"], case["public_key_hex"]
    )

    assert revoked is case["revoked"]


@pytest.mark.parametrize("case", VECTORS["takedown_index_cases"], ids=lambda case: case["name"])
def test_takedown_index_outcome_matches_go(case: dict[str, Any]) -> None:
    held = verify_static_site_release_revocation(
        VECTORS["takedown_index_snapshot"].encode(), POLICY
    )

    assert (
        held.release_revoked(case["release_digest"]),
        held.site_revoked(case["site_digest"]),
        held.signer_revoked(case["key_id"], case["public_key_hex"]),
    ) == (case["release_revoked"], case["site_revoked"], case["signer_revoked"])


@pytest.mark.parametrize(
    "reason",
    [
        "credential_harvesting",
        "illegal_content",
        "key_compromise",
        "malware",
        "phishing",
        "platform_integrity",
    ],
)
def test_only_a_takedown_reason_denies_the_site(reason: str) -> None:
    release, site = "sha256:" + "a1" * 32, "sha256:" + "5a" * 32
    stored = revocation_snapshot_bytes(
        1, REVOCATION_ISSUED_EPOCH, releases=((release, site, reason),)
    )
    policy = parse_static_site_release_revocation_trust_policy(
        revocation_policy_bytes(),
        pinned_digest_sha256=json.loads(revocation_policy_bytes())["digest_sha256"],
        release_policy=RELEASE_POLICY,
    )

    held = verify_static_site_release_revocation(stored, policy)

    assert held.release_revoked(release)
    assert held.site_revoked(site) is (reason != "key_compromise")


def test_authenticated_index_of_a_taken_down_site_is_revoked() -> None:
    """The post-authentication path judges the verified release's own site_digest."""

    index, _ = verified_site()
    release_policy = static_trust_policy()
    policy = parse_static_site_release_revocation_trust_policy(
        revocation_policy_bytes(),
        pinned_digest_sha256=json.loads(revocation_policy_bytes())["digest_sha256"],
        release_policy=release_policy,
    )
    other_release = "sha256:" + "d4" * 32

    def held(reason: str) -> Any:
        return verify_static_site_release_revocation(
            revocation_snapshot_bytes(
                1,
                REVOCATION_ISSUED_EPOCH,
                releases=((other_release, index.release.site_digest, reason),),
            ),
            policy,
        )

    assert static_index_revoked(held("malware"), index, release_policy)
    assert not static_index_revoked(held("key_compromise"), index, release_policy)  # control


@pytest.mark.parametrize(
    ("offset", "code"),
    [
        (86_400, None),
        (86_401, "revocation_stale"),
        (-300, None),
        (-301, "revocation_issued_in_future"),
    ],
)
def test_freshness_boundaries(offset: int, code: str | None) -> None:
    held = verify_static_site_release_revocation(VECTORS["example"]["stored"].encode(), POLICY)
    issued = 1_790_812_800  # 2026-10-01T00:00:00Z

    assert revocation_freshness(held, now_epoch=issued + offset, max_age_seconds=86_400) == code


# --------------------------------------------------------------------------
# Validator boundary: misscomputer-assignment-probe --static-sites on
# --------------------------------------------------------------------------


def _static_deployment(publication: StaticPublication) -> Any:
    return next(
        item for item in publication.v3.deployments if item.workload_kind == "static-site-v1"
    )


def _run(
    publication: StaticPublication,
    run: Path,
    snapshot: bytes | None,
    *,
    state_root: str | None = None,
    **static_changes: Any,
) -> AssignmentProbeCLIResult:
    config = cli_config(publication, run)
    assert config.static_sites is not None
    offered = None
    if snapshot is not None:
        offered = str(secure_write(run / "offered-snapshot.json", snapshot))
    static = replace(config.static_sites, revocation_snapshot=offered, **static_changes)
    if state_root is not None:
        static = replace(static, state_root=state_root, trusted_state_anchor="current")
    return execute(replace(config, static_sites=static), publication.world)


def _static_calls(publication: StaticPublication) -> list[str]:
    return [target for kind, target in publication.world.calls if kind == "static"]


def _index_calls(publication: StaticPublication) -> list[str]:
    return [target for kind, target in publication.world.calls if kind == "index"]


OTHER_KEY = "ab" * 32


def _published_record(path: str) -> dict[str, Any]:
    """The written record must validate under the committed schema of its own version."""

    record: dict[str, Any] = json.loads(Path(path).read_bytes())
    schema_path = ROOT / (
        f"contracts/schemas/static-epoch-score.v{record['schema_version']}.schema.json"
    )
    Draft202012Validator(json.loads(schema_path.read_bytes())).validate(record)
    return record


@pytest.mark.parametrize(
    ("entries", "revoked", "index_fetched"),
    [
        pytest.param("release", True, False, id="release digest"),
        pytest.param("signer-key", True, True, id="signer public key under another id"),
        pytest.param("signer-id", True, True, id="signer id with another public key"),
        pytest.param("unrelated", False, True, id="control: unrelated entries"),
    ],
)
def test_revoked_release_abstains_without_a_probe_or_a_zero(
    tmp_path: Path, entries: str, revoked: bool, index_fetched: bool
) -> None:
    publication = write_static_publication(tmp_path / "publication")
    static = _static_deployment(publication)
    release_key = raw_public(RELEASE_KEY).hex()
    releases, signer_keys = {
        "release": (((static.release_digest, static.site_digest, "phishing"),), ()),
        "signer-key": ((), (("static-release-2026a", release_key, "key_compromise"),)),
        "signer-id": ((), ((RELEASE_KEY_ID, OTHER_KEY, "key_retired"),)),
        "unrelated": (
            (("sha256:" + "a1" * 32, "sha256:" + "5a" * 32, "malware"),),
            (("static-release-2026a", OTHER_KEY, "key_compromise"),),
        ),
    }[entries]
    snapshot = revocation_snapshot_bytes(
        1, REVOCATION_ISSUED_EPOCH, releases=releases, signer_keys=signer_keys
    )

    result = _run(publication, tmp_path / "run", snapshot)

    assert result.epoch.epoch_status == "scored"  # the organic path is untouched
    assert result.static is not None and result.static.epoch is not None
    epoch = result.static.epoch
    # finney epochs run under the revocation authority: v3, bound to what they relied on.
    record = _published_record(result.static.config.epoch_output)
    assert result.static.revocation is not None and result.static.revocation.held is not None
    assert (
        record["schema_version"],
        record["release_revocation_policy_digest_sha256"],
        record["release_revocation_snapshot_digest"],
    ) == (
        3,
        result.static.revocation.policy.digest_sha256,
        result.static.revocation.held.snapshot_digest,
    )
    assert bool(_index_calls(publication)) is index_fetched
    if not revoked:
        assert epoch.index_abstentions == [] and epoch.epoch_status == "scored"
        assert {item.disposition for item in epoch.endpoints} == {"eligible"}
        assert _static_calls(publication)
        return
    assert [(row.code, row.record_code) for row in epoch.index_abstentions] == [
        ("release_revoked", "static_release_revoked")
    ]
    assert {item.disposition for item in epoch.endpoints} == {"abstain_index"}
    assert {item.availability_numerator for item in epoch.endpoints} == {None}
    assert "static_release_revoked" in {item.code for item in epoch.alerts}
    assert _static_calls(publication) == []
    assert aggregate_static_window([epoch]).miners == []
    assert replay_static_epoch_score(epoch, []) == epoch


@pytest.mark.parametrize(
    ("reason", "same_release", "revoked"),
    [
        pytest.param("phishing", False, True, id="separately signed live release, takedown"),
        pytest.param(
            "platform_integrity", False, True, id="separately signed live release, platform"
        ),
        pytest.param(
            "key_compromise", False, False, id="control: key_compromise rotation keeps the site"
        ),
        pytest.param("key_compromise", True, True, id="key_compromise of the live release"),
    ],
)
def test_taken_down_site_abstains_every_release_but_key_compromise_rotates(
    tmp_path: Path, reason: str, same_release: bool, revoked: bool
) -> None:
    """The edge withdraws every release of a taken-down site; so must the validator."""

    publication = write_static_publication(tmp_path / "publication")
    static = _static_deployment(publication)
    # Another, separately signed release of the very site that is live.
    release = static.release_digest if same_release else "sha256:" + "d4" * 32
    snapshot = revocation_snapshot_bytes(
        1, REVOCATION_ISSUED_EPOCH, releases=((release, static.site_digest, reason),)
    )

    result = _run(publication, tmp_path / "run", snapshot)

    assert result.static is not None and result.static.epoch is not None
    epoch = result.static.epoch
    assert _published_record(result.static.config.epoch_output)["schema_version"] == 3
    if not revoked:
        assert epoch.index_abstentions == [] and epoch.epoch_status == "scored"
        assert _static_calls(publication)
        return
    assert [(row.code, row.record_code) for row in epoch.index_abstentions] == [
        ("release_revoked", "static_release_revoked")
    ]
    assert _index_calls(publication) == [] and _static_calls(publication) == []
    assert {item.availability_numerator for item in epoch.endpoints} == {None}
    assert aggregate_static_window([epoch]).miners == []


@pytest.mark.parametrize(
    ("snapshot", "code"),
    [
        pytest.param(
            lambda: revocation_snapshot_bytes(1, EPOCH_START - 86_400), None, id="control: max age"
        ),
        pytest.param(
            lambda: revocation_snapshot_bytes(1, EPOCH_START - 86_401),
            "static_revocation_stale",
            id="older than max age",
        ),
        pytest.param(
            lambda: revocation_snapshot_bytes(1, EPOCH_START + 300), None, id="control: skew"
        ),
        pytest.param(
            lambda: revocation_snapshot_bytes(1, EPOCH_START + 301),
            "static_revocation_issued_in_future",
            id="beyond skew",
        ),
        pytest.param(lambda: None, "static_revocation_unavailable", id="never delivered"),
        pytest.param(
            lambda: revocation_snapshot_bytes(1, REVOCATION_ISSUED_EPOCH, private=RELEASE_KEY),
            "static_revocation_signature_invalid",
            id="signed by the release key",
        ),
    ],
)
def test_unfresh_or_unverified_revocation_abstains_the_whole_static_epoch(
    tmp_path: Path, snapshot: Any, code: str | None
) -> None:
    publication = write_static_publication(tmp_path / "publication")

    result = _run(publication, tmp_path / "run", snapshot())

    assert result.epoch.epoch_status == "scored"
    static = result.static
    assert static is not None
    state_root = Path(static.config.state_root)
    if code is None:
        assert static.epoch is not None and static.epoch.epoch_status == "scored"
        return
    assert (static.abstained_code, static.epoch) == (code, None)
    assert not Path(static.config.epoch_output).exists()
    assert _index_calls(publication) == [] and _static_calls(publication) == []
    # The v3 chain still advances. A verified, stale snapshot still raises the
    # high water (it can only add revocations); nothing else becomes it.
    assert (state_root / "state.json").exists()
    high_water = state_root / REVOCATION_HIGH_WATER_NAME
    if code == "static_revocation_stale":
        assert high_water.read_bytes() == snapshot()
    else:
        assert not high_water.exists()


def test_high_water_is_durable_monotonic_and_cumulative_across_runs(tmp_path: Path) -> None:
    publication = write_static_publication(tmp_path / "publication")
    static = _static_deployment(publication)
    revoked = ((static.release_digest, static.site_digest, "phishing"),)
    held = revocation_snapshot_bytes(2, REVOCATION_ISSUED_EPOCH, releases=revoked)

    first = _run(publication, tmp_path / "first", held)

    assert first.static is not None and first.static.epoch is not None
    state_root = first.static.config.state_root
    high_water = Path(state_root) / REVOCATION_HIGH_WATER_NAME
    assert high_water.read_bytes() == held
    for name, offered, code in [
        ("rollback", revocation_snapshot_bytes(1, REVOCATION_ISSUED_EPOCH), "rollback"),
        (
            "equivocation",
            revocation_snapshot_bytes(2, REVOCATION_ISSUED_EPOCH + 1, releases=revoked),
            "equivocation",
        ),
        ("dropped", revocation_snapshot_bytes(3, REVOCATION_ISSUED_EPOCH + 1), "not_cumulative"),
    ]:
        result = _run(publication, tmp_path / name, offered, state_root=state_root)
        assert result.static is not None
        assert result.static.abstained_code == f"static_revocation_{code}", name
        assert high_water.read_bytes() == held, name
    publication.world.calls.clear()

    # Nothing offered: the durable high water alone still revokes the release.
    later = _run(publication, tmp_path / "later", None, state_root=state_root)

    assert later.static is not None and later.static.epoch is not None
    assert [row.code for row in later.static.epoch.index_abstentions] == ["release_revoked"]
    assert _static_calls(publication) == []
    newer = revocation_snapshot_bytes(3, REVOCATION_ISSUED_EPOCH + 1, releases=revoked)
    advanced = _run(publication, tmp_path / "advanced", newer, state_root=state_root)
    assert advanced.static is not None and advanced.static.epoch is not None
    assert high_water.read_bytes() == newer


def _rotated_policy(run: Path) -> dict[str, Any]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    rendered = revocation_policy_bytes(Ed25519PrivateKey.from_private_bytes(b"\x0a" * 32))
    return {
        "revocation_policy": str(secure_write(run / "rotated-policy.json", rendered)),
        "revocation_policy_digest": json.loads(rendered)["digest_sha256"],
    }


def _shared_key_policy(run: Path) -> dict[str, Any]:
    rendered = revocation_policy_bytes(RELEASE_KEY)
    return {
        "revocation_policy": str(secure_write(run / "shared-policy.json", rendered)),
        "revocation_policy_digest": json.loads(rendered)["digest_sha256"],
    }


def _tamper(high_water: Path) -> None:
    rendered = bytearray(high_water.read_bytes())
    index = rendered.index(b'"signature":"') + len(b'"signature":"')
    rendered[index] = ord("0") if rendered[index] != ord("0") else ord("1")
    high_water.write_bytes(bytes(rendered))


@pytest.mark.parametrize(
    ("prior", "changes", "code"),
    [
        pytest.param(
            False,
            lambda _run: {"revocation_policy": None, "revocation_policy_digest": None},
            "static_revocation_policy_required",
            id="finney without a policy",
        ),
        pytest.param(
            "tamper", lambda _run: {}, "static_revocation_high_water_invalid", id="tamper"
        ),
        pytest.param(
            True, _rotated_policy, "static_revocation_high_water_invalid", id="unverifiable"
        ),
        pytest.param(
            False,
            lambda _run: {"revocation_policy_digest": "0" * 64},
            "static_revocation_policy_digest_mismatch",
            id="another pin",
        ),
        pytest.param(
            False,
            _shared_key_policy,
            "static_revocation_policy_key_not_dedicated",
            id="a release key",
        ),
    ],
)
def test_revocation_configuration_refuses_before_any_state_or_probe(
    tmp_path: Path, prior: bool | str, changes: Any, code: str
) -> None:
    publication = write_static_publication(tmp_path / "publication")
    state_root = None
    if prior:
        first = _run(publication, tmp_path / "first", revocation_snapshot_bytes(1, EPOCH_START))
        assert first.static is not None and first.static.epoch is not None
        state_root = first.static.config.state_root
        if prior == "tamper":
            _tamper(Path(state_root) / REVOCATION_HIGH_WATER_NAME)
    state_before = (
        (Path(state_root) / "state.json").read_bytes() if state_root is not None else None
    )
    publication.world.calls.clear()
    run = tmp_path / "run"
    run.mkdir(mode=0o700)

    with pytest.raises(AssignmentProbeCLIError) as error:
        _run(publication, run, None, state_root=state_root, **changes(run))

    assert error.value.code == code
    assert publication.world.calls == []
    assert not (run / "state" / "state.json").exists()
    if state_root is not None:
        assert (Path(state_root) / "state.json").read_bytes() == state_before


def _static_only(
    publication: StaticPublication, run: Path, *, state_root: str | None = None, **changes: Any
) -> StaticEpochRun:
    config = cli_config(publication, run)
    assert config.static_sites is not None
    static = replace(config.static_sites, **changes)
    if state_root is not None:
        static = replace(static, state_root=state_root, trusted_state_anchor="current")
    fake = FakeTime(EPOCH_START)
    return static_cli.execute_static_probe(
        StaticProbeCLIConfig(
            trust_policy=config.trust_policy,
            probe_seed=config.probe_seed,
            epoch_index=config.epoch_index,
            current_finalized_height=config.current_finalized_height,
            validator_hotkey=config.validator_hotkey,
            wallet=config.wallet,
            static_sites=static,
        ),
        transport_factory=lambda _context: publication.world,
        signer_factory=alice_signer,
        clock=fake.clock,
        sleep=fake.sleep,
    )


DISABLED: Final[dict[str, Any]] = {
    "revocation_policy": None,
    "revocation_policy_digest": None,
    "revocation_snapshot": None,
}


def test_testnet_may_run_without_revocation_until_it_holds_a_high_water(tmp_path: Path) -> None:
    """Only ``finney`` requires the authority, but a held high water is never dropped."""

    publication = write_static_publication(tmp_path / "publication")
    retarget_test581(publication)

    unpinned = _static_only(publication, tmp_path / "unpinned", **DISABLED)

    assert unpinned.epoch is not None and unpinned.epoch.epoch_status == "scored"
    # Without a revocation authority the record keeps the frozen v1 contract.
    unpinned_record = _published_record(unpinned.config.epoch_output)
    assert unpinned_record["schema_version"] == 1
    assert "release_revocation_snapshot_digest" not in unpinned_record
    pinned = _static_only(publication, tmp_path / "pinned")
    assert pinned.epoch is not None and pinned.revocation is not None
    state_root = pinned.config.state_root
    assert (Path(state_root) / REVOCATION_HIGH_WATER_NAME).exists()
    state_before = (Path(state_root) / "state.json").read_bytes()
    publication.world.calls.clear()

    with pytest.raises(AssignmentProbeCLIError) as error:
        _static_only(publication, tmp_path / "dropped", state_root=state_root, **DISABLED)

    assert error.value.code == "static_revocation_policy_required"
    assert publication.world.calls == []
    assert (Path(state_root) / "state.json").read_bytes() == state_before


@pytest.mark.parametrize(
    ("extra", "remove", "exit_code", "stderr"),
    [
        pytest.param(
            [], {"--static-release-revocation-policy"}, EXIT_USAGE, "usage", id="digest alone"
        ),
        pytest.param(
            ["--static-release-revocation-max-age-seconds", "299"],
            set(),
            EXIT_REJECTED,
            "static_revocation_max_age_invalid",
            id="max age below bound",
        ),
        pytest.param(
            ["--static-release-revocation-max-age-seconds", "1e3"],
            set(),
            EXIT_USAGE,
            "usage",
            id="max age not decimal",
        ),
    ],
)
def test_revocation_options_are_all_or_nothing_and_bounded(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    extra: list[str],
    remove: set[str],
    exit_code: int,
    stderr: str,
) -> None:
    publication = write_static_publication(tmp_path / "publication")
    argv = config_argv(cli_config(publication, tmp_path / "run"))
    argv = [
        item
        for option, value in zip(argv[::2], argv[1::2], strict=True)
        if option not in remove
        for item in (option, value)
    ] + extra

    assert run_cli(argv) == exit_code
    assert capsys.readouterr().err == f"REJECTED {stderr}\n"
    assert publication.world.calls == []


def _revoked_record(tmp_path: Path) -> dict[str, Any]:
    publication = write_static_publication(tmp_path / "publication")
    static = _static_deployment(publication)
    snapshot = revocation_snapshot_bytes(
        1,
        REVOCATION_ISSUED_EPOCH,
        releases=((static.release_digest, static.site_digest, "phishing"),),
    )
    result = _run(publication, tmp_path / "run", snapshot)
    assert result.static is not None
    return _published_record(result.static.config.epoch_output)


def _reseal(document: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in document.items() if key != "epoch_score_digest_sha256"}
    return (
        json.dumps(
            {**unsigned, "epoch_score_digest_sha256": digest(unsigned)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


@pytest.mark.parametrize(
    ("version", "drop_binding", "code"),
    [
        pytest.param(1, True, "static_epoch_revocation_unbound", id="v1 carrying release_revoked"),
        pytest.param(3, True, "static_epoch_revocation_binding_invalid", id="v3 without binding"),
        pytest.param(1, False, "static_epoch_revocation_binding_invalid", id="v1 with binding"),
    ],
)
def test_release_revoked_is_only_parseable_in_a_bound_v3_record(
    tmp_path: Path, version: int, drop_binding: bool, code: str
) -> None:
    record = _revoked_record(tmp_path)
    assert parse_static_epoch_score(_reseal(record)).schema_version == 3  # control
    changed = {**record, "schema_version": version}
    if version == 1:
        changed.pop("transport_profile")
        changed.pop("transport_policy_digest_sha256")
    if drop_binding:
        changed.pop("release_revocation_policy_digest_sha256")
        changed.pop("release_revocation_snapshot_digest")

    with pytest.raises(ValueError) as error:
        parse_static_epoch_score(_reseal(changed))

    assert code in str(error.value.__cause__)


def test_scoring_refuses_release_revoked_without_a_revocation_binding(tmp_path: Path) -> None:
    epoch = parse_static_epoch_score(_reseal(_revoked_record(tmp_path)))
    abstentions = [
        StaticIndexAbstention(row.deployment_id, row.site_digest, row.code)
        for row in epoch.index_abstentions
    ]
    common: dict[str, Any] = {
        "validator_hotkey": epoch.validator_hotkey,
        "epoch_index": epoch.epoch_index,
        "probe_body_ceiling": epoch.probe_body_ceiling,
    }

    with pytest.raises(StaticScoringError) as error:
        score_static_epoch(epoch.targets, [], abstentions, [], **common)

    assert error.value.code == "static_scoring_index_state_invalid"
    bound = score_static_epoch(
        epoch.targets,
        [],
        abstentions,
        [],
        release_revocation=(
            str(epoch.release_revocation_policy_digest_sha256),
            str(epoch.release_revocation_snapshot_digest),
        ),
        **common,
    )
    assert static_epoch_score_bytes(bound) == static_epoch_score_bytes(epoch)
    assert model_document(bound)["schema_version"] == 3
