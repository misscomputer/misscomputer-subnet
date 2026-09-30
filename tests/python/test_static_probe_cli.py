# SPDX-License-Identifier: AGPL-3.0-only
"""``misscomputer-assignment-probe --static-sites on``: end-to-end CLI boundary."""

from __future__ import annotations

import functools
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from assignment_probe_context import FINALIZED_HEIGHT, signer_keys
from organic_context import EPOCH_START
from static_cli_context import (
    INDEX_ORIGIN,
    STATIC_ID,
    FakeTime,
    alice_signer,
    cli_config,
    config_argv,
    execute,
    sign_v3,
    write_static_publication,
)
from static_context import SERVER, trust_policy

import misscomputer_subnet.assignment_probe_cli as probe_cli
import misscomputer_subnet.static_runtime as static_runtime
from misscomputer_subnet.assignment_probe import parse_assignment_manifest_chain_state
from misscomputer_subnet.assignment_probe_cli import (
    EXIT_DEGRADED,
    EXIT_OK,
    EXIT_USAGE,
    AssignmentProbeCLIError,
    run_cli,
)
from misscomputer_subnet.contract_codec import canonical_json, model_document
from misscomputer_subnet.organic_manifest import (
    ORGANIC_MANIFEST_SIGNATURE_DOMAIN_SEPARATOR,
    assignment_manifest_v3_bytes,
    organic_assignment_manifest_bytes,
)
from misscomputer_subnet.static_evidence import StaticEvidenceJournal
from misscomputer_subnet.static_index import static_deployment_targets
from misscomputer_subnet.static_scoring import aggregate_static_window, parse_static_epoch_score


def _cli(world: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeTime(EPOCH_START)
    monkeypatch.setattr(
        probe_cli,
        "execute_assignment_probe",
        functools.partial(
            probe_cli.execute_assignment_probe,
            transport_factory=lambda _context: world,
            signer_factory=alice_signer,
            clock=fake.clock,
            sleep=fake.sleep,
        ),
    )


def _static_calls(world: Any) -> list[str]:
    return [target for kind, target in world.calls if kind == "static"]


def test_stalled_static_send_cannot_delay_an_organic_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The static worker may stall, but the organic send keeps its private instant."""

    fake = FakeTime(EPOCH_START)
    epoch_index = int(EPOCH_START) // 300
    first = int(EPOCH_START * 1_000) + 10
    organic_sent = threading.Event()
    static_completed: list[bool] = []
    static_run = SimpleNamespace(observations=[], skipped=0)

    def static_fire(_now: int) -> None:
        static_completed.append(organic_sent.wait(0.5))
        static_run.observations.append("static")

    def organic_schedule(
        _manifest: Any, _policy: Any, _transport: Any, observations: list[str], **_kw: Any
    ) -> list[Any]:
        def organic_fire(_now: int) -> None:
            organic_sent.set()
            observations.append("organic")

        return [(first + 10, organic_fire)]

    monkeypatch.setattr(static_runtime, "load_static_epoch", lambda *a, **kw: None)
    monkeypatch.setattr(
        static_runtime, "static_probe_schedule", lambda *a, **kw: [(first, static_fire)]
    )
    monkeypatch.setattr(probe_cli, "organic_probe_schedule", organic_schedule)

    observed, skipped = probe_cli._run_with_static(
        static_run,
        (object(), "server", "index"),
        object(),
        object(),
        object(),
        seed=b"x" * 32,
        validator_hotkey="validator",
        sign=lambda value: value,
        epoch_index=epoch_index,
        edge_origin=None,
        evaluation_epoch=int(EPOCH_START),
        current_finalized_height=1,
        clock=fake.clock,
        sleep=fake.sleep,
    )

    assert observed == ["organic"]
    assert skipped == 0 and static_completed == [True]


def test_static_epoch_is_scored_separately_and_organic_bytes_are_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    publication = write_static_publication(tmp_path / "publication")
    off = cli_config(publication, tmp_path / "off", static=False)
    execute(off, publication.world)
    publication.world.calls.clear()
    on = cli_config(publication, tmp_path / "on")
    _cli(publication.world, monkeypatch)

    assert run_cli(config_argv(on)) == EXIT_OK

    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("PROBED status=scored ") and out[1].startswith("STATIC status=scored ")
    # The organic record is byte-identical to the organic-only run.
    assert Path(on.epoch_output).read_bytes() == Path(off.epoch_output).read_bytes()
    static = on.static_sites
    assert static is not None
    epoch = parse_static_epoch_score(Path(static.epoch_output).read_bytes())
    # Only the static-site-v1 deployment is a static target; the v3 OCI entry is not.
    assert [item.deployment_id for item in epoch.targets] == [STATIC_ID]
    assert {(item.disposition, item.successes, item.attempts) for item in epoch.endpoints} == {
        ("eligible", 3, 3)
    }
    assert epoch.coverage[0].routes_total > 0 and epoch.index_abstentions == []
    assert sorted(_static_calls(publication.world)) == sorted(
        item.endpoint_id for item in epoch.endpoints for _ in range(3)
    )
    # Every observation is durable in the hash-chained journal before scoring.
    with StaticEvidenceJournal(static.journal) as journal:
        assert sorted(journal.observations, key=lambda item: item.probe_nonce) == sorted(
            epoch.observations, key=lambda item: item.probe_nonce
        )
    state = parse_assignment_manifest_chain_state(
        (Path(static.state_root) / "state.json").read_bytes()
    )
    assert state.last_manifest_digest_sha256 == publication.v3.manifest_digest_sha256
    archived = Path(static.manifest_archive_dir) / f"{publication.v3.manifest_digest_sha256}.json"
    assert archived.read_bytes() == assignment_manifest_v3_bytes(publication.v3)
    organic_archive = Path(on.manifest_archive_dir)
    assert [path.name for path in organic_archive.iterdir()] == [
        f"{publication.organic.manifest_digest_sha256}.json"
    ]
    assert (
        organic_archive / f"{publication.organic.manifest_digest_sha256}.json"
    ).read_bytes() == (organic_assignment_manifest_bytes(publication.organic))


def test_static_options_require_the_flag_and_the_flag_requires_every_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    publication = write_static_publication(tmp_path / "publication")
    _cli(publication.world, monkeypatch)
    argv = config_argv(cli_config(publication, tmp_path / "run"))
    flag = argv.index("--static-sites")

    assert run_cli(argv[:flag] + argv[flag + 2 :]) == EXIT_USAGE
    journal = argv.index("--static-journal")
    assert run_cli(argv[:journal] + argv[journal + 2 :]) == EXIT_USAGE
    assert capsys.readouterr().err == "REJECTED usage\nREJECTED usage\n"
    assert publication.world.calls == []


@pytest.mark.parametrize(
    ("index", "record_code"),
    [({"publish_index": False}, "static_index_unavailable"), ({"release_override": b"{}\n"}, None)],
)
def test_missing_or_invalid_index_abstains_without_a_probe_or_a_zero(
    tmp_path: Path, index: dict[str, Any], record_code: str | None
) -> None:
    publication = write_static_publication(tmp_path / "publication", **index)
    config = cli_config(publication, tmp_path / "run")

    result = execute(config, publication.world)

    assert result.epoch.epoch_status == "scored"
    static = result.static
    assert static is not None and static.epoch is not None
    (abstention,) = static.epoch.index_abstentions
    assert abstention.record_code == (record_code or "static_index_invalid")
    assert {item.disposition for item in static.epoch.endpoints} == {"abstain_index"}
    assert static.epoch.epoch_status == "no_eligible_endpoints"
    # No static probe was sent and no dynamic predicate stood in for one.
    assert _static_calls(publication.world) == []
    assert aggregate_static_window([static.epoch]).miners == []


def test_slow_index_abstains_at_the_bounded_fetch_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publication = write_static_publication(tmp_path / "publication")
    config = cli_config(publication, tmp_path / "run")
    original_fetch = publication.world.fetch

    def slow_fetch(**kwargs: Any) -> Any:
        if "/manifests/" in kwargs["url"]:
            time.sleep(0.04)
        return original_fetch(**kwargs)

    monkeypatch.setattr(publication.world, "fetch", slow_fetch)
    monkeypatch.setattr(static_runtime, "STATIC_INDEX_LOAD_BUDGET_SECONDS", 0.02, raising=False)

    result = execute(config, publication.world)

    assert result.epoch.epoch_status == "scored"
    assert result.static is not None and result.static.epoch is not None
    assert [item.record_code for item in result.static.epoch.index_abstentions] == [
        "static_index_unavailable"
    ]
    assert len([kind for kind, _ in publication.world.calls if kind == "index"]) == 1
    assert _static_calls(publication.world) == []


def test_index_budget_gives_each_site_a_first_fetch_across_epochs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publication = write_static_publication(tmp_path / "publication")
    prepared = execute(cli_config(publication, tmp_path / "prepared"), publication.world)
    assert prepared.static is not None and prepared.static.verification is not None
    first = static_deployment_targets(prepared.static.verification)[0]
    second = first.model_copy(update={"deployment_id": "site-b"})
    monkeypatch.setattr(
        static_runtime, "static_deployment_targets", lambda _verified: [first, second]
    )
    monkeypatch.setattr(static_runtime, "STATIC_INDEX_LOAD_BUDGET_SECONDS", 0.02)
    fetched: list[str] = []

    def slow_index(_transport: Any, target: Any, **_kwargs: Any) -> tuple[None, None]:
        fetched.append(target.deployment_id)
        time.sleep(0.04)
        return None, None

    monkeypatch.setattr(static_runtime, "fetch_static_index_documents", slow_index)
    first_fetched: list[str] = []
    for offset in range(2):
        static = cli_config(publication, tmp_path / f"epoch-{offset}").static_sites
        assert static is not None
        run = static_runtime.lock_static_epoch(static, publication.policy)
        try:
            static_runtime.load_static_epoch(
                run,
                transport=publication.world,
                policy=publication.policy,
                release_policy=trust_policy(),
                server_digest=SERVER,
                index_origin=INDEX_ORIGIN,
                evaluation_epoch=int(EPOCH_START) + offset * 300,
                current_finalized_height=FINALIZED_HEIGHT,
            )
        finally:
            run.close()
        first_fetched.append(fetched[0])
        fetched.clear()

    assert set(first_fetched) == {"site-a", "site-b"}


def test_unverifiable_v3_manifest_abstains_static_while_organic_scores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    keys = signer_keys()
    first = write_static_publication(tmp_path / "template")
    # Signed over the v2 domain: a valid signature, but never a v3 signature.
    wrong_domain = sign_v3(
        first.v3,
        keys,
        message=ORGANIC_MANIFEST_SIGNATURE_DOMAIN_SEPARATOR
        + b"\x00"
        + canonical_json(model_document(first.v3)),
    )
    publication = write_static_publication(tmp_path / "publication", v3_signatures=wrong_domain)
    config = cli_config(publication, tmp_path / "run")
    _cli(publication.world, monkeypatch)

    assert run_cli(config_argv(config)) == EXIT_DEGRADED

    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("PROBED status=scored ")
    assert out[1] == "STATIC status=abstained code=static_signature_invalid"
    static = config.static_sites
    assert static is not None
    assert not Path(static.epoch_output).exists()
    assert not (Path(static.state_root) / "state.json").exists()
    assert list(Path(static.manifest_archive_dir).iterdir()) == []
    assert _static_calls(publication.world) == []
    assert Path(config.epoch_output).exists()


def _wrong_body(state: dict[str, Any]) -> None:
    if state["body"]:
        state["body"] = state["attested_body"] = b"x" * len(state["body"])


def test_content_fault_is_journaled_and_recommends_quarantine_not_trust_zero(
    tmp_path: Path,
) -> None:
    publication = write_static_publication(tmp_path / "publication")
    faulty = publication.world.edge.endpoints[1].endpoint_id
    publication.world.edge.faults[faulty] = _wrong_body
    config = cli_config(publication, tmp_path / "run")

    result = execute(config, publication.world)

    static = result.static
    assert static is not None and static.epoch is not None
    (action,) = static.epoch.endpoint_actions
    assert (action.endpoint_id, action.reason, action.quarantine, action.trust_zero) == (
        faulty,
        "content_fault",
        True,
        False,
    )
    assert {row.endpoint_id for row in static.epoch.content_fault_evidence} == {faulty}
    assert config.static_sites is not None
    with StaticEvidenceJournal(config.static_sites.journal) as journal:
        journaled = {item.observation_digest_sha256 for item in journal.observations}
    assert set(action.evidence_digests) <= journaled


def test_a_tampered_journal_refuses_the_run_before_any_state_or_probe(tmp_path: Path) -> None:
    publication = write_static_publication(tmp_path / "publication")
    config = cli_config(publication, tmp_path / "first")
    execute(config, publication.world)
    assert config.static_sites is not None
    journal = Path(config.static_sites.journal)
    journal.write_bytes(journal.read_bytes()[:-3])
    publication.world.calls.clear()
    later = cli_config(publication, tmp_path / "second")
    assert later.static_sites is not None
    later = replace(later, static_sites=replace(later.static_sites, journal=str(journal)))

    with pytest.raises(AssignmentProbeCLIError) as error:
        execute(later, publication.world)

    assert error.value.code == "static_evidence_journal_invalid"
    assert publication.world.calls == []
    assert not (Path(later.state_root) / "state.json").exists()


def test_stale_static_anchor_refuses_before_organic_state_advances(tmp_path: Path) -> None:
    publication = write_static_publication(tmp_path / "publication")
    first = cli_config(publication, tmp_path / "first")
    execute(first, publication.world)
    assert first.static_sites is not None
    later = cli_config(publication, tmp_path / "later")
    assert later.static_sites is not None
    later = replace(
        later,
        static_sites=replace(
            later.static_sites,
            state_root=first.static_sites.state_root,
            trusted_state_anchor="genesis",
        ),
    )
    publication.world.calls.clear()

    with pytest.raises(AssignmentProbeCLIError) as error:
        execute(later, publication.world)

    assert error.value.code == "state_anchor_stale"
    assert publication.world.calls == []
    assert not (Path(later.state_root) / "state.json").exists()
    assert not Path(later.epoch_output).exists()


def test_static_worker_failure_abstains_without_losing_organic_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publication = write_static_publication(tmp_path / "publication")
    off = cli_config(publication, tmp_path / "off", static=False)
    execute(off, publication.world)
    on = cli_config(publication, tmp_path / "on")

    def fail_index(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("index unavailable")

    monkeypatch.setattr(static_runtime, "fetch_static_index_documents", fail_index)
    result = execute(on, publication.world)

    assert len(result.epoch.observations) == 18 and result.skipped_probes == 0
    assert Path(on.epoch_output).read_bytes() == Path(off.epoch_output).read_bytes()
    assert result.static is not None
    assert result.static.epoch is None
    assert result.static.abstained_code == "static_internal_error"
    assert on.static_sites is not None
    assert not Path(on.static_sites.epoch_output).exists()


def test_slow_static_index_does_not_delay_organic_output_or_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publication = write_static_publication(tmp_path / "publication")
    off = cli_config(publication, tmp_path / "off", static=False)
    execute(off, publication.world)
    on = cli_config(publication, tmp_path / "on")
    started = threading.Event()
    unblock = threading.Event()
    organic_written = threading.Event()
    original_fetch = static_runtime.fetch_static_index_documents
    original_write = probe_cli._write_output

    def slow_index(*args: Any, **kwargs: Any) -> Any:
        started.set()
        if not unblock.wait(3):
            raise AssertionError("test index was not released")
        return original_fetch(*args, **kwargs)

    def watch_output(path: str, rendered: bytes, *, state_root: str) -> None:
        original_write(path, rendered, state_root=state_root)
        if path == on.epoch_output:
            organic_written.set()

    monkeypatch.setattr(static_runtime, "fetch_static_index_documents", slow_index)
    monkeypatch.setattr(probe_cli, "_write_output", watch_output)
    results: list[Any] = []
    failures: list[BaseException] = []

    def run() -> None:
        try:
            results.append(execute(on, publication.world))
        except BaseException as exc:
            failures.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert started.wait(2)
        assert organic_written.wait(2)
        assert thread.is_alive()  # still blocked solely on the static index
    finally:
        unblock.set()
        thread.join(timeout=5)
    assert not thread.is_alive() and not failures
    assert len(results) == 1
    assert results[0].skipped_probes == 0
    assert Path(on.epoch_output).read_bytes() == Path(off.epoch_output).read_bytes()


def test_static_state_root_may_not_alias_the_organic_root(tmp_path: Path) -> None:
    publication = write_static_publication(tmp_path / "publication")
    config = cli_config(publication, tmp_path / "run")
    assert config.static_sites is not None
    aliased = replace(
        config, static_sites=replace(config.static_sites, state_root=config.state_root)
    )

    with pytest.raises(AssignmentProbeCLIError) as error:
        execute(aliased, publication.world)

    assert error.value.code == "static_state_root_alias"
    assert publication.world.calls == []
