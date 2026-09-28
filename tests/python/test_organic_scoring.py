# SPDX-License-Identifier: AGPL-3.0-only
"""Organic availability scoring from hidden validator probes (contract §17.2)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from fractions import Fraction

import pytest
from assignment_probe_context import BASE_EPOCH, MINERS, miner_key
from organic_context import (
    BLOG,
    EPOCH,
    EPOCH_START,
    SHOP,
    VALIDATOR_HOTKEY,
    build_manifest,
    endpoint,
    epoch_probes,
    fixture_deployments,
    make_context,
    probe,
)
from pydantic import ValidationError

from misscomputer_subnet.checkpoint_score_contracts import (
    CanonicalScoreReport,
    canonical_score_report_bytes,
)
from misscomputer_subnet.contract_codec import canonical_json, digest, model_document
from misscomputer_subnet.organic_contracts import (
    ActiveAssignmentManifestV2 as OrganicAssignmentManifest,
)
from misscomputer_subnet.organic_contracts import miner_probe_attestation_v2_message
from misscomputer_subnet.organic_probe import OrganicProbeObservation
from misscomputer_subnet.organic_scoring import (
    OrganicAvailabilityScore,
    OrganicEpochScore,
    OrganicScoringError,
    ServingCorroboration,
    aggregate_organic_window,
    organic_epoch_score_bytes,
    organic_weight_rows,
    parse_organic_epoch_score,
    replay_organic_epoch_score,
    score_organic_epoch,
)
from misscomputer_subnet.weight_plan import build_weight_plan


@pytest.fixture(scope="module")
def context():  # type: ignore[no-untyped-def]
    return make_context()


def score(
    manifest: OrganicAssignmentManifest,
    observations: Sequence[OrganicProbeObservation],
    *,
    epoch_index: int = EPOCH,
    corroboration: Sequence[ServingCorroboration] = (),
) -> OrganicEpochScore:
    return score_organic_epoch(
        [manifest],
        observations,
        validator_hotkey=VALIDATOR_HOTKEY,
        epoch_index=epoch_index,
        corroboration=corroboration,
    )


def availability(result: OrganicAvailabilityScore) -> dict[str, Fraction]:
    return {
        item.miner_hotkey: Fraction(item.availability_numerator, item.availability_denominator)
        for item in result.miners
    }


def all_endpoints(manifest: OrganicAssignmentManifest) -> list[str]:
    return [r.endpoint_id for d in manifest.deployments for r in d.replicas]


def test_miner_availability_is_the_mean_of_eligible_endpoint_epochs(context) -> None:  # type: ignore[no-untyped-def]
    """Worked example over two epochs; every replica sampled three times per epoch."""

    policy, manifest = context.policy, context.manifest
    shop_b, blog_b = endpoint(manifest, SHOP, "MinerB"), endpoint(manifest, BLOG, "MinerB")
    healthy = {item: ("success",) * 3 for item in all_endpoints(manifest)}
    first = score(
        manifest,
        epoch_probes(policy, manifest, {**healthy, shop_b: ("success", "edge_down", "success")}),
    )
    second = score(
        manifest,
        epoch_probes(
            policy,
            manifest,
            {**healthy, blog_b: ("transport", "transport", "success")},
            epoch_start=EPOCH_START + 300,
        ),
        epoch_index=EPOCH + 1,
    )
    result = aggregate_organic_window([second, first])
    # MinerB: mean(2/3, 1, 1, 1/3) over its four eligible endpoint-epochs.
    assert availability(result) == {
        "MinerA": Fraction(1),
        "MinerB": Fraction(3, 4),
        "MinerC": Fraction(1),
        "MinerD": Fraction(1),
    }
    assert {item.miner_hotkey: item.eligible_endpoint_epochs for item in result.miners} == {
        "MinerA": 2,
        "MinerB": 4,
        "MinerC": 4,
        "MinerD": 2,
    }


def test_under_sampled_endpoints_abstain_and_unsampled_miners_stay_unscored(context) -> None:  # type: ignore[no-untyped-def]
    policy, manifest = context.policy, context.manifest
    record = score(
        manifest,
        epoch_probes(
            policy,
            manifest,
            {
                endpoint(manifest, SHOP, "MinerA"): ("edge_down",),
                endpoint(manifest, SHOP, "MinerB"): ("success", "success"),
                endpoint(manifest, SHOP, "MinerC"): ("success", "success", "success"),
            },
        ),
    )
    dispositions = {item.miner_hotkey: item.disposition for item in record.endpoints}
    assert dispositions == {
        "MinerA": "abstain_insufficient_attempts",
        "MinerB": "eligible",
        "MinerC": "eligible",
    }
    result = aggregate_organic_window([record])
    # MinerA abstained and MinerD was never probed: both absent, never zero.
    assert set(availability(result)) == {"MinerB", "MinerC"}


def test_common_mode_edge_outage_abstains_instead_of_penalizing(context) -> None:  # type: ignore[no-untyped-def]
    policy, manifest = context.policy, context.manifest
    endpoints = all_endpoints(manifest)
    script = {item: ("edge_down", "transport", "edge_down") for item in endpoints[:4]}
    script.update({item: ("success",) * 3 for item in endpoints[4:]})
    record = score(manifest, epoch_probes(policy, manifest, script))
    assert record.epoch_status == "common_mode_unavailable"
    assert {item.disposition for item in record.endpoints} == {"excluded_common_mode"}
    result = aggregate_organic_window([record])
    assert result.miners == [] and result.abstained_epochs == [EPOCH]
    # One dead replica among six is the miner's own unavailability, not common mode.
    script = {item: ("success",) * 3 for item in endpoints}
    script[endpoints[0]] = ("edge_down",) * 3
    minority = score(manifest, epoch_probes(policy, manifest, script))
    assert minority.epoch_status == "scored"
    assert (
        minority.endpoints[
            [item.endpoint_id for item in minority.endpoints].index(endpoints[0])
        ].availability_numerator
        == 0
    )


def test_app_wide_health_failure_excludes_every_replica_of_that_app(context) -> None:  # type: ignore[no-untyped-def]
    policy, manifest = context.policy, context.manifest
    script = {item: ("success",) * 3 for item in all_endpoints(manifest)}
    script[endpoint(manifest, SHOP, "MinerA")] = ("app_status", "success", "success")
    script[endpoint(manifest, SHOP, "MinerB")] = ("app_marker",) * 3
    script[endpoint(manifest, SHOP, "MinerC")] = ("edge_down",) * 3
    record = score(manifest, epoch_probes(policy, manifest, script))
    assert record.inconclusive_deployments == [SHOP]
    shop = [item for item in record.endpoints if item.deployment_id == SHOP]
    assert {item.disposition for item in shop} == {"excluded_app_inconclusive"}
    # A single replica failing the predicate is still scored against its miner.
    script[endpoint(manifest, SHOP, "MinerB")] = ("success",) * 3
    single = score(manifest, epoch_probes(policy, manifest, script))
    assert single.inconclusive_deployments == []


def test_serving_volume_is_corroboration_only_and_never_changes_scores(context) -> None:  # type: ignore[no-untyped-def]
    policy, manifest = context.policy, context.manifest
    script = {item: ("success", "edge_down", "success") for item in all_endpoints(manifest)}
    observations = epoch_probes(policy, manifest, script)
    flood = [
        ServingCorroboration(
            endpoint_id=item,
            window_start_epoch=BASE_EPOCH + 60 * minute,
            window_digest_sha256=digest([item, minute]),
            requests=1_000_000 if "MinerA" in item else 0,
            origin=False,
        )
        for item in all_endpoints(manifest)
        for minute in range(5)
    ]
    quiet = aggregate_organic_window([score(manifest, observations)])
    busy_record = score(manifest, observations, corroboration=flood)
    busy = aggregate_organic_window([busy_record])
    assert quiet.miners == busy.miners
    shop_a = endpoint(manifest, SHOP, "MinerA")
    tally = next(item for item in busy_record.endpoints if item.endpoint_id == shop_a)
    assert (tally.corroborating_windows, tally.corroborating_requests) == (5, 5_000_000)


def test_epoch_record_bytes_do_not_depend_on_input_order(context) -> None:  # type: ignore[no-untyped-def]
    observations = list(context.epoch.observations)
    shuffled = observations[1::2][::-1] + observations[::2]
    assert shuffled != observations
    assert organic_epoch_score_bytes(score(context.manifest, shuffled)) == (
        organic_epoch_score_bytes(context.epoch)
    )


def test_sealed_record_rederives_every_tally_from_its_evidence(context) -> None:  # type: ignore[no-untyped-def]
    document = json.loads(organic_epoch_score_bytes(context.epoch))
    target = next(item for item in document["endpoints"] if item["successes"] < item["attempts"])
    target["successes"] += 1
    target["availability_numerator"] = target["availability_denominator"] = 1
    unsigned = {k: v for k, v in document.items() if k != "epoch_score_digest_sha256"}
    document["epoch_score_digest_sha256"] = digest(unsigned)
    with pytest.raises(ValidationError, match="epoch_endpoints_mismatch"):
        OrganicEpochScore.model_validate(document)
    with pytest.raises(ValueError):
        parse_organic_epoch_score(canonical_json(document) + b"\n")


def _forged_success(context, signer) -> OrganicProbeObservation:  # type: ignore[no-untyped-def]
    """Turn a failed probe into a digest-valid 'success' with an attestation from ``signer``."""

    failed = probe(
        context.policy,
        context.manifest,
        endpoint(context.manifest, SHOP, "MinerA"),
        offset_seconds=5,
        behavior="no_attestation",
    )
    genuine = probe(
        context.policy,
        context.manifest,
        endpoint(context.manifest, SHOP, "MinerA"),
        offset_seconds=5,
        behavior="success",
    )
    assert genuine.attestation is not None
    attestation = genuine.attestation.model_copy(update={"signature_hex": "00" * 64})
    attestation = attestation.model_copy(
        update={"signature_hex": signer.sign(miner_probe_attestation_v2_message(attestation)).hex()}
    )
    document = model_document(failed, exclude={"observation_digest_sha256"})
    document.update(
        outcome="success",
        failure_code=None,
        attribution="none",
        attestation_status="verified",
        attestation=model_document(attestation),
    )
    return OrganicProbeObservation.model_validate(
        {**document, "observation_digest_sha256": digest(document)}
    )


def test_scoring_reverifies_attestations_so_a_forged_success_is_refused(context) -> None:  # type: ignore[no-untyped-def]
    genuine = _forged_success(context, miner_key("MinerA"))
    score(context.manifest, [genuine])
    forged = _forged_success(context, miner_key("MinerB"))
    with pytest.raises(OrganicScoringError, match="scoring_attestation_unverified"):
        score(context.manifest, [forged])


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        pytest.param("foreign_validator", "scoring_validator_mismatch", id="foreign-validator"),
        pytest.param("wrong_epoch", "scoring_epoch_mismatch", id="wrong-epoch"),
        pytest.param("duplicate", "scoring_observation_duplicate", id="replayed-observation"),
        pytest.param("unknown_manifest", "scoring_manifest_unknown", id="unknown-manifest"),
    ],
)
def test_untrustworthy_epoch_inputs_are_refused(context, mutation: str, code: str) -> None:  # type: ignore[no-untyped-def]
    observations = list(context.epoch.observations)
    manifests: list[OrganicAssignmentManifest] = [context.manifest]
    validator, epoch_index = VALIDATOR_HOTKEY, EPOCH
    if mutation == "foreign_validator":
        validator = "SomeoneElse"
    elif mutation == "wrong_epoch":
        epoch_index = EPOCH + 1
    elif mutation == "duplicate":
        observations.append(observations[0])
    elif mutation == "unknown_manifest":
        manifests = [build_manifest(context.policy, fixture_deployments(), issued_at=BASE_EPOCH)]
    with pytest.raises(OrganicScoringError, match=code):
        score_organic_epoch(
            manifests, observations, validator_hotkey=validator, epoch_index=epoch_index
        )


def test_third_party_replay_accepts_the_record_only_against_its_manifests(context) -> None:  # type: ignore[no-untyped-def]
    assert replay_organic_epoch_score(context.epoch, [context.manifest]) == context.epoch
    other = build_manifest(context.policy, fixture_deployments(), issued_at=BASE_EPOCH)
    with pytest.raises(OrganicScoringError, match="scoring_manifest_unknown"):
        replay_organic_epoch_score(context.epoch, [other])


def test_fraud_is_surfaced_as_evidence_and_counts_only_as_a_failed_probe(context) -> None:  # type: ignore[no-untyped-def]
    fraud = [item for item in context.epoch.fraud_evidence]
    assert [(item.miner_hotkey, item.endpoint_id) for item in fraud] == [
        ("MinerD", endpoint(context.manifest, BLOG, "MinerD"))
    ]
    row = next(item for item in context.score.miners if item.miner_hotkey == "MinerD")
    assert (row.availability_numerator, row.availability_denominator) == (2, 3)
    assert row.fraudulent_attestations == 1


def test_availability_rows_feed_the_existing_weight_plan(context) -> None:  # type: ignore[no-untyped-def]
    from misscomputer_subnet.chain import MetagraphSnapshot, NeuronRecord

    neurons = [
        NeuronRecord(
            uid=7,
            hotkey=VALIDATOR_HOTKEY,
            validator_permit=True,
            tao_stake=1_000.0,
            axon=None,
            active=True,
        ),
        *[
            NeuronRecord(
                uid=uid,
                hotkey=hotkey,
                validator_permit=False,
                tao_stake=1.0,
                axon="127.0.0.1:8091",
                active=True,
            )
            for uid, hotkey in MINERS
        ],
    ]
    snapshot = MetagraphSnapshot(
        network="finney", netuid=24, block=1_000, tempo=100, neurons=tuple(neurons), finalized=True
    )
    plan = build_weight_plan(
        snapshot=snapshot,
        validator_hotkey=VALIDATOR_HOTKEY,
        rows=organic_weight_rows(context.score),
        version_key=1,
    )
    weights = {entry.hotkey: entry.weight for entry in plan.weights}
    assert set(weights) == {"MinerA", "MinerB", "MinerC", "MinerD"}
    # Normalized in proportion to availability 1 : 5/6 : 1/2 : 2/3.
    assert weights["MinerA"] / weights["MinerC"] == pytest.approx(2.0)
    assert weights["MinerB"] / weights["MinerD"] == pytest.approx(1.25)


def test_central_report_rows_follow_from_availability_and_fraud(context) -> None:  # type: ignore[no-untyped-def]
    """The checkpoint's score input: floor ppm, fraud is ineligible, rows re-derived on parse."""

    report = context.central_report
    rows = {item.miner_hotkey: item for item in report.miner_scores}
    assert {
        key: (row.eligibility_status, row.canonical_score_ppm) for key, row in rows.items()
    } == {
        "MinerA": ("eligible", 1_000_000),
        "MinerB": ("eligible", 833_333),
        "MinerC": ("eligible", 500_000),
        "MinerD": ("ineligible", 0),
    }
    assert rows["MinerD"].reason_codes == ["attestation_fraud"]
    document = json.loads(canonical_score_report_bytes(report))
    document["miner_scores"][1]["canonical_score_ppm"] = 1_000_000
    record = {k: v for k, v in document["miner_scores"][1].items() if k != "record_digest_sha256"}
    document["miner_scores"][1]["record_digest_sha256"] = digest(record)
    document["score_vector_digest_sha256"] = digest(document["miner_scores"])
    unsigned = {k: v for k, v in document.items() if k != "report_digest_sha256"}
    document["report_digest_sha256"] = digest(unsigned)
    with pytest.raises(ValidationError, match="rows do not follow"):
        CanonicalScoreReport.model_validate(document)
