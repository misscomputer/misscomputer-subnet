# SPDX-License-Identifier: AGPL-3.0-only
"""The static-site side of ``misscomputer-assignment-probe`` (``--static-sites on``).

Off by default. When enabled, one probe run additionally:

1. takes the owner-only **static** state root lock (independent of the v2
   root: v3 is its own append-only publication chain);
2. loads one signed ``active-assignment-manifest`` v3 from an explicit file or
   HTTPS URL and verifies it live under the same pinned assignment-manifest
   trust policy (``organic_manifest.verify_assignment_manifest_v3``, its own
   v3 chain state); a missing or unverifiable v3 manifest makes the static
   path **abstain** for the epoch (no probe, no record, never a zero and never
   a dynamic probe) while the organic path runs unchanged;
3. archives the verified v3 manifest, then advances the v3 state;
4. with a pinned revocation policy (required on ``finney``), offers the
   operator-delivered ``static-site-release-revocation`` v1 snapshot to the
   durable high water in the static state root, and abstains for the epoch
   unless that high water exists and is fresh (§7.3,
   :mod:`misscomputer_subnet.static_revocation`);
5. authenticates ``static-site-v1`` deployment indexes (stored site manifest
   and signed release) within a whole-epoch fetch budget under the pinned
   static release trust policy and implementation digest; a deployment whose
   index is unfetched, unavailable or invalid abstains with its §11.2 record
   code, and one whose release or release signer is revoked abstains with
   ``static_release_revoked`` (never probed, never a zero);
6. interleaves the static hidden plan (seed-derived instants and paths,
   GET only within the trust policy's response ceiling, HEAD above it) with
   the organic plan in one time-ordered schedule, appending every sealed
   observation to the durable hash-chained evidence journal as it is judged;
7. seals a ``static-epoch-score`` v1 (coverage, content-fault and fraud
   evidence, quarantine recommendations, alerts) to its own exclusive output.

Static records never enter the organic epoch record, the window decision,
the weight plan or the checkpoint: they stay separate until an explicit
scoring-policy digest combines them.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Final, cast
from urllib.parse import urlsplit

from pydantic import ValidationError

from .assignment_probe import (
    MAX_DOCUMENT_BYTES,
    MAX_KEYS,
    AssignmentManifestChainState,
    AssignmentManifestSignatureEnvelope,
    AssignmentManifestTrustPolicy,
    AssignmentProbeError,
    assignment_manifest_chain_state_bytes,
    parse_assignment_manifest_signature_envelope,
)
from .assignment_probe_cli import (
    MAX_FETCH_BYTES,
    MAX_SIGNATURE_BYTES,
    AssignmentProbeCLIError,
    ManifestSource,
    ProbeTransport,
    ScheduledProbe,
    SignatureSource,
    _archive_document,
    _fail,
    _fetch_document,
    _load_file_bytes,
    _preflight_output,
    _resolve_prior_state,
    _StateRoot,
    _validated_https_url,
    _write_output,
)
from .organic_contracts import ActiveAssignmentManifestV3
from .organic_manifest import (
    AssignmentManifestV3Verification,
    anchor_assignment_manifest_v3_chain_state,
    assignment_manifest_v3_bytes,
    organic_manifest_effective_expires_at_epoch,
    parse_assignment_manifest_v3,
    verify_assignment_manifest_v3,
)
from .score_checkpoint_relay_cli import InputFile, _normalized_absolute_path
from .static_crawl import fetch_static_index_documents, send_static_probe
from .static_evidence import StaticEvidenceJournal
from .static_index import (
    StaticIndexAbstention,
    StaticSiteReleaseTrustPolicy,
    VerifiedStaticIndex,
    ingest_static_index,
    parse_static_site_release_trust_policy,
    static_deployment_targets,
)
from .static_probe import (
    HIDDEN_PROBE_CEILING_BYTES,
    PlannedStaticProbe,
    StaticProbeObservation,
    StaticPublicTransportPolicy,
    plan_static_hidden_probes,
)
from .static_revocation import (
    DEFAULT_MAX_AGE_SECONDS,
    MAX_MAX_AGE_SECONDS,
    MAX_REVOCATION_POLICY_BYTES,
    MAX_REVOCATION_SNAPSHOT_BYTES,
    MIN_MAX_AGE_SECONDS,
    StaticRevocationError,
    StaticSiteReleaseRevocationTrustPolicy,
    VerifiedRevocation,
    advance_static_site_release_revocation,
    parse_static_site_release_revocation_trust_policy,
    revocation_freshness,
    static_index_revoked,
    verify_static_site_release_revocation,
)
from .static_scoring import StaticEpochScore, score_static_epoch, static_epoch_score_bytes

MAX_RELEASE_TRUST_POLICY_BYTES: Final = 256 * 1_024
# A slow index origin must not keep the static-state lock across later epochs.
# Targets not fetched within this wall-clock budget abstain, never score zero.
STATIC_INDEX_LOAD_BUDGET_SECONDS: Final = 30.0
_PREFIXED_DIGEST_HEX: Final = frozenset("0123456789abcdef")
#: The durable revocation high water: exact stored snapshot bytes in the static root.
REVOCATION_HIGH_WATER_NAME: Final = "static-release-revocation.json"
REVOCATION_HIGH_WATER_INSTALL_NAME: Final = ".static-release-revocation.install"
REVOCATION_STATE_ENTRIES: Final = frozenset(
    {REVOCATION_HIGH_WATER_NAME, REVOCATION_HIGH_WATER_INSTALL_NAME}
)
_REVOCATION_PREFIX: Final = "static_revocation_"


@dataclass(frozen=True, slots=True)
class StaticSitesConfig:
    """Everything ``--static-sites on`` needs; every path and pin is explicit."""

    manifest: ManifestSource
    signatures: tuple[SignatureSource, ...]
    state_root: str
    trusted_state_anchor: str
    release_trust_policy: InputFile
    #: The pinned ``static-handler.v1`` implementation digest (``sha256:<hex>``).
    server_implementation_digest: str
    #: HTTPS origin of the §1 public static index (``static-sites/v1/...``).
    index_origin: str
    manifest_archive_dir: str
    epoch_output: str
    journal: str
    #: Pinned ``static-site-release-revocation-trust-policy`` v1 path and its
    #: ``digest_sha256``; ``None`` disables revocation (refused on ``finney``).
    revocation_policy: str | None = None
    revocation_policy_digest: str | None = None
    #: Operator-delivered snapshot offered to the high water this run (self-authenticating).
    revocation_snapshot: str | None = None
    revocation_max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS


@dataclass(slots=True)
class StaticRevocationState:
    """The pinned revocation authority and the durable high water this run relies on."""

    policy: StaticSiteReleaseRevocationTrustPolicy
    held: VerifiedRevocation | None


@dataclass(slots=True)
class StaticEpochRun:
    """One enabled static epoch: its verified inputs, then its evidence."""

    config: StaticSitesConfig
    root: _StateRoot | None
    prior_state: AssignmentManifestChainState | None = None
    #: Set when the static path abstains for the whole epoch (no v3 manifest).
    abstained_code: str | None = None
    verification: AssignmentManifestV3Verification | None = None
    indexes: list[VerifiedStaticIndex] = field(default_factory=list)
    abstentions: list[StaticIndexAbstention] = field(default_factory=list)
    observations: list[StaticProbeObservation] = field(default_factory=list)
    journal: StaticEvidenceJournal | None = None
    skipped: int = 0
    epoch: StaticEpochScore | None = None
    public_transport_policy: StaticPublicTransportPolicy | None = None
    revocation: StaticRevocationState | None = None

    def close(self) -> None:
        if self.journal is not None:
            self.journal.close()
        if self.root is not None:
            self.root.close()


def _pinned_digest(value: str) -> str:
    hex_part = value.removeprefix("sha256:")
    if (
        not value.startswith("sha256:")
        or len(hex_part) != 64
        or not set(hex_part) <= _PREFIXED_DIGEST_HEX
    ):
        _fail("static_server_digest_invalid")
    return value


def static_input_paths(config: StaticSitesConfig) -> set[str]:
    files = [config.release_trust_policy]
    if config.manifest.file is not None:
        files.append(config.manifest.file)
    files.extend(item.file for item in config.signatures if item.file is not None)
    paths = [item.path for item in files]
    paths.extend(
        path for path in (config.revocation_policy, config.revocation_snapshot) if path is not None
    )
    return {_normalized_absolute_path(path, code="input_path_unsafe") for path in paths}


def _check_revocation_options(config: StaticSitesConfig) -> None:
    if (config.revocation_policy is None) != (config.revocation_policy_digest is None):
        _fail("usage")
    if config.revocation_policy is None and (
        config.revocation_snapshot is not None
        or config.revocation_max_age_seconds != DEFAULT_MAX_AGE_SECONDS
    ):
        _fail("usage")
    digest_hex = config.revocation_policy_digest
    if digest_hex is not None and (
        len(digest_hex) != 64 or not set(digest_hex) <= _PREFIXED_DIGEST_HEX
    ):
        _fail("static_revocation_policy_digest_invalid")
    age = config.revocation_max_age_seconds
    if (
        isinstance(age, bool)
        or not isinstance(age, int)
        or not MIN_MAX_AGE_SECONDS <= age <= MAX_MAX_AGE_SECONDS
    ):
        _fail("static_revocation_max_age_invalid")


def _load_unpinned_file(path: str, *, label: str, max_bytes: int) -> bytes:
    """Bounded hardened read of a self-authenticating or digest-pinned document."""

    from .production_release_verifier import HardenedFileSet, ReleaseVerificationError

    normalized = _normalized_absolute_path(path, code="input_path_unsafe")
    try:
        with HardenedFileSet().open(normalized, label=label) as source:
            rendered, _ = source.read_bytes(max_bytes=max_bytes)
    except ReleaseVerificationError as exc:
        raise AssignmentProbeCLIError(f"{label}_unavailable") from exc
    return rendered


def _lock_revocation(
    root: _StateRoot, config: StaticSitesConfig, policy: AssignmentManifestTrustPolicy
) -> StaticRevocationState | None:
    """Load the pinned revocation authority and re-verify the stored high water.

    A held high water can never be dropped by configuration: without a policy
    it refuses the run, as does ``finney`` without a policy. A high water the
    pinned policy cannot verify refuses the run before any state advances.
    """

    stored = root.read_document(
        REVOCATION_HIGH_WATER_NAME,
        max_bytes=MAX_REVOCATION_SNAPSHOT_BYTES,
        prefix=_REVOCATION_PREFIX,
    )
    if config.revocation_policy is None or config.revocation_policy_digest is None:
        if stored is not None or policy.network == "finney":
            _fail("static_revocation_policy_required")
        return None
    release_policy = _load_release_policy(config.release_trust_policy)
    rendered = _load_unpinned_file(
        config.revocation_policy,
        label="static_revocation_policy",
        max_bytes=MAX_REVOCATION_POLICY_BYTES,
    )
    try:
        revocation_policy = parse_static_site_release_revocation_trust_policy(
            rendered,
            pinned_digest_sha256=config.revocation_policy_digest,
            release_policy=release_policy,
        )
    except StaticRevocationError as exc:
        raise AssignmentProbeCLIError(f"static_{exc.code}") from exc
    held = None
    if stored is not None:
        try:
            held = verify_static_site_release_revocation(stored, revocation_policy)
        except StaticRevocationError as exc:
            raise AssignmentProbeCLIError("static_revocation_high_water_invalid") from exc
    return StaticRevocationState(policy=revocation_policy, held=held)


def _install_revocation_high_water(
    root: _StateRoot, state: StaticRevocationState, offered: VerifiedRevocation
) -> None:
    """Advance the durable high water; the store re-reads its own bytes, then memory follows."""

    stored = root.read_document(
        REVOCATION_HIGH_WATER_NAME,
        max_bytes=MAX_REVOCATION_SNAPSHOT_BYTES,
        prefix=_REVOCATION_PREFIX,
    )
    try:
        held = (
            None if stored is None else verify_static_site_release_revocation(stored, state.policy)
        )
    except StaticRevocationError as exc:
        raise AssignmentProbeCLIError("static_revocation_high_water_invalid") from exc
    if advance_static_site_release_revocation(held, offered):
        root.install_document(
            REVOCATION_HIGH_WATER_NAME,
            REVOCATION_HIGH_WATER_INSTALL_NAME,
            offered.stored,
            max_bytes=MAX_REVOCATION_SNAPSHOT_BYTES,
            prefix=_REVOCATION_PREFIX,
        )
        held = offered
    state.held = held


def _revocation_gate(run: StaticEpochRun, root: _StateRoot, *, evaluation_epoch: int) -> str | None:
    """Offer this run's snapshot; ``None`` only when a fresh high water is held."""

    state = run.revocation
    if state is None:
        return None
    path = run.config.revocation_snapshot
    if path is not None:
        try:
            offered_bytes = _load_unpinned_file(
                path,
                label="static_revocation_snapshot",
                max_bytes=MAX_REVOCATION_SNAPSHOT_BYTES,
            )
            offered = verify_static_site_release_revocation(offered_bytes, state.policy)
            # A future-dated snapshot would hold back every later issuance.
            if (
                revocation_freshness(
                    offered,
                    now_epoch=evaluation_epoch,
                    max_age_seconds=MAX_MAX_AGE_SECONDS,
                )
                == "revocation_issued_in_future"
            ):
                return "static_revocation_issued_in_future"
            _install_revocation_high_water(root, state, offered)
        except AssignmentProbeCLIError as exc:
            if exc.code == "static_revocation_snapshot_unavailable":
                return exc.code
            raise
        except StaticRevocationError as exc:
            return f"static_{exc.code}"
    if state.held is None:
        return "static_revocation_unavailable"
    stale = revocation_freshness(
        state.held,
        now_epoch=evaluation_epoch,
        max_age_seconds=run.config.revocation_max_age_seconds,
    )
    return None if stale is None else f"static_{stale}"


def _load_release_policy(value: InputFile) -> StaticSiteReleaseTrustPolicy:
    rendered = _load_file_bytes(
        value, label="static_release_trust_policy", max_bytes=MAX_RELEASE_TRUST_POLICY_BYTES
    )
    try:
        return parse_static_site_release_trust_policy(rendered)
    except (TypeError, ValueError, ValidationError, RecursionError) as exc:
        raise AssignmentProbeCLIError("static_release_trust_policy_invalid") from exc


def _load_v3_publication(
    config: StaticSitesConfig, transport: ProbeTransport, timeout_seconds: float
) -> tuple[ActiveAssignmentManifestV3, tuple[AssignmentManifestSignatureEnvelope, ...]]:
    if config.manifest.file is not None:
        rendered = _load_file_bytes(
            config.manifest.file, label="static_manifest", max_bytes=MAX_DOCUMENT_BYTES
        )
    else:
        rendered = _fetch_document(
            transport,
            cast(str, config.manifest.url),
            max_bytes=MAX_FETCH_BYTES,
            timeout_seconds=timeout_seconds,
            code="static_manifest",
        )
    try:
        manifest = parse_assignment_manifest_v3(rendered)
    except (TypeError, ValueError, ValidationError, RecursionError) as exc:
        raise AssignmentProbeCLIError("static_manifest_invalid") from exc
    if not 1 <= len(config.signatures) <= MAX_KEYS:
        _fail("static_signature_count_invalid")
    envelopes: list[AssignmentManifestSignatureEnvelope] = []
    for index, source in enumerate(config.signatures):
        if source.file is not None:
            document = _load_file_bytes(
                source.file,
                label=f"static_manifest_signature_{index:02d}",
                max_bytes=MAX_SIGNATURE_BYTES,
            )
        else:
            document = _fetch_document(
                transport,
                cast(str, source.url),
                max_bytes=MAX_SIGNATURE_BYTES,
                timeout_seconds=timeout_seconds,
                code="static_signature",
            )
        try:
            envelopes.append(parse_assignment_manifest_signature_envelope(document))
        except (TypeError, ValueError, ValidationError, RecursionError) as exc:
            raise AssignmentProbeCLIError("static_signature_invalid") from exc
    signer_ids = [item.signer_key_id for item in envelopes]
    if len(signer_ids) != len(set(signer_ids)):
        _fail("static_signature_set_noncanonical")
    return manifest, tuple(sorted(envelopes, key=lambda item: item.signer_key_id))


def preflight_static(
    config: StaticSitesConfig,
    *,
    organic_state_root: str | None = None,
    organic_inputs: set[str] | None = None,
) -> tuple[StaticSiteReleaseTrustPolicy, str, str]:
    """Refuse an unsafe or aliased static configuration before anything is probed."""

    server_digest = _pinned_digest(config.server_implementation_digest)
    _check_revocation_options(config)
    index_origin = _validated_https_url(config.index_origin, code="static_index_origin_invalid")
    index_origin = index_origin.rstrip("/")
    static_root = _normalized_absolute_path(config.state_root, code="state_root_path_unsafe")
    if organic_state_root is not None and (
        static_root == organic_state_root
        or static_root.startswith(organic_state_root + "/")
        or organic_state_root.startswith(static_root + "/")
    ):
        _fail("static_state_root_alias")
    inputs = (organic_inputs or set()) | static_input_paths(config)
    for path in (config.epoch_output, config.journal):
        normalized = _normalized_absolute_path(path, code="output_path_unsafe")
        if normalized in inputs:
            _fail("output_path_alias")
        for root in (
            (static_root,) if organic_state_root is None else (organic_state_root, static_root)
        ):
            if normalized == root or normalized.startswith(root + "/"):
                _fail("output_path_unsafe")
    if _normalized_absolute_path(config.epoch_output, code="output_path_unsafe") == (
        _normalized_absolute_path(config.journal, code="output_path_unsafe")
    ):
        _fail("output_path_alias")
    return _load_release_policy(config.release_trust_policy), server_digest, index_origin


def lock_static_epoch(
    config: StaticSitesConfig, policy: AssignmentManifestTrustPolicy
) -> StaticEpochRun:
    """Take the static state root lock, preflight the output and open the journal.

    Runs before the organic manifest is loaded, so a busy or unsafe static
    root, stale anchor, unsafe output, or unsafe or tampered journal refuses
    the whole run before any state advances or any probe is sent.
    """

    root = _StateRoot(config.state_root)
    run = StaticEpochRun(config=config, root=root)
    try:
        _preflight_output(config.epoch_output, state_root=root.path)
        run.journal = _open_journal(config.journal)
        run.prior_state = _resolve_prior_state(
            root, policy, config.trusted_state_anchor, ignored=REVOCATION_STATE_ENTRIES
        )
        run.revocation = _lock_revocation(root, config, policy)
    except BaseException:
        run.close()
        raise
    return run


def load_static_epoch(
    run: StaticEpochRun,
    *,
    transport: ProbeTransport,
    policy: AssignmentManifestTrustPolicy,
    release_policy: StaticSiteReleaseTrustPolicy,
    server_digest: str,
    index_origin: str,
    epoch_index: int,
    evaluation_epoch: int,
    current_finalized_height: int,
) -> None:
    """Verify v3, archive, advance the v3 state, and authenticate bounded indexes.

    A stale anchor or unsafe archive of the validator's own state refuses the
    run. An unavailable or unverifiable v3 publication only makes the static
    path abstain for this epoch; an unavailable or invalid index only makes
    its deployment abstain.
    """

    config = run.config
    root = cast(_StateRoot, run.root)
    prior = run.prior_state
    if prior is None:
        _fail("static_state_unavailable")
    try:
        manifest, signatures = _load_v3_publication(
            config, transport, policy.probe_timeout_millis / 1000
        )
        verify = (
            anchor_assignment_manifest_v3_chain_state
            if config.trusted_state_anchor == "genesis"
            else verify_assignment_manifest_v3
        )
        verification = verify(
            manifest,
            signatures,
            policy,
            prior,
            evaluation_epoch=evaluation_epoch,
            current_finalized_height=current_finalized_height,
        )
    except AssignmentProbeError as exc:
        run.abstained_code = f"static_{exc.code}"[:64]
        return
    except AssignmentProbeCLIError as exc:
        if not exc.code.startswith("static_"):
            raise
        run.abstained_code = exc.code
        return
    except (TypeError, ValueError, ValidationError, RecursionError):
        run.abstained_code = "static_manifest_invalid"
        return
    _archive_document(
        config.manifest_archive_dir,
        verification.manifest.manifest_digest_sha256,
        assignment_manifest_v3_bytes(verification.manifest),
        state_root=root.path,
    )
    if not verification.reprobe:
        root.replace_state(assignment_manifest_chain_state_bytes(verification.next_chain_state))
    revocation_code = _revocation_gate(run, root, evaluation_epoch=evaluation_epoch)
    if revocation_code is not None:
        run.abstained_code = revocation_code
        return
    run.verification = verification
    held = run.revocation.held if run.revocation is not None else None
    server_name = urlsplit(index_origin).hostname or ""
    deadline = time.monotonic() + STATIC_INDEX_LOAD_BUDGET_SECONDS
    targets = static_deployment_targets(verification)
    # A fixed prefix lets slow low-ID indexes consume the budget forever.
    # Rotate the first opportunity each epoch; scoring still uses the
    # manifest's canonical target order in finish_static_epoch.
    start = epoch_index % len(targets) if targets else 0
    for target in targets[start:] + targets[:start]:
        if held is not None and held.release_revoked(target.release_digest):
            run.abstentions.append(
                StaticIndexAbstention(target.deployment_id, target.site_digest, "release_revoked")
            )
            continue
        if time.monotonic() >= deadline:
            run.abstentions.append(
                StaticIndexAbstention(target.deployment_id, target.site_digest, "index_unavailable")
            )
            continue
        manifest_bytes, release_bytes = fetch_static_index_documents(
            transport,
            target,
            index_origin=index_origin,
            server_name=server_name,
            deadline=deadline,
        )
        result = ingest_static_index(
            target,
            manifest_bytes,
            release_bytes,
            release_policy,
            pinned_server_implementation_digest=server_digest,
        )
        if isinstance(result, VerifiedStaticIndex) and (
            held is None or not static_index_revoked(held, result, release_policy)
        ):
            run.indexes.append(result)
        elif isinstance(result, VerifiedStaticIndex):
            run.abstentions.append(
                StaticIndexAbstention(target.deployment_id, target.site_digest, "release_revoked")
            )
        else:
            run.abstentions.append(result)


def _open_journal(path: str) -> StaticEvidenceJournal:
    normalized = _normalized_absolute_path(path, code="static_journal_unsafe")
    try:
        return StaticEvidenceJournal(normalized)
    except OSError as exc:
        raise AssignmentProbeCLIError("static_journal_unsafe") from exc
    except ValueError as exc:
        code = str(exc)
        raise AssignmentProbeCLIError(
            code if code.startswith("static_evidence_") else "static_journal_invalid"
        ) from exc


def abstain_static_epoch(run: StaticEpochRun, exc: Exception) -> None:
    """Keep a static-only runtime fault from invalidating an organic record.

    The journal may contain partial static evidence, but no partial static
    score is published. The error code is intentionally bounded and contains
    no exception message or index-origin data.
    """

    code = getattr(exc, "code", None)
    run.abstained_code = (
        (code if code.startswith("static_") else f"static_{code}")[:64]
        if isinstance(code, str) and code
        else "static_internal_error"
    )
    run.verification = None


def static_probe_ceiling(policy: AssignmentManifestTrustPolicy) -> int:
    return min(policy.max_response_bytes, HIDDEN_PROBE_CEILING_BYTES)


def static_probe_schedule(
    run: StaticEpochRun,
    transport: ProbeTransport,
    policy: AssignmentManifestTrustPolicy,
    *,
    seed: bytes,
    validator_hotkey: str,
    sign: Callable[[bytes], bytes],
    epoch_index: int,
    edge_origin: str | None,
) -> list[ScheduledProbe]:
    """The static hidden schedule; each fired probe is journaled before it is kept."""

    if run.verification is None or not run.indexes:
        return []
    manifest = run.verification.manifest
    ceiling = static_probe_ceiling(policy)
    plan = plan_static_hidden_probes(
        seed=seed,
        validator_hotkey=validator_hotkey,
        indexes=run.indexes,
        epoch_index=epoch_index,
        horizon_start_epoch=manifest.issued_at_epoch,
        horizon_end_epoch=organic_manifest_effective_expires_at_epoch(manifest),
        ceiling_bytes=ceiling,
    )
    by_deployment = {index.target.deployment_id: index for index in run.indexes}
    journal = run.journal
    if journal is None:
        _fail("static_journal_unsafe")

    def firing(index: VerifiedStaticIndex, planned: PlannedStaticProbe) -> Callable[[int], None]:
        def fire(now_millis: int) -> None:
            observation = send_static_probe(
                index,
                planned,
                transport,
                validator_hotkey=validator_hotkey,
                sign=sign,
                issued_at_epoch=now_millis // 1_000,
                timeout_millis=policy.probe_timeout_millis,
                max_bytes=ceiling,
                probe_port=manifest.probe_port,
                edge_origin=edge_origin,
                pinned_edge_leaf_certificate_sha256=policy.pinned_edge_leaf_certificate_sha256,
                public_transport_policy=run.public_transport_policy,
            )
            journal.append(observation)
            run.observations.append(observation)

        return fire

    return [
        (cast(int, planned.fire_at_millis), firing(by_deployment[planned.deployment_id], planned))
        for planned in plan
    ]


def finish_static_epoch(
    run: StaticEpochRun, *, validator_hotkey: str, epoch_index: int, probe_ceiling: int
) -> StaticEpochScore | None:
    """Seal and write the static epoch record; ``None`` when the static path abstained."""

    if run.verification is None or run.root is None:
        return None
    epoch = score_static_epoch(
        static_deployment_targets(run.verification),
        run.indexes,
        run.abstentions,
        run.observations,
        validator_hotkey=validator_hotkey,
        epoch_index=epoch_index,
        probe_body_ceiling=probe_ceiling,
        network=run.verification.manifest.network,
        netuid=run.verification.manifest.netuid,
        public_transport_policy=run.public_transport_policy,
        release_revocation=_revocation_binding(run),
    )
    rendered = static_epoch_score_bytes(epoch)
    _write_output(run.config.epoch_output, rendered, state_root=run.root.path)
    run.epoch = epoch
    return epoch


def _revocation_binding(run: StaticEpochRun) -> tuple[str, str] | None:
    state = run.revocation
    if state is None:
        return None
    if state.held is None:  # the revocation gate abstains before any scoring
        _fail("static_revocation_unavailable")
    return state.policy.digest_sha256, state.held.snapshot_digest


def static_summary(run: StaticEpochRun) -> str:
    if run.epoch is None:
        return f"STATIC status=abstained code={run.abstained_code or 'static_abstained'}\n"
    epoch = run.epoch
    return (
        f"STATIC status={epoch.epoch_status} epoch={epoch.epoch_index} "
        f"deployments={len(epoch.targets)} index_abstentions={len(epoch.index_abstentions)} "
        f"observations={len(epoch.observations)} skipped={run.skipped} "
        f"content_faults={len(epoch.content_fault_evidence)} "
        f"quarantine={sum(1 for item in epoch.endpoint_actions if item.quarantine)} "
        f"alerts={len(epoch.alerts)}\n"
    )


def static_signature_sources(
    files: Sequence[InputFile], urls: Sequence[str]
) -> tuple[SignatureSource, ...]:
    return (
        *(SignatureSource(file=item) for item in files),
        *(SignatureSource(url=url) for url in urls),
    )
