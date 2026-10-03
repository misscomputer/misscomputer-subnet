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
4. authenticates ``static-site-v1`` deployment indexes (stored site manifest
   and signed release) within a whole-epoch fetch budget under the pinned
   static release trust policy and implementation digest; a deployment whose
   index is unfetched, unavailable or invalid abstains with its §11.2 record code;
5. interleaves the static hidden plan (seed-derived instants and paths,
   GET only within the trust policy's response ceiling, HEAD above it) with
   the organic plan in one time-ordered schedule, appending every sealed
   observation to the durable hash-chained evidence journal as it is judged;
6. seals a ``static-epoch-score`` v1 (coverage, content-fault and fraud
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
    plan_static_hidden_probes,
)
from .static_scoring import StaticEpochScore, score_static_epoch, static_epoch_score_bytes

MAX_RELEASE_TRUST_POLICY_BYTES: Final = 256 * 1_024
# A slow index origin must not keep the static-state lock across later epochs.
# Targets not fetched within this wall-clock budget abstain, never score zero.
STATIC_INDEX_LOAD_BUDGET_SECONDS: Final = 30.0
_PREFIXED_DIGEST_HEX: Final = frozenset("0123456789abcdef")


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
    return {_normalized_absolute_path(item.path, code="input_path_unsafe") for item in files}


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
    config: StaticSitesConfig, *, organic_state_root: str, organic_inputs: set[str]
) -> tuple[StaticSiteReleaseTrustPolicy, str, str]:
    """Refuse an unsafe or aliased static configuration before anything is probed."""

    server_digest = _pinned_digest(config.server_implementation_digest)
    index_origin = _validated_https_url(config.index_origin, code="static_index_origin_invalid")
    index_origin = index_origin.rstrip("/")
    static_root = _normalized_absolute_path(config.state_root, code="state_root_path_unsafe")
    if (
        static_root == organic_state_root
        or static_root.startswith(organic_state_root + "/")
        or organic_state_root.startswith(static_root + "/")
    ):
        _fail("static_state_root_alias")
    inputs = organic_inputs | static_input_paths(config)
    for path in (config.epoch_output, config.journal):
        normalized = _normalized_absolute_path(path, code="output_path_unsafe")
        if normalized in inputs:
            _fail("output_path_alias")
        for root in (organic_state_root, static_root):
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
        run.prior_state = _resolve_prior_state(root, policy, config.trusted_state_anchor)
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
    run.verification = verification
    server_name = urlsplit(index_origin).hostname or ""
    deadline = time.monotonic() + STATIC_INDEX_LOAD_BUDGET_SECONDS
    targets = static_deployment_targets(verification)
    # A fixed prefix lets slow low-ID indexes consume the budget forever.
    # Rotate the first opportunity each epoch; scoring still uses the
    # manifest's canonical target order in finish_static_epoch.
    start = epoch_index % len(targets) if targets else 0
    for target in targets[start:] + targets[:start]:
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
        if isinstance(result, VerifiedStaticIndex):
            run.indexes.append(result)
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
    )
    rendered = static_epoch_score_bytes(epoch)
    _write_output(run.config.epoch_output, rendered, state_root=run.root.path)
    run.epoch = epoch
    return epoch


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
