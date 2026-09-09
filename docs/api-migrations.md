# Public API migrations

## Contract checkpoint v1: clock-skew coherence

This release makes the checkpoint's clock-skew tolerances coherent across the
stages that apply them, and binds every evaluation-time rule to the policy
document that admitted the evidence. It contains two declared contract
compatibility events (`validator-weight-decision` v1 gains `trust_policies`;
`validator-probe-report` v1 observations gain `trust_policy_digest_sha256`;
together with the earlier `assignment-manifest-chain-state` event the
checkpoint now carries three), one new publisher-local contract
(`active-assignment-snapshot-lineage` v1), two breaking pure-API changes
(`decide_weight_submission` requires `trust_policies`;
`build_validator_probe_report` refuses an epoch, policy, or observation other
than its verification's), and one semantic relaxation plus one semantic
tightening of `active-assignment-snapshot` v1 invariants that change no schema
or golden bytes. No other contract, fixture, Go API, or CLI changes. The
supported mixed-version pairings, the coordinated pause that keeps operation
inside them, rollback order, and retention are at the end of this section.

### `validator-weight-decision` v1 gains `trust_policies` (compatibility event; breaking `decide_weight_submission`)

Live manifest verification admits a manifest whose `issued_at_epoch` leads the
validator's `evaluation_epoch` by at most the trust policy's
`max_future_skew_seconds`, so a verified probe report may precede its
manifest's issuance by that much, and the bound may differ between manifests
verified under different policies across a rotation inside one window.
`decide_weight_submission` previously bound each report to its manifest with an
undocumented zero tolerance (`manifest.issued_at_epoch <=
report.evaluation_epoch`), refusing such rounds as `decision_round_invalid`,
and never checked the terminal manifest's issuance against its evaluation
instant at all. The decision now binds every time bound to the verifying
policy document:

- `decide_weight_submission` requires the keyword argument `trust_policies`
  (**breaking**): the approved `assignment-manifest-trust-policy` documents the
  coordinator verified the window's manifests under. Each must re-validate,
  be unique by digest, and name the registered set's network and netuid and
  one central authority (`decision_trust_policy_invalid`, at most 16). Every
  window, archived, and terminal manifest must name one of them by
  `trust_policy_digest_sha256` (`decision_trust_policy_missing`).
- A round is admitted only if `manifest.issued_at_epoch <=
  report.evaluation_epoch + policy.max_future_skew_seconds` for that
  manifest's policy and the report's `probe_timeout_millis` and
  `max_response_bytes` are that policy's scalars (`decision_round_invalid`).
  A verified terminal manifest must satisfy `issued_at_epoch <=
  terminal_evaluated_at_epoch + policy.max_future_skew_seconds` for its policy
  (`decision_terminal_future`), exactly as live verification at that instant
  requires.
- Beyond the skew, every report and the terminal are re-admitted under their
  manifest's policy with the new pure helper
  `assignment_probe.verify_manifest_policy_admission(manifest, policy,
  evaluation_epoch=...)`: everything `verify_active_assignment_manifest`
  requires that depends only on the manifest, the policy, and the instant
  (policy-digest, network, authority, scheme, and route-suffix binding; the
  policy valid at the instant; the manifest inside the policy interval and
  lifetime; future skew; staleness), and every observation must satisfy
  `assignment_probe.verify_observation_policy_binding(observation, policy)`
  (every response-derived outcome inside the policy's whole-request budget,
  `latency_millis <= probe_timeout_millis`; a pinned certificate when the
  policy pins; `response_bytes` within `max_response_bytes`; a
  `tls_pin_mismatch` only under a policy that pins and against a recorded leaf
  outside its pins, so a mismatch judged under a stricter policy cannot be
  carried into a report naming a looser one; each judged on the outcomes and
  failure codes that could only follow that check, in both directions). Producer codes:
  `decision_round_policy_rejected`, `decision_terminal_policy_rejected`; parser
  codes: `report_policy_rejected`, `terminal_policy_rejected`. Signatures,
  block leases, and the effective horizon are not re-derived: the first two
  are live-only, the horizon is the decision's own rule.
- The record gains `trust_policies`: exactly the policy documents its sealed
  manifests name, sorted by digest. Parsing re-validates each document
  (digests and key material), requires the canonical order and the exact set
  (`trust_policies_not_canonical`, `trust_policies_not_derived`), requires them
  to match the record's network, netuid, and the manifests' authority
  (`trust_policy_authority_mismatch`), and re-applies each manifest's own bound
  to every embedded report (`scoring_window_evidence_inconsistent`) and to the
  terminal (`terminal_manifest_future`).
- `WeightDecisionPolicy` carries no clock-skew field; there is no
  decision-local or default bound.
- The `validator-weight-decision` schema (now embedding the trust-policy
  definition), its golden fixture, and every negative fixture under
  `contracts/negative/validator-weight-decision.v1/` are re-pinned. The golden
  window seals one policy (5s) and probes manifest 2 once 5s before its
  issuance. New negatives: `submit-with-report-preceding-manifest-beyond-skew`
  (that report resealed one second earlier, with the scoring window and record
  resealed), `submit-with-terminal-issued-beyond-skew` (a terminal issued 6s
  after the close, legitimately produced at close+1, evaluation instant
  rewritten to the close), `submit-with-terminal-before-policy-validity` (a
  terminal under a successor policy valid from close+5, produced at close+5,
  evaluation instant rewritten to the close),
  `submit-with-report-probe-bounds-not-policy`,
  `submit-with-observation-oversized-for-policy`,
  `submit-without-verifying-trust-policy`. A record sealed before this release
  lacks `trust_policies`: its canonical document, and therefore
  `decision_digest_sha256`, no longer matches, so it does not parse and must be
  archived with its original reader; old-report reprocessing is unsupported
  in this release (see Retention and reprocessing).

### `validator-probe-report` v1: observations seal their evaluation policy (compatibility event)

Every `ProbeObservation` gains `trust_policy_digest_sha256`: the digest of the
trust policy whose bounds (request budget, certificate pins, response ceiling)
`evaluate_probe_response` judged it under. `build_validator_probe_report`,
`verify_observation_policy_binding`, the standalone report parser, scorer,
decision producer, and decision parser require it to equal the policy the report names, so an observation can
never be relabelled under a looser or stricter policy than the one that made
it: the same 101ms response is a `timeout` under a 100ms budget and `serving`
under 5000ms, and neither observation is admissible under the other policy.
A foreign digest is `observation_policy_violation` during model validation
(and the existing `document_invalid` wrapper during byte parsing),
`scoring_round_invalid` at standalone scoring, and `decision_round_invalid`
at the decision producer's report-validation boundary. Policy-bound semantic
violations on otherwise well-formed reports keep their existing codes.
An oversized verdict now also preserves the size evidence the transport judged
(`ProbeTransportFailure.response_bytes`: the declared `Content-Length`, or the
bytes received before the ceiling was crossed, capped at
`MAX_RESPONSE_BYTES_CEILING + 1`), and `response_oversized` is admissible only
with `response_bytes` above the named policy's `max_response_bytes`. The
`validator-probe-report` schema and golden fixture, and every decision fixture
that embeds reports, are re-pinned; a report sealed before this release lacks
the field and does not parse (`additionalProperties: false`, digest). No
validator is live on the previous form; the probe CLI emits the new form.

### Report construction is bound to its verification (breaking)

`ManifestVerificationResult` gains `evaluation_epoch` and
`trust_policy_digest_sha256`: the instant and policy the freshness, skew,
signer-validity, and chain rules were applied at and under (live, historical,
and anchor verification all record them). Historical verification additionally
sets `reportable=False`; the report builder refuses it with
`historical_verification_not_reportable`, and anchor propagation preserves the
mode. Even a caller-constructed live result is rechecked for freshness and
effective expiry before report production. `build_validator_probe_report`
refuses an `evaluation_epoch` other than the verification's
(`report_evaluation_epoch_mismatch`, new `ProbeRejectionCode`), a
`trust_policy` whose digest differs from the verification's or from the
manifest's `trust_policy_digest_sha256` (`trust_policy_mismatch`), and any
observation that `evaluate_probe_response` could not have produced under that
policy (`observation_policy_violation`, new `ProbeRejectionCode`): responses
judged under a same-authority policy with a longer request budget, without
certificate pins, or with a larger body ceiling cannot be relabelled as serving
under the stricter policy that verified the manifest. A report can therefore never claim an evaluation
instant, a clock skew, or a serving verdict that its verification did not
admit. The `misscomputer-assignment-probe` CLI already passes the same epoch
and policy to every call and is unaffected.

### `misscomputer-assignment-probe` transport: one whole-request budget (behavioural)

`HttpsProbeTransport` now enforces the policy's `probe_timeout_millis` as one
absolute whole-request budget on one monotonic clock (`RequestBudget`), in two
layers. httpx's per-operation timeouts only cap each read or write, so a peer
trickling header or body bytes just inside them could hold a request open
indefinitely; the connection therefore runs on `DeadlineNetworkBackend` (new
module `misscomputer_subnet.probe_transport`), an httpcore network backend
that owns name resolution, address dialling, the TLS handshake, and every
socket read and write and bounds each by the time remaining in the budget:
`getaddrinfo` runs on a helper thread that the caller waits on for exactly the
remaining budget and then abandons (it cannot be cancelled and holds no file
descriptor); helper threads come from a process-wide pool of
`MAX_OUTSTANDING_RESOLUTIONS` (16) slots with no queue, so however many
lookups are blocked at once, at most that many threads exist and a request
that finds no free slot fails fast with a connection error instead of waiting
(the slot is released when the lookup itself returns). Setup objects are
allocated before admission; a locked lease transfers creator ownership to the
worker, so cancellation before claim prevents lookup execution and cancellation
after claim cannot release the worker's slot. SIGINT is deferred only across
lease accounting, not DNS or waits, closing the acquire/record interruption
window. Fork children reset the default process pool because parent workers
no longer exist there. Signaling failure still releases
the completed lookup's slot. Remaining time is recomputed after setup/start and
immediately before waiting; unavoidable scheduler/startup delays are not
followed by another stale-budget wait; each resolved address
is dialled with the budget remaining at
that instant so three unreachable addresses cost one budget rather than three,
every `send` of a partial write re-derives the remaining budget, and every
read is clamped the same way. A slow trickle anywhere in the request ends
within a small margin of the budget as `ProbeTransportFailure("timeout")`. No
socket is ever closed from another thread, so a stale read can never consume a
reused file descriptor. The probe CLI module itself imports no socket
primitives; the transport module is the only place that opens connections, it
does so only under the caller's `ssl.SSLContext`, and a guard test pins its
import surface. The transport also measures the elapsed time
immediately before it inspects the response headers, before every
response-derived return (`Content-Length` rejection, body rejection, and the
response itself), and at every body chunk, and anything that would complete
after the budget is reported as a timeout too. A wire status outside the
contract's `100..599` (httpx accepts up to 999) is reported as
`ProbeTransportFailure("transport_error")` with no recorded status, and
`evaluate_probe_response` maps such a `ProbeResponse` the same way instead of
raising a `ValidationError`. Exact boundary: latency is whole-request elapsed time in
floor milliseconds; a response-derived outcome with `latency_millis` equal to
the budget is a response, one millisecond more is a timeout, mirroring
`verify_observation_policy_binding`. Previously a response whose headers
arrived after the budget but inside every per-phase timeout was reported as a
response (for example `unexpected_status` or `response_oversized` at 101ms on a
100ms budget), which the new report builder, decision, and parser refuse.
`HttpsProbeTransport(ssl_context, *, clock=time.monotonic,
transport_factory=None)` gains two keyword-only injection points for
deterministic tests; the CLI is otherwise unchanged. Old CLIs remain able to
emit response-derived observations beyond the budget, which a new coordinator
refuses (see the pairing matrix below).

### `active-assignment-snapshot-lineage` v1 (new, publisher-local)

`assignment_snapshot` gains `SnapshotLineage`, `ReplicaLineage`,
`build_initial_snapshot_lineage`, `advance_snapshot_lineage`,
`snapshot_lineage_bytes`, and `parse_snapshot_lineage`, with schema, golden
fixture (genesis advanced over the golden capture and its signer-skew
successor), and negative fixtures under `contracts/negative/`. The lineage is
the durable form of snapshot succession: it carries the last accepted
capture's transactional position and the latest accepted incarnation of every
`replica_id` ever exported (generation, nonce, endpoint, ticket and receipt
digests, replica-document digest, ticket-bound deployment-facts digest) and
every assignment nonce, ticket digest, and receipt digest ever accepted for
any incarnation (`used_assignment_nonces`, `used_ticket_digests`,
`used_receipt_digests`, sorted and unique; the current incarnations' facts are
among them, `lineage_used_facts_not_canonical`/`lineage_used_facts_not_derived`
on parse). History is anchored, contiguous, and era-scoped:

- every advanced lineage names its predecessor
  (`previous_lineage_digest_sha256`; `lineage_chain_link_missing` when a
  non-genesis lineage lacks it), so persisted lineages form a hash chain, and
  `verify_snapshot_lineage_anchor(lineage,
  expected_lineage_digest_sha256=...)` refuses a restored file that is not the
  head the operator last persisted (`snapshot_lineage_anchor_mismatch`): a
  stale backup or a resealed copy with retired facts removed is digest-valid
  but not the anchored head;
- captures are accepted only in exact order: the first must be
  `history_start_snapshot_sequence` and every later one exactly
  `last_snapshot_sequence + 1` (`snapshot_lineage_gap`; a lower or equal
  sequence stays `snapshot_sequence_not_increasing`; the parser also refuses a
  lineage whose current replicas share any nonce, ticket digest, or receipt
  digest in any role, `lineage_replica_facts_duplicate`), and the parser requires
  `last_snapshot_sequence == history_start_snapshot_sequence +
  accepted_snapshot_count - 1` exactly (`lineage_history_not_contiguous`) with
  every `last_seen_snapshot_sequence` inside that range
  (`lineage_replica_seen_out_of_range`). `replay_snapshot_lineage(lineage,
  snapshots)` seeds or catches up a lineage over retained captures in order
  and refuses a gap; a missed capture is never skipped. **This tightens the
  base contract**, which allowed any strictly increasing `snapshot_sequence`:
  a legacy history with skipped values cannot be replayed across the skip.
  `snapshot_history_gaps(snapshots)` preflights a retained history: it
  enforces every base-contract invariant between adjacent captures (authority,
  network, revision, capture instant, finalized height/hash/epoch) and refuses
  a repeated or lower sequence outright (`snapshot_sequence_not_increasing`:
  a duplicate is a rollback no legacy runtime could have produced, and a
  restart after it would launder whatever the duplicate carried), then names
  every forward skip. The lineage is started with `first_snapshot_sequence`
  set to the capture after the last skip, records it as
  `history_start_snapshot_sequence`, and states that facts before it are
  outside the guarantee. Runtimes must increment `snapshot_sequence` by
  exactly one per capture from now on;
- freshness is judged across every fact role: a new incarnation's nonce,
  ticket digest, and receipt digest must each be absent from the union of
  every nonce, ticket digest, and receipt digest the lineage has accepted in
  the era, so a retired ticket digest cannot return as a receipt digest nor
  the reverse, and the parser refuses a lineage whose ticket and receipt
  histories overlap (`lineage_used_facts_overlap`);
- `snapshot_lineage_overflow` (more than `MAX_LINEAGE_REPLICAS` distinct
  `replica_id`s, more than `MAX_LINEAGE_FACTS` retained facts of one kind, or
  an `era` that would exceed `MAX_LINEAGE_ERAS`, i.e. more than
  `MAX_LINEAGE_ERAS - 1` boundaries) **refuses the capture and forgets
  nothing**. The only operation that sheds anything is
  `begin_snapshot_lineage_era(lineage, retain_for=None)`: it opens `era + 1`,
  keeps exactly the incarnations exported by the last accepted capture (each
  `ReplicaLineage` records `last_seen_snapshot_sequence`; inactive entries are
  pruned) with their facts, drops every retired fact, and records a
  `LineageEraBoundary` (era, last accepted sequence, dropped replica lineages
  and facts, digest of the lineage it was taken from, and the digest of the
  capture it was taken for, if any) that stays in the document forever.
  The parser bounds every dropped count by the corresponding maximum,
  requires a boundary that no capture followed to name the document's own
  predecessor, and refuses boundaries out of range or out of order
  (`lineage_era_invalid`). A lineage over `MAX_LINEAGE_REPLICAS` recovers at a
  boundary when it holds inactive entries; when a capture replaces every
  `replica_id` at the cap (all entries active), the plain boundary keeps them
  all and the capture still overflows, so the operator takes the boundary
  **for that capture** (`retain_for=capture`): only the active lineages the
  capture continues are kept, the boundary records the capture's digest, and
  the capture is accepted next (it never exceeds the bound by itself). The
  candidate is fully dry-run through `advance_snapshot_lineage` against
  the proposed pruned state before any state is returned (including rewritten
  incarnations, generation, reused facts, and resource limits; pass the same
  `max_facts` and `max_replicas` to boundary and advance), the commitment is enforced by the live lineage (only that exact
  capture may follow; `snapshot_lineage_candidate_mismatch`), and one boundary
  per accepted capture is allowed (`snapshot_lineage_boundary_pending`), so a
  prepared boundary can never be spent on a different capture and a boundary
  can never hide behind another at the same sequence (the parser requires
  strictly increasing `opened_after_snapshot_sequence`). Every live history is
  therefore replayable to itself. The
  never-reuse guarantee is therefore exactly: no nonce, ticket digest, or
  receipt digest accepted since `history_start_snapshot_sequence` within the
  current `era` is ever accepted again in any role, and no incarnation kept
  across the boundary is replaced without a higher generation. After an era
  boundary, facts and generations retired before it are no longer guarded,
  and the document says so; a consumer must treat `era > 1` as a re-scoped
  guarantee and may reject or flag it by policy.

Replay is complete: `replay_snapshot_lineage(lineage, snapshots,
era_boundaries=...)` replays retained captures and the recorded era
boundaries in order, taking each boundary after the capture it names and for
the candidate it recorded, and requires the replayed boundary to reproduce the
recorded one exactly (`snapshot_lineage_replay_mismatch`), so a history that
contains a boundary replays to the same lineage instead of refusing the era-2
facts the live lineage legitimately accepted. Freshness checking is linear in
the capture: the union of retained facts is built once and updated as facts
are accepted (a scale guard in the suite fails on quadratic behaviour).

Replay is **not linear in capture count**: immutable hash-chain links require
hashing growing history at each step. `MAX_REPLAY_WORK = 1_000_000` enforces a
cumulative-work ceiling per call before expensive transitions: each charge
counts one state plus retained replicas, all three fact arrays, boundaries,
and the candidate's deployment/replica entries. Candidate boundaries charge
three passes for preparation and full dry-run. `max_work` may lower but never
raise the ceiling; overflow returns `snapshot_lineage_replay_work_exceeded`
without returning a partial state. This bounds cumulative sorting/hashing work
by O(B log B) for the fixed entry cap B, rather than claiming O(captures).
Use bounded batches starting at an independently anchored persisted head for
long archives; keep all captures and boundaries, never restart genesis merely
to evade the bound. Growing-history tests cover rejection and batch equivalence.

Boundary input is explicit: `boundary_mode="full"` (default) requires the exact
current boundary prefix followed by new events; `boundary_mode="suffix"`
contains only new events, beginning with the next era. No sorting or silent
prefix dropping occurs. To resume without new boundaries, use suffix mode.
A crash head between boundary preparation and candidate acceptance is restored
by supplying the candidate as `pending_candidate=...`, not in `snapshots`:
it is fully validated but not consumed. This reproduces the pending digest
exactly; replaying with the candidate in `snapshots` intentionally advances it.
The parser requires pending heads to retain only active incarnations and exactly
their facts; dropped plus retained counts obey all caps and the equal-count
nonce/ticket/receipt invariant. As always, history claims additionally require
the independently retained anchor; a self digest is not historical proof.

New codes: `snapshot_generation_not_increasing`,
`snapshot_incarnation_facts_reused`, `snapshot_lineage_gap`,
`snapshot_lineage_overflow`, `snapshot_lineage_anchor_mismatch`,
`snapshot_lineage_replay_mismatch`, `snapshot_lineage_candidate_mismatch`,
`snapshot_lineage_boundary_pending`; parser codes `lineage_chain_link_missing`,
`lineage_history_not_contiguous`, `lineage_replica_seen_out_of_range`,
`lineage_replica_facts_duplicate`, `lineage_used_facts_overlap`,
`lineage_era_invalid`. A publisher
persists the lineage beside its manifest chain state, retains the head digest
out of band, and advances it with every accepted capture before it derives or
publishes anything from that capture. There is no Go counterpart.

### `active-assignment-snapshot` v1: incarnation immutability across captures (semantics only)

`verify_snapshot_succession` is now exactly `advance_snapshot_lineage` applied
from genesis over the two captures, and therefore adds
`snapshot_incarnation_rewritten` (a retained `endpoint_id` must carry the
identical replica document and identical ticket-bound deployment facts:
image digest, challenge digest, workload spec, campaign, build, route),
`snapshot_generation_not_increasing`, and `snapshot_incarnation_facts_reused`.
A signed ticket binds its own issuance and its assignment, so a retained ticket
digest with a restamped `ticket_issued_at_epoch`, a moved
`route_activated_at_epoch`, a changed parent fact, or a replacement that keeps
the generation, nonce, ticket, or receipt is an impossible rewrite, not a
re-assignment. The two-capture form cannot see an incarnation dropped by one
capture and rewritten by a later one, nor a fact retired two or more
replacements ago; the persisted lineage can. Schema and
golden bytes are unchanged. There is no Go counterpart: succession is a
publisher-side rule and `pkg/assignment` has no succession API.

### `active-assignment-snapshot` v1: one clock-domain rule (semantics only)

The replica invariant `route_activated_at_epoch >= ticket_issued_at_epoch`
together with `route_activated_at_epoch <= captured_at_epoch` made the
documented capture+30 ticket-issuance tolerance unreachable: no valid capture
could carry a ticket stamped after the capture instant. The contract now
names its two clocks (ticket window on the signer's clock; activation and
capture on the runtime's) and applies `TICKET_MAX_FUTURE_SKEW_SECONDS` (30)
to both cross-clock comparisons: the replica rule is
`ticket_issued_at_epoch <= route_activated_at_epoch + 30`
(`replica_activation_order_invalid`), the capture rule stays
`ticket_issued_at_epoch <= captured_at_epoch + 30`
(`snapshot_replica_ticket_issued_after_capture`), and the same-clock rule
`route_activated_at_epoch <= captured_at_epoch` stays exact. Python
(`assignment_snapshot`) and Go (`pkg/assignment`) apply the identical rule and
codes. Every previously valid snapshot remains valid; schema and golden fixture
bytes are unchanged. Added: the supplementary golden
`contracts/fixtures/active-assignment-snapshot-signer-skew.v1.json` (both
suites parse and re-seal it byte-for-byte; its replicas are fresh
generation-2 incarnations with fresh nonces, endpoints, ticket and receipt
digests, so it is a valid successor of the golden capture) and the negatives
`replica-ticket-issued-beyond-capture-skew` and
`replica-activated-before-ticket-skew`.

### Operator runbook

`public-validator-live-probe-runbook.md` lists `finalized_epoch_rollback`
beside the other rollback and fork codes in both the pre-request rejection
list and the fork/rollback/equivocation response procedure; the retention and
escalation steps are unchanged and apply to it.

### Mixed-version operation, coordinated upgrade, rollback, and retention

This release is **not** transparently mixed-version compatible for two of its
contracts, and the checkpoint's own fail-closed rules turn an incompatible
pairing into a publication or decision stop, never into a wrong weight. The
matrix below states exactly which writer/reader pairings are supported; the
procedure that follows keeps every pairing inside the supported set.

| Contract | Old writer → new reader | New writer → old reader | Consequence of an unsupported pairing |
| --- | --- | --- | --- |
| `validator-weight-decision` v1 | **unsupported**: an old coordinator seals records without `trust_policies`; the new parser refuses them (digest mismatch) | **unsupported**: the new coordinator seals `trust_policies`; the old parser refuses them (`additionalProperties: false`) | no weight plan can be built from the refused record; the validator keeps its previous weights (abstain-equivalent) until the pairing is corrected |
| `active-assignment-snapshot` v1 | **conditionally supported**: every capture an old runtime could emit that satisfied the old rules is accepted by the new publisher *except* captures that rewrite a retained incarnation or recycle retired facts (`snapshot_incarnation_rewritten`, `snapshot_generation_not_increasing`, `snapshot_incarnation_facts_reused`), which the old rules never tested; the new publisher refuses those and stops publishing | **unsupported once the new runtime uses the tolerance**: a capture whose ticket is stamped after activation within the 30s tolerance is refused by an old publisher (`replica_activation_order_invalid`); the old publisher stops publishing | the publisher fails closed; the last manifest reaches its effective horizon and every validator abstains (`manifest_expired_at_close`); no miner is zeroed, no weight moves |
| `active-assignment-snapshot-lineage` v1 | n/a (new; publisher-local) | n/a | none |
| `validator-probe-report` v1 | **unsupported**: an old CLI's observations lack `trust_policy_digest_sha256`, so the new report parser refuses the report (digest and required field) before any round can be considered | **unsupported**: a new CLI's observations carry `trust_policy_digest_sha256`, which an old parser refuses (`additionalProperties: false`) | the coordinator holds no admissible reports from the mismatched CLIs for that window and abstains (`rounds_insufficient`/`coverage_insufficient`); no wrong weight is produced |
| `active-assignment-snapshot` sequence numbering | **conditionally supported**: a legacy runtime that skipped sequence values (allowed by the base contract) produces `snapshot_lineage_gap` at the skip; preflight with `snapshot_history_gaps` and start the lineage after the last skip | supported: contiguous sequences are strictly increasing | the publisher refuses the capture after the skip until the lineage is restarted at the documented late start; validators abstain after the horizon meanwhile |
| manifests, envelopes, trust policy, pointer, weight plan | supported (bytes unchanged) | supported (bytes unchanged) | none |

There is no compatibility reader: neither parser accepts the other form, by
design (`additionalProperties: false`, self digests). Mixed-version operation
is therefore made safe by a **coordinated pause** per writer/reader pair, not
by tolerance:

1. **Decision pair (coordinator and every consumer of its records).** Pause
   the coordinator at a scoring-window boundary: let the current window close
   and its record be sealed and consumed under the *old* code, then stop the
   coordinator. Upgrade the decision consumers (parser, weight-plan builder,
   archive readers) and the coordinator together, and restart the coordinator
   at the next window boundary with its approved trust-policy documents. No
   window is sealed by one version and consumed by the other. The pause costs
   at most one window of weight submission; the chain keeps the previous
   weights meanwhile, which is the abstain outcome and is safe. A pause longer
   than the window is not an outage of the network, only of this validator's
   weight updates.
2. **Snapshot pair (runtime and publisher).** Upgrade the publisher first (it
   accepts everything a correct old runtime emits), preflight the runtime's
   retained captures with `snapshot_history_gaps`, seed its lineage by
   replaying them in order from sequence 1 (`replay_snapshot_lineage`) or,
   if the history has a skip, from the capture after the last skip (record
   `history_start_snapshot_sequence` and the head digest), then upgrade the
   runtime, within one manifest lifetime so the publisher never sits idle
   past the effective horizon. If the new publisher refuses an old runtime's
   capture with a lineage code, the runtime state is genuinely inconsistent
   (a rewritten incarnation or a recycled fact): keep the refusal and expect
   validators to abstain until publication resumes; the only sanctioned way
   past it is to repair the runtime's assignments (new generations with fresh
   tickets) or, if retired facts or inactive lineage must be forgotten, an
   explicit `begin_snapshot_lineage_era` recorded in the operator log and
   visible to every reader (it keeps only the incarnations of the last
   accepted capture). Never downgrade the publisher to make a lineage refusal
   disappear. Do not upgrade the runtime before the publisher.
3. **Probe CLIs and coordinator (report pair).** Reports are a writer/reader
   pair with no compatible direction, so they are cut over together inside the
   same coordinator pause: stop the coordinator at a window boundary, upgrade
   every probe CLI that feeds it and the coordinator itself, then restart the
   coordinator at the next window boundary. Reports sealed by old CLIs during
   the pause are not admissible under the new coordinator and are archived
   only; reports sealed by new CLIs before the coordinator restarts would be
   refused by an old coordinator, which is why the CLIs never lead. A
   validator operating its own coordinator upgrades both binaries in one step.

Rollback is **writers first**, and for snapshots it is not a binary swap:

- Coordinator and probe CLIs: stop the coordinator at a window boundary,
  downgrade every probe CLI, the coordinator, and its consumers together,
  restart. Records sealed by the new coordinator, and reports sealed by new
  CLIs, stay in the archive and are readable only by the new parsers (below).
- Runtime and publisher: downgrading the runtime binary does not drain or
  rewrite the assignments it already issued; every active incarnation whose
  ticket was stamped after its activation within the +1..+30s tolerance stays
  in the next captures until it expires or is re-issued, and an old publisher
  refuses any capture that still carries one
  (`replica_activation_order_invalid`). Before downgrading the publisher,
  either let every tolerant assignment expire or be superseded and verify that
  the runtime's current capture parses under the old rules, or re-issue those
  assignments under old-compatible timing (ticket stamped at or before
  activation) and verify the capture the same way. Only then downgrade the
  runtime and, last, the publisher.
- Lineage: after any rollback and re-upgrade, or after any gap in the
  publisher's operation, replay the retained captures from the lineage's next
  expected sequence before accepting new ones; a gap is refused
  (`snapshot_lineage_gap`), so the lineage cannot silently resume with a hole.
- Never roll back a reader while a writer of the new form is running.

Archive readers: base readers refuse every decision that carries
`trust_policies` and every report whose observations carry
`trust_policy_digest_sha256`; new readers refuse every decision and report
without them. Any archive that spans the upgrade therefore needs either a
dual-version reader (dispatch on the presence of those fields to the matching
parser, never a lenient one) or segregated archives per form; a single-version
reader over a mixed archive is unsupported. This release ships no
compatibility reader: the field is required in both directions so that no
reader ever admits an observation whose judging policy is unknown.

Retention and reprocessing:

- Retain every sealed decision, capture, report, trust policy, and lineage as
  produced; never rewrite an archived document. Old-form and new-form
  decisions coexist in the archive and are told apart by the presence of
  `trust_policies`.
- A decision sealed before this release does not parse under the new rules.
  **Reprocessing retained old-form reports with the new decision API is
  unsupported.** No old/dual reader or validated converter ships here; adding
  a policy digest and resealing cannot prove which policy judged an old probe.
  Retain original bytes and their compatible archived reader in a segregated
  offline archive. A future conversion requires a separately reviewed policy
  and provenance validation; do not feed converted or historical evidence into
  live report production. Live weight submission never depends on conversion.
- A publisher adopting the lineage seeds it by replaying every retained
  capture in order from the runtime's first sequence
  (`replay_snapshot_lineage`); the lineage then remembers every fact those
  captures carried. If retained history starts later, genesis is built with
  that `first_snapshot_sequence`, the document records it as
  `history_start_snapshot_sequence`, and facts before it are outside the
  guarantee: the document states the scope, the operator log states why.
- Persist the advanced lineage (write-ahead, fsync, atomic replace) before
  deriving or publishing a manifest from the capture that advanced it, hold a
  single writer lock on the lineage file, and compare the on-disk head digest
  with the retained anchor before every advance and after every restore
  (`verify_snapshot_lineage_anchor`); a mismatch is a stale or altered
  lineage and publication must stop until the true head is restored or the
  captures are replayed from a known-good head.
- A lineage past `MAX_LINEAGE_REPLICAS` or `MAX_LINEAGE_FACTS` refuses every
  capture (`snapshot_lineage_overflow`) and forgets nothing. The operator may
  open a new era (`begin_snapshot_lineage_era`), which keeps only the
  incarnations of the last accepted capture with their facts, prunes inactive
  lineage, and records the boundary in the document; for a capture that
  replaces every `replica_id` at the cap the boundary is taken for that
  capture (`retain_for`), so the lifecycle at the cap is: refusal, boundary
  taken for the refused capture, acceptance. A lineage already at
  `era == MAX_LINEAGE_ERAS` (64 eras, 63 boundaries) cannot open another and
  is terminal: the operator starts a new lineage from genesis over the
  runtime's retained captures **and the recorded era boundaries**
  (`replay_snapshot_lineage(..., era_boundaries=...)`), which reproduces the
  live lineage exactly if the history is complete, or, when the retained
  history is not complete, a new document with its own history start whose
  scope the operator records; there is no silent re-anchor and no continuation
  that pretends to remember.

Outage prevention checklist: pause the coordinator only at a window boundary;
finish each writer/reader pair within one manifest lifetime; verify the
publisher accepts the runtime's first post-upgrade capture before the previous
manifest's effective horizon; keep the old binaries available for the
writers-first rollback; and treat any `manifest_expired_at_close` abstention
during the window as the intended safe outcome, not as data loss.

## Contract checkpoint v1

This release adds three versioned contracts and their pure verification code;
see [`contract-checkpoint-v1.md`](contract-checkpoint-v1.md). It contains one
declared contract compatibility event, makes the block-lease check mandatory
for every live manifest consumer (a breaking signature change for
`verify_active_assignment_manifest`, `anchor_manifest_chain_state`, the
`verify_manifest` boundary operation, and the `misscomputer-assignment-probe`
CLI), and otherwise leaves every existing contract, schema, fixture, and Go
API unchanged.

### `assignment-manifest-chain-state` v1 gains `last_finalized_epoch` (breaking)

The append-only chain state now carries the finalized epoch of the last
accepted manifest beside its height and block hash, so that a publication
whose finalized epoch goes backwards, or that pairs one finalized height with
two epochs, is rejected (`finalized_epoch_rollback`, `same_height_fork`). The
field is `null` exactly at genesis. Canonical chain-state bytes and their
digests change; a chain-state document persisted before this release does not
parse and must be re-anchored (re-created from genesis and caught up, or
anchored on the live head; see the checkpoint document). No validator is live
on the previous form. The `assignment-manifest-chain-state` schema and fixture,
and the `validator-probe-report` fixture that embeds a chain-state digest, are
re-pinned at their new bytes; the probe-report *schema* is unchanged.

### Manifest verification

- Manifest validity is bounded by the effective horizon
  `min(expires_at_epoch, min(ticket_expires_at_epoch))`; a manifest whose
  tickets have all expired is `manifest_expired` even if `expires_at_epoch`
  lies ahead.
- `verify_active_assignment_manifest` requires the keyword argument
  `current_finalized_height` (**breaking**): every replica's `expires_at_block`
  is enforced against it (`manifest_replica_lease_expired`), and an invalid
  value is `current_finalized_height_invalid`. A caller that cannot state its
  finalized height cannot verify live; there is no opt-out. Historical
  verification (`verify_historical_active_assignment_manifest`,
  `replay_manifest_history`) is unchanged and lease-free, because superseded
  manifests are never probed. `anchor_manifest_chain_state` requires the same
  argument.
- `misscomputer-assignment-probe` requires `--finalized-height`
  (**breaking**); `AssignmentProbeCLIConfig` gains the required field
  `current_finalized_height`, validated like `evaluation_epoch`
  (`operator_context_invalid`).
- New pure helpers: `manifest_effective_expires_at_epoch`,
  `manifest_earliest_lease_expires_at_block`, `verify_manifest_block_leases`,
  `verify_pointer_signer_set`, and
  `verify_historical_active_assignment_manifest` (catch-up semantics).

### Publication and latest pointer

- `assignment-manifest-latest-pointer` v1 carries `finalized_epoch`.
- `bind_latest_pointer_to_manifest(pointer, manifest, signatures)` now takes
  the fetched envelopes and requires them to be exactly the pointer's signer
  set (`pointer_signature_mismatch`).
- `verify_manifest_latest_pointer` checks the claimed signer set against key
  validity windows, revocations, threshold, and required roles
  (`pointer_signer_invalid`, `pointer_required_role_missing`) and mirrors the
  chain-view rules. Its verdict gains `history_depth`, which is zero for a
  direct digest link and otherwise is the maximum number of immutable history
  entries to walk, not a count inferred from possibly jumping sequence values.
- New: `pointer_object_key`, `ManifestHistoryEntry`,
  `replay_manifest_history` (catch-up), and `anchor_manifest_chain_state`
  (onboarding).

### Validator decision and weight plan

- `validator-weight-decision` v1 gains `terminal_finalized_block_hash`,
  `terminal_finalized_epoch`, `terminal_manifest_effective_expires_at_epoch`,
  `terminal_earliest_lease_expires_at_block`, `prior_assigned_baseline`,
  `prior_assigned_baseline_status`, `assigned_baseline`, the row field
  `assigned_at_close`, the row aggregation `replica_share_counts`, the policy
  field `assigned_baseline_max_age_seconds`, and the abstain reason
  `assignment_lease_expired_at_close`. Parsing re-derives every abstain reason
  and row classification from the sealed fields.
- The decision now embeds a canonical `scoring_window` and ordered
  `assignment_manifest_evidence` entries containing each unique full manifest
  and the exact sorted full reports that probed it. Parsing reconstructs the
  probe rounds and recomputes the scoring-window digest, report partition,
  observation count, serving attributions and latency, per-identity
  opportunities and replica-share buckets, terminal registered identity set,
  maximum assigned count, mass-drop guard, and successor baseline. Baselines
  now carry their canonical assigned-identity list; count and identity digest
  are derived from it.
- Parsing also enforces sealed serving evidence: a positive row needs at least
  `scoring_policy.min_attributions` attributions, no more attributions than
  opportunities, no more opportunities than the record's `observation_count`,
  no more rounds than observations, row attributions summing to at most
  `serving_observation_count`, and an exact reduced expected-attribution
  fraction recomputed from the row's canonical `replica_share_counts` buckets.
  Positive weights form one normalized distribution
  (`row_positive_weight_without_evidence`, `row_weight_below_min_attributions`,
  `row_attributions_exceed_opportunities`,
  `row_expected_attributions_inconsistent`, `observation_counts_invalid`,
  `weights_not_normalized`).
- Parsing derives each registered identity's earliest sealed manifest sighting
  and rejects a non-`unassigned` row whose `first_seen_epoch` is absent or later
  (`row_first_seen_not_derived`). An earlier sighting supplied from the
  coordinator's archive remains valid. The producer records sightings per
  exact `(uid, hotkey)` identity rather than per endpoint owner, so an
  endpoint republished under a new UID never leaves the identity that earned
  weight without a sighting. Archived sightings are supplied through
  `identity_first_seen_epoch`, keyed by exact `(uid, hotkey)`; each entry
  moves only that identity (it must not post-date the identity's earliest
  in-chain publication, `decision_first_seen_after_sighting`, and is ignored
  for an identity the chain never publishes), so the old UID's archive never
  pulls a republished new UID out of activation grace. The former
  endpoint-keyed `endpoint_first_seen_epoch` input is removed.
- Assigned sets are counted in registered identities only:
  `terminal_assigned_miner_count` must equal the rows sealed
  `assigned_at_close` (`assigned_counts_invalid`), and the successor
  `assigned_baseline` identity digest is always checked. A record whose
  `mass_unassignment_guard` fired must carry the largest set (the applied prior
  baseline, or a manifest of the window at a sequence below the terminal)
  rather than the reduced terminal set (`assigned_baseline_not_derived`).
  On an unavailable or rejected terminal fetch, the largest verified
  in-window set is carried unless an applied prior is strictly larger; this
  also applies to first windows and expired priors.
- `decide_weight_submission` accepts `prior_assigned_baseline` and
  `archived_manifests`. The window's manifests, the archived manifests, and
  the terminal must include every actual digest-linked transition; bounded
  sequence jumps do not imply intermediate publications. A missing actual
  predecessor is `decision_manifest_chain_gap`,
  an archived manifest that does not re-validate or lies beyond the terminal
  is `decision_archived_manifest_invalid`.
- `weight_plan.build_weight_plan_from_decision` is the only path from a
  decision to a plan; `build_weight_plan` itself is unchanged. The decision's
  rows must be exactly `weight_plan.eligible_weight_targets(snapshot,
  validator_hotkey)` (every active neuron other than the validator), so a
  decision that omits an eligible miner is refused. The builder deep-validates
  once into a private decision and immutable row snapshot, so concurrent
  mutation of a caller-owned nested row list cannot split these checks.
- `probe_scoring.accumulate_scoring_window` re-validates every round
  (`scoring_round_invalid`).
- `assignment_snapshot.verify_snapshot_succession` adds
  `snapshot_finalized_epoch_rollback` and treats a second epoch at one height
  as `snapshot_finalized_fork`.

### `misscomputer-checkpoint-boundary`

Protocol `misscomputer.checkpoint-boundary.v1` gains the operations
`build_snapshot_replica`, `build_snapshot_deployment`,
`build_assignment_snapshot`, `project_snapshot_deployments`,
`verify_snapshot_succession`, `verify_manifest_derived_from_snapshot`,
`build_manifest_latest_pointer`, `verify_manifest_latest_pointer`,
`bind_latest_pointer_to_manifest` (arguments `pointer`, `manifest`,
`signatures`), and `rebind_manifest_state_trust_policy`, and the `validate`
operation accepts the models `active_assignment_snapshot` and
`assignment_manifest_latest_pointer`. The `verify_manifest_latest_pointer`
response carries `history_depth`. The `verify_manifest` operation requires the
argument `current_finalized_height` (**breaking**; a request without it is
rejected with `current_finalized_height_required`, and the manifest's block
leases are enforced against it). Every other pre-existing operation, argument,
and response shape is unchanged; chain-state documents a producer exchanges
follow the compatibility event above.

### Go `pkg/assignment`

New package; no existing Go package changed. `Seal`, `Parse`, `Marshal`,
`Project`, `Validate`, and `CanonicalJSON` are the only exported functions.

### `contracts/negative/`

New directory convention for golden invalid documents. It is not read by
`schema_inventory` and does not affect the public contract inventory digest
of `contracts/fixtures` and `contracts/schemas`.

No migration exports the hidden challenge, changes validator scoring, submits
weights, or introduces multi-validator coordination.

## Periodic prober hardening and health-observation v3

This release contains two intentional compatibility breaks needed to keep a
raw assignment challenge and endpoint-health evidence inside their exact
security boundaries.

### Go `control.Prober` construction

The exported `control.ReplicaProber` callback and exported `Prober.Probe` field
were removed. Both accepted the raw hidden challenge value and therefore let
an arbitrary external Go callback capture material that must remain inside the
scheduler/runtime process.

External callers must no longer inject a probe callback. Construct a
`control.Prober` with its `Scheduler`, `Interval`, `Timeout`, and optional
logger/observation callback, then call `Run` (continuous operation) or `Sweep`
(one-shot diagnostics). The scheduler creates the private targeted validator
probe internally. `ProbeOutcome` exposes only result metadata and never the
raw challenge. There is deliberately no compatibility adapter for the removed
callback seam.

`Prober.Timeout` is now the authoritative whole-request budget for periodic
probes even when it exceeds five seconds. The scheduler validator's independent
five-second default remains in force for admission; the periodic path preserves
the configured HTTP transport but prevents that admission-oriented client
timeout from silently shortening its own context deadline. An earlier parent
deadline still wins, and preserved transport-stage bounds or failures may
return sooner. This correction changes no API shape and leaves the shipped 5s
timeout default unchanged.

`Prober.Validate` now returns `ErrProbeCadence` when the scheduler health
monitor's `RapidWindow` is zero or negative. Such a policy resets rapid failure
evidence instead of accumulating the failures needed for eviction, so it is no
longer accepted as an inert configuration. The shipped 15s rapid window is
unchanged.

`control.Scheduler.HandleHealth` also intentionally adds `endpointID` between
the stable replica ID and miner ID. Go callers must retain the endpoint ID from
the active-replica snapshot and pass that exact value; there is no legacy
overload because silently substituting an empty or stable identifier would
reintroduce cross-incarnation replay.

`validator.ProbeResult.At` now identifies the terminal network observation,
not request start. For a complete response it is captured immediately after
body EOF, and `Latency` includes the complete body transfer. This causal
timestamp is required so a result completed before a peer failure cannot be
re-stamped as fresh corroboration merely because its goroutine was processed
later. Callers that need the approximate request start can subtract `Latency`
from `At`.

### `POST /v1/health`

Health reports use the message-scoped protocol
`subnet-synapse.v3`. Other neuron messages remain on
`subnet-synapse.v2`.

Version 3 adds the required `endpoint_id`. Reporters obtain it from
`GET /v1/deployments/{deployment}` and must submit the exact tuple
`deployment_id`, `replica_id`, `endpoint_id`, and `miner_hotkey` they probed.
The production private gateway authenticates requests before forwarding them
over the root-owned mode-0600 Unix runtime socket. The runtime socket itself
uses canonical JSON and filesystem access control; it does not add a second
request signature. Because `endpoint_id` is in the authenticated request body,
the gateway authentication covers the incarnation, and the runtime checks the
tuple again against current scheduler state immediately before any health
mutation. Older liveness reports are rejected endpoint-globally, including
external successes that predate this validator's latest internal probe
evidence; at the newest timestamp, each bounded vantage may contribute once
(with a fixed per-instant cap), and attributable wrong or fraudulent content
is never discarded solely because a newer liveness report
arrived first.

The private gateway must also bind `vantage` to the authenticated reporter
(derive it from the principal or reject a body value that does not match the
principal's configured stable label). The runtime bounds and deduplicates that
label but cannot recover a principal identity from its mode-0600 socket. A
gateway that lets one authenticated writer rotate arbitrary vantage strings
would invalidate the multi-vantage trust-zero threshold and is not a conforming
deployment.

External healthy reports remain valid liveness evidence, but they cannot close
the process-local serving circuit owned by this validator's targeted prober.
Only a complete correct targeted response through the same local edge path can
restore ordinary traffic after that circuit opens.

The Go server and Python model both reject impossible evidence combinations:
`correct` requires `reachable`, while `fraudulent` requires a reachable but
incorrect response. Identity and vantage strings retain the schema's explicit
size bounds before they enter scheduler or monitor state.

The HTTP boundary durably inserts the accepted scoring sample after exact
incarnation/replay validation but before mutating health or routing policy. If
that insert fails, no health evidence is consumed and the same report remains
retryable. Once it succeeds, a later cleanup or replacement error is returned
as `health_action_failed`; replaying that committed report is rejected and
never creates a duplicate sample.

The deprecated Go `Scheduler.ObserveHealth` compatibility seam now also
requires the exact endpoint ID and verifies the signed route tuple before
changing its legacy route-only policy state. Live bridge integrations must use
the v3 HTTP contract (or `HandleHealth`) so scheduler removal, cleanup, and
replacement ownership remain coordinated.

Version 2 health reports are rejected fail-closed because a stable replica ID
does not identify a generation and assignment nonce. The checked-in v1/v2
fixtures and schemas remain immutable historical artifacts and are not
reinterpreted as v3.

Operators should upgrade in this order:

1. pause the old health reporter;
2. deploy the runtime advertising the `health-observation-v3` capability;
3. upgrade the reporter to fetch and retain the exact endpoint ID and emit v3;
4. resume reporting only after the capability and endpoint tuple are present.

No migration exports the hidden challenge, changes validator scoring, submits
weights, or introduces multi-validator coordination.
