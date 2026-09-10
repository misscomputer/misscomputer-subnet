# Prior checkpoint repair evidence

Historical evidence for `00de93cd`; the subsequent atomic-cap and timeout
repairs supersede its ceiling and timeout-policy claims. See
[the next-round evidence](pr9-atomic-timeout-repair-evidence.md).

## Scope and immutable input

- Public PR: https://github.com/misscomputer/misscomputer-subnet/pull/9
- Base/main/merge-base: `75e44ba36609d9a53c55478af7399574ba072b40`.
- Reviewed input: `5642ecd17a2760e2982b182db10f2ceedd1e36c8`.
- Before edits: clean dedicated writer worktree; local HEAD, upstream, remote
  branch, pull ref, and GitHub PR head matched the input. PR open, non-draft,
  unmerged, cleanly mergeable; four exact-head Python/Go checks succeeded.
- No merge, deployment, private-repository modification, or live-state changes.
  Independent review and controller merge authority remain required.

## Design and dispositions

| Review finding | Repair and stable outcome |
| --- | --- |
| PR9-LINEAGE-CANDIDATE-DEADEND | Boundary preparation fully dry-runs candidate advancement against the proposed pruned state before returning anything. Rewritten incarnation, generation, fact reuse, invalid ordering and resource limits reject without changing the old head. Existing candidate commitment and repeated-boundary guards remain. |
| PR9-LINEAGE-REPLAY-PENDING-COMMIT | Explicit `pending_candidate` validates without consuming the candidate and reproduces the pending head byte-for-byte. Supplying the candidate in `snapshots` deliberately produces the post-candidate head. |
| PR9-LINEAGE-REPLAY-SUPERLINEAR | Preserve exact immutable hash-chain semantics; do not claim linear capture-count runtime. Enforce `MAX_REPLAY_WORK=1_000_000`, including retained replicas, three fact arrays, boundary records and incoming deployment/replica entries, before expensive transitions. Candidate preparation charges its dry run. Oversized calls reject as `snapshot_lineage_replay_work_exceeded`; bounded batches reproduce sequential hashes exactly. |
| PR9-DNS-SLOT-OWNERSHIP | Allocate setup objects before admission; locked creator/worker/released lease ownership. Pre-claim cancellation prevents lookup execution, post-claim cancellation cannot release a live worker's permit. Signaling failure releases through `finally`; SIGINT is deferred only during lease accounting. Default pool resets in fork children. |
| PR9-DNS-DEADLINE-STALE | Recompute remaining time after setup/start and immediately before waiting, with post-wait expiry check. Slow setup never buys a second stale-budget wait. |
| PR9-REPORT-PARSER-POLICY-PARITY | Report model requires every observation's policy digest to equal its own: `observation_policy_violation`, byte-parser wrapper `document_invalid`, standalone scorer `scoring_round_invalid`, decision report-validation boundary `decision_round_invalid`. Added resealed standalone negative fixture; existing decision negative now rejects earlier. |
| PR9-HISTORICAL-RESULT-REPORTABLE | Historical verification explicitly sets `reportable=False`; builder rejects as `historical_verification_not_reportable`. Propagation preserves the mode. Builder also revalidates manifest freshness/effective expiry as defense in depth. |
| PR9-LINEAGE-REPLAY-SUFFIX | Explicit full-history/default versus suffix boundary modes. Full history must match the entire current prefix; suffix begins at the next era. No sorting, deduplication, ignored event, or blind prefix dropping. Mismatches reject as `snapshot_lineage_replay_mismatch`. |
| PR9-LINEAGE-PARSER-PENDING-FACT-CAP | Pending heads retain exactly active incarnations and their facts. Dropped plus retained facts obey all three caps, equal nonce/ticket/receipt totals, and replica-count feasibility: `lineage_era_invalid`. |
| PR9-HTTPCORE-UNPINNED | Exact direct `httpcore==1.0.9`; compatibility record, BSD-3-Clause notice and SPDX package/dependency edge added. Release guard now checks every runtime direct pin against SBOM versions. No transitive Python lock is claimed. |
| PR9-DOC-OLD-REPORT-REPROCESSING | Explicitly unsupported. Keep old bytes and compatible segregated offline readers; no conversion or dual reader ships, and adding a policy digest cannot establish historical probe provenance. |

Adjacent repairs close a newly dialed socket if option setup/deadline checking
fails, and reject zero-byte socket sends instead of looping without progress.
The transport capability guard permits only `os.register_at_fork` from the new
OS import. Existing CLI capability prohibitions remain intact.

## Failing-first evidence

`tests/python/test_pr9_final_repair.py` contains the reproductions. Before source
edits the initial cases reproduced the rewritten-candidate acceptance, ignored
forged boundary, all three combined-fact-cap failures, foreign-policy report
acceptance, Event-allocation permit leak, started-then-interrupted premature
release, stale DNS wait, and missing direct dependency pin. The historical case
was corrected to use the fixture's actual `state` field and then demonstrated
that an expired manifest could build a report at epoch `1800004000` despite
expiry `1800003600`.

A second failing-first run loaded `git archive` source from the exact old SHA
inside the writer's ignored test-cache directory, with the same writer venv and
new acceptance tests. The lineage/replay/parser/historical/DNS selection had
**17 failures, 3 passes, 5 deselected**. New API cases fail on the old source's
missing keyword arguments; legacy reproductions fail because it accepts or
misaccounts the attack. The old tests and old source were not modified.

Growing-history benchmark (one replica, fresh generation and facts per capture):

| Source | Captures | Outcome | Wall seconds |
| --- | ---: | --- | ---: |
| Old exact SHA | 300 | accepted, 300 facts/kind | 0.299506 |
| Old exact SHA | 1,200 | accepted, 1,200 facts/kind | 3.713575 |
| Repaired tree | 300 | accepted, 300 facts/kind | 0.293427 |
| Repaired tree | 1,200 | `snapshot_lineage_replay_work_exceeded` | 1.785704 |

The old ratio was 12.4x for 4x input. The repaired acceptance test separately
replays all 1,200 captures in explicit 100-capture batches and requires exact
equality with ordinary sequential advancement. This is a bounded-work remedy,
not an unbounded linear-replay claim.

The DNS startup reproduction injects 120ms start latency under a 100ms budget:
old code takes about 220ms; repaired code refuses immediately after setup
(test ceiling 180ms). Event/Thread construction, failed start, late worker
claim, worker completion, signaling exception, real SIGINT after admission,
blocked resolver capacity and fork inheritance have independent cases.

## Local validation

Final source validation before commit:

- Complete Python suite: **751 passed**, 77.81s.
- Ruff check and format check: pass (64 source/test files).
- Strict mypy: pass, 32 source files.
- Writer venv rebuilt with `python -m pip install -e '.[dev]'`; import path
  points to the writer source; HTTPCore installed version 1.0.9; pip check pass.
- Go gofmt check, `go vet ./...`, `go test -race ./...`: pass.
- Assignment-probe and checkpoint fixture/schema generators run twice;
  complete contract-tree manifests identical. SHA-256 of the sorted
  `sha256sum` manifest: `511940dfba57287488a45f50ed45f301e9cf3c471ab2117c48112898fa596fc8`.
- Attribution, public-boundary, release-metadata/SBOM, repository-secret and
  `git diff --check` guards pass. The secret guard is also rerun after staging.
- Existing historical regression suites retained: skew boundaries, policy
  rotations/relabeling in both directions across timeouts/pins/size, A-B-A fact
  reuse, disappearance/reappearance and empty captures, exact-cap turnover,
  duplicate/rollback/fork sequence, pending recovery, replay modes, blocked DNS,
  multi-address dialing, partial sends, real-TLS trickles and producer/parser
  parity. Earlier-rejected foreign-policy reports are deliberately constructed
  only in tests to keep downstream revalidation attacks covered.

Hosted CI is checked on the pushed immutable SHA and reported in the PR handoff,
not inferred from local results or the old head.

## Limits and operating contract

- The lineage hash-chain format remains cumulative-state hashing. Large replay
  requires explicit bounded batches; a failed call returns no partial state.
- Candidate-boundary preparation is fully validated, but still produces a
  pending state. Retain the committed candidate, use identical resource limits
  for its advance, and use the explicit pending replay API for crash recovery.
- Era rotation intentionally re-scopes retired-fact memory; anchors must remain
  independently trusted. A self digest alone cannot prove historical truth.
- Resolver calls cannot be forcibly cancelled. Claimed workers hold capacity
  until completion; exhaustion fails fast. Scheduler/startup overhead cannot be
  preempted by Python; it consumes the budget instead of extending waits.
- SIGINT accounting is covered on the supported POSIX runtime. Arbitrary
  interpreter-level asynchronous thread-exception injection, process kill, or
  hostile replacements of synchronization primitives are not supported APIs.
- HTTPX private-pool integration remains, explicitly paired with reviewed direct
  pins HTTPX 0.28.1 / HTTPCore 1.0.9. Transitive resolved release inputs remain
  the release pipeline's responsibility.
- No old-report converter, production integration, deployment, or merge is
  included. This document records writer evidence, not independent approval.

## Route

Requested provider/model: `saygm-openai` / `gpt-6-astra`.
Effective and response model reported by the runtime: `saygm-openai/gpt-6-astra`.
This writer invoked no model delegation or fallback. No separate raw upstream
response-model metadata is exposed to the writer, so route attestation is based
on the runtime identity rather than an invented transport-level receipt.
