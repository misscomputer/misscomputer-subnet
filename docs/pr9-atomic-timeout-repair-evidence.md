# Atomic replay and timeout repair evidence

## Immutable input and boundary

Public PR: https://github.com/misscomputer/misscomputer-subnet/pull/9.
Reviewed input: `00de93cd2baa8b951074476129877dc820913847`.
Base/main/merge-base: `75e44ba36609d9a53c55478af7399574ba072b40`.
Before edits, fetch plus local HEAD/upstream/origin branch/pull ref/GitHub PR
head all matched the reviewed input; worktree clean, PR OPEN, non-draft,
unmerged, CLEAN, exact-head CI 4/4 success. All repository operations stayed
in the designated public-PR worktree. No private repository or vendor copy,
services, credentials, deployment, chain, or live systems were touched.
No merge or self-approval; a separate SayGM Sol exact-SHA review is required.

## Findings and design

| Finding | Writer disposition |
| --- | --- |
| PR9-LINEAGE-REPLAY-ATOMIC-CAP | Repaired by deriving `MAX_REPLAY_WORK=1_814_787` from producer field caps, without changing accounting or validation. State S ≤ 426,048; candidate C ≤ 36,865; initial validation plus the largest atomic candidate boundary costs S+3(S+C). Ordinary capture/plain boundary/pending-head verification cost less. Regressions build 4,096 replicas and 86,016, then 131,072 facts per array through producers and reproduce pending hashes exactly. A deliberately lower 1,000,000 caller cap still refuses. |
| PR9-REPORT-TIMEOUT-POLICY-RELABEL | Repaired by eliminating ambiguous timeout causes: timeout iff recorded floor-ms latency exceeds the named whole-request budget. Early OS/per-operation timeout is `transport_error`; all outcomes after expiry become timeout in both pure evaluator and HTTPS transport. Report models/parsers and standalone scorer enforce embedded budget/size; policy-aware producer/decision paths bind scalars to policy. Fully resealed 101ms strict→loose attacks fail without relying on self digests as authentication. |
| PR9-TRANSPORT-FRACTIONAL-BUDGET-CUTOFF | Repaired by continuous deadline `(budget_millis+1)/1000`, including outer HTTPX timeout, matching existing floor-inclusive admission. Real backend TCP dial/read/write regressions accept at 100.5ms and refuse at 101ms under a 100ms budget. |

Policy review: timeout, size, and pin membership are the observation-dependent
policy branches. Size failures and pin mismatches retain bidirectional checks;
report-level size validation also closes standalone-scorer parity. Other policy
fields govern manifest identity, validity/freshness/skew/lifetime, routes,
keys/threshold/roles/revocation, or chain sequence/height admission. Existing
checks remain. Compatible policies can admit identical facts; signed telemetry
is not claimed. Deliberately fabricating latency/cause remains outside the
trusted local-observer boundary of these unsigned reports.

## Failing-first behavior

Before any tracked edit, an executable reproduction was created inside the
worktree's ignored `.pytest_cache/pr9-repair/` and executed with its `.venv`.
Tracked worktree status remained clean on old SHA `00de93cd`.

- 512 deployments × 8 replicas × 21 generations = 86,016 facts per array:
  producer accepted candidate boundary; replay raised
  `snapshot_lineage_replay_work_exceeded`. This fixture charges 1,062,407
  entries (its candidate includes 512 deployment entries); the review's
  1,048,583 figure is likewise above the old hard ceiling.
- Strict 100ms observation at 101ms, relabelled to same-authority 5000ms policy
  with every observation/vector/report digest resealed: policy binding,
  report producer/parser, and 45-round decision producer/parser all accepted;
  resulting submitted weights differed from the original golden window.
  The reproduction deliberately failed after proving all those acceptances.
- At 100.5ms the old budget returned latency 100, `exhausted=False`, but the
  production backend raised `ConnectTimeout` before resolution. At 101ms the
  expected timeout control passed.

The first combined run found the lineage and fractional failures plus one
reproduction harness error (nested attestation alias). After correcting only
that ignored harness, the timeout-only run proved the complete attack above.
No claim is based on the harness error. Durable repaired regressions are in
`tests/python/test_pr9_atomic_timeout_repair.py`; existing adversarial tests
remain, with exact semantic-boundary expectations updated rather than removed.

## Compatibility and stable outcomes

No new fields, schema changes, or dependency changes in this round. Old reports
claiming timeout at/below budget no longer parse and must remain in their
original offline archives; no resealing/conversion is offered. CLI/coordinator
cut over together. The silent fixture route now records 5001ms, not an
impossible 42ms timeout under a 5000ms policy. Golden decision rows and weights
are byte-equivalent as JSON values; only facts and dependent digests change.

Budget/size failures now reject earlier at report validation:
`observation_policy_violation`, byte parser `document_invalid`, standalone
scorer `scoring_round_invalid`, decision producer `decision_round_invalid`.
Three previously later-rejecting negative fixtures are repinned to this exact
outcome. Remaining full-policy checks retain their existing codes. Replay
keeps `snapshot_lineage_replay_work_exceeded`, all input caps and exact hashes.
Migration and contract documentation specify both the new semantics and limits.

## Validation

- Complete Python suite: **774 passed**, 153.84 seconds.
- New adversarial suite: **23 passed**; includes near/exact-cap producer replay,
  worst-case charge proof, fully resealed 45-round attack across all consumers,
  real TCP backend fractional cutoffs, and 18 cause/latency parity cases.
- Ruff check and format: pass, 65 source/test files.
- Strict mypy: pass, 32 source modules.
- Worktree `.venv` imports this worktree; every direct runtime/dev pin matches
  installed metadata; `pip check` passes. HTTPX 0.28.1 / HTTPCore 1.0.9 retained.
- Combined new/prior adversarial suites: **49 passed**, 83.25 seconds.
- Go 1.23.12: gofmt clean, vet and uncached `test -race -count=1` pass.
- Both fixture/schema generators run twice: all **194** contract files identical.
- Attribution, public-boundary, release metadata/direct-pin SBOM parity,
  repository-secret scan, and diff-hygiene guards pass; staging is scanned again.
- Cumulative source diff and adjacent contracts inspected: lineage/candidate
  ordering and resource guards, transport DNS/stream ownership, report/scorer/
  decision admission, schema and fixture generation, Go clock-skew parity,
  dependency metadata and migration rules. No unrelated runtime change added.

Hosted exact-head CI and final pins are reported in the PR handoff after push,
not inferred from old-head CI or local results.

## Limits and route

Replay remains bounded cumulative immutable-state hashing, not linear in
capture count. A candidate boundary and candidate acceptance are separate
persistable transitions and may need separate calls; lower caller budgets may
intentionally refuse an otherwise valid atomic event. Independent anchors and
retained candidates remain mandatory. Resolver calls cannot be cancelled;
scheduling overhead is charged but not preemptible. Real-backend boundary tests
inject a deterministic clock/DNS to test submillisecond semantics and use real
loopback sockets; existing real-TLS trickle tests cover wall-clock integration.
No production deployment, transitive dependency lock, signed validator telemetry,
old-report converter, independent approval, or merge is claimed.

Resolved runtime provider/model: `saygm-openai/gpt-6-astra` (provider
`saygm-openai`, model `gpt-6-astra`). No writer-invoked fallback or delegation;
no fallback indicated by runtime. Raw provider routing receipts are unavailable,
so this is a runtime-identity attestation, not a separate transport receipt.
