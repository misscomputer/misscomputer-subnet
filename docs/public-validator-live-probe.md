# Public-validator hidden probes of organic assignments

The synthetic challenge probe is removed (contract §13). A public validator now
runs `misscomputer-assignment-probe` once per five-minute epoch: it verifies the
central `active-assignment-manifest` v2, derives that epoch's hidden schedule
from its private seed, sends one signed targeted probe per scheduled instant,
judges each response and miner attestation v2, and seals one
`organic-epoch-score` record. Contracts, attribution, and scoring rules are in
[`organic-availability-scoring.md`](organic-availability-scoring.md); the
operator procedure is in
[`public-validator-live-probe-runbook.md`](public-validator-live-probe-runbook.md).

## One epoch, step by step

1. **Trust and state.** Load the locally pinned
   `assignment-manifest-trust-policy` (out-of-band digest) and take the
   owner-only state-root lock (`probe_busy` if another run holds it).
2. **Manifest.** Obtain the manifest v2 and its signature envelopes from
   explicit files or HTTPS URLs. Verify live at the start instant: trust
   policy, freshness, identity rules, v2 signatures, leases against the
   operator's `--finalized-height`, and the append-only chain against the
   local state. `--trusted-state-anchor genesis` onboards on the current head
   at any sequence; `current` or a state digest requires the head to extend
   the held state. The next state is persisted before any probe.
3. **Hidden schedule.** HMAC-SHA256 of the 32-byte private seed over the
   manifest digest, epoch, endpoint incarnation, and probe index yields three
   instants per endpoint (one in each third of the epoch) and one 32-byte
   nonce each.
4. **Probes.** At each instant, the CLI signs an `organic-probe-authorization`
   with the validator hotkey through the purpose-limited
   `HotkeySigningFacade.sign_organic_probe_authorization` (which refuses any
   other message), then sends one bounded HTTPS request (`GET` or `HEAD` per
   the published predicate) to the route host through the edge with
   `X-Miss-Organic-Probe-Authorization`. No redirects, no environment proxies,
   one whole-request deadline, exact byte bound. A scheduled instant that
   already passed by more than 10 s, or a send time outside the epoch, is
   skipped and counted, never sent late.
5. **Judgement and record.** Every response is judged and attributed
   (`path`, `miner`, `application`, fraud only for a verified signature over a
   mismatched identity) and the epoch is sealed with
   `organic_scoring.score_organic_epoch` into `--epoch-output`.

Exit status: `0` scored, `3` recorded but not scored (common-mode outage or no
eligible endpoint), `2` rejected, `64` usage, `70` internal, `75` busy.

## What it does not do

It selects nothing central (routes, deployments, domains), rescores nothing,
submits nothing, and holds no RPC or weight capability. Window decisions
(`validator-weight-decision` v2) and weight plans are separate pure steps; see
[`organic-availability-scoring.md`](organic-availability-scoring.md).
