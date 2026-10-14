# D18 verifier process boundary

`misscomputer-d18-verify --request /absolute/request.json --response
/absolute/response.json` is a one-shot offline public verifier for the D18
old/new validator mock capture. The private collector runs it in a separately
installed public interpreter; it does not import public Python in-process.
No network, signing, chain, submission, or activation operation is exposed.

The request is canonical JSON (sorted keys, compact separators, ASCII escapes,
one trailing newline), at most 4 MiB. It has the exact keys `protocol`,
`captures`, `epoch_index`, `site_digest`, `faulty_endpoint_id`, `network`,
`netuid`, `started_at`, `finished_at`. The protocol is
`misscomputer.d18-verifier-boundary.v1`. `captures` has exactly these base64
byte fields, each at most 1 MiB decoded: `v2-policy`, `v2-manifest`,
`v2-auditor`, `v2-issuer`, `v3-manifest`, `v3-auditor`, `v3-issuer`,
`release-policy`, `release-index`, `site-manifest`, `old-score`, `new-score`,
`journal`. The caller must bind these bytes to its separately captured hashes
and release provenance before submission.

The verifier authenticates both signed publications under the same trust
policy, authenticates the static release/index, replays the static score from
the index, checks old/new epoch/validator bindings, verifies the journal chain
and observation parity, and checks the fault and observation window. Only then
it derives `old_validator_abstained`, `wrong_bytes_detected`, and
`false_penalties`. The response is canonical JSON. Success has exactly
`protocol`, `status: "verified"`, and `metrics`; a refusal has exactly
`protocol`, `status: "rejected"`, and a fixed `code`. Diagnostics and supplied
payload bytes are never included in the response.

This API checks the captured D18 pair; it does not claim that a later verifier
binary was the binary used by either validator during the captured run. The
private release must install this command from its approved vendored public
snapshot, pin its path, and treat command absence, timeout, malformed response,
or refusal as a failed collection. No D18 output authorizes live rollout.
