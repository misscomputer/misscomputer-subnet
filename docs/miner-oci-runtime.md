# Miner OCI runtime (organic `deployment.v4`)

This note describes how a miner agent turns an organic `deployment.v4`
ticket into a running replica. It implements the organic deployment
contract §5 (digest chain), §6.6–6.7 (ticket/receipt v4 on the miner side)
and §7 (runtime profile `small-v1`). Synthetic challenge layers play no part:
the ticket names an artifact-manifest v2 by digest and the miner runs the
customer's OCI image exactly as built and smoke-tested by the CLI.

## Acceptance sequence

1. **Envelope and ticket.** The Python neuron accepts `subnet-synapse.v3`
   deploys (`DeploySynapseV3`, strict parse), applies the same btauth and
   Bittensor identity checks as v2, and forwards a v3 loopback request. The
   agent (`Agent.AssignBoundV4`) verifies the `protocol.TicketV4` with
   `VerifyTicketV4` (signature by the bound validator service key, window,
   every `deployment.v4` rule including `resources == organic.SmallV1` and
   `failure_threshold == 2`), then network, netuid, hotkeys, UID, chain
   block, its own service key and its transport pin. No nonce is consumed and
   no receipt is signed for a rejected ticket.
2. **Manifest.** `v1/manifests/<hex>.json` is read with the manifest key
   derived from `image_digest` (never trusted separately), bounded at 1 MiB,
   and accepted only as the canonical stored bytes whose SHA-256 is the
   `image_digest` (`artifact.ParseManifestV2`).
3. **Layout.** `artifact.MaterializeOCILayout` streams the OCI manifest, the
   config and every layer from the read-only store into
   `<state>/<instance>.oci/`, re-hashing length and SHA-256 of each blob,
   checking the OCI manifest's descriptors against the artifact manifest,
   the config's platform and `rootfs.diff_ids`, and decompressing gzip
   layers to verify each `diff_id` and `uncompressed_size`. Configs that
   declare `Volumes` or have no entrypoint/command are rejected. Layers are
   never buffered whole in memory (`BlobOpener` for `FileStore` and
   `S3Store`).
4. **Load and identity.** The verified layout is streamed as an OCI archive
   into `docker load`, tagged `misscomputer/organic:a-<artifact hex>`. The
   engine's image ID must be either the config digest (classic image store)
   or the OCI manifest digest (containerd image store); both bind exactly
   the verified config. Any other ID is `image_identity_mismatch`. The
   verified blob copies are then discarded.
5. **Run.** The container is started from the verified image ID with the
   exact `small-v1` flags: `--pull never --platform linux/amd64 --cpus 1.000
   --memory 1024m --memory-swap 1024m --pids-limit 256 --read-only --tmpfs
   /tmp:rw,noexec,nosuid,size=64m --user 65532:65532 --cap-drop ALL
   --security-opt no-new-privileges --ipc private --log-driver json-file
   --log-opt max-size=1m --log-opt max-file=2 --rm`, the image `ENV` plus only
   `PORT` and `HOST`, and no restart policy, volumes, devices or host
   namespaces. The container name stays `miss-<prefix>-<12hex>`; its cleanup
   identity is durable before `docker run`.
6. **Startup health.** The agent probes `http://<container IP>:<port><path>`
   directly with `Host: <route_host>`: `startup_timeout_millis` overall,
   `probe_timeout_millis` per attempt, `interval_millis` between attempts,
   `successes_required` consecutive matches of status and (optional) marker
   within the first 64 KiB. Redirects are not followed. A container that is
   no longer running fails immediately as `container_exited`. There is no
   health loop after `ready`.
7. **Receipt.** The agent signs `protocol.ReceiptV4` (`SignReceiptV4`):
   `ready` with `loaded_image_config_digest` (= artifact `config.digest`) and
   `error_code: null`, or `failed` with one `organic.ReceiptErrorAttribution`
   code and a printable-ASCII `error` of at most 512 bytes that never contains
   container output. Every signed receipt, including failures, is returned as
   `deploy-response.v3` and kept for `status-response.v3`.

Error codes: store unavailability → `artifact_fetch_failed`; any digest,
size, binding or policy mismatch → `artifact_verify_failed`; `docker load`
failure → `image_load_failed`; wrong engine ID → `image_identity_mismatch`;
`docker run`/network attach failure → `container_create_failed`; `ENOSPC`
anywhere → `resource_exhausted`; fence during creation → `deactivated`.

## Network isolation (D9 deny-all egress)

Replicas join one Docker bridge network (default `misscomputer-organic`) that
is `--internal` (no route off the host), has inter-container communication
disabled, IPv6 off, and a fixed host interface name (default
`miss-organic0`). The agent reaches apps at the container IP; no ports are
published.

An internal bridge still lets a container open connections to host services
bound to `0.0.0.0` through the bridge gateway address. The agent therefore
requires the host rule

```text
iptables -I INPUT -i miss-organic0 -m conntrack --ctstate NEW -j DROP
```

which drops container-initiated connections while conntrack admits replies
to the agent's own health and proxy connections. `miner-agent --runtime
docker` creates/validates the network and, with `--host-isolation enforce`
(default), installs the rule when missing; `--host-isolation verify` only
checks for it. Startup fails, and `organic-oci-v1` is never advertised,
unless both checks pass. The real-engine test
`TestDockerOCIRuntimeRunsVerifiedImageUnderSmallV1`
(`MISSCOMPUTER_DOCKER_OCI_TEST=1`, root) observes from inside the container
that the host gateway, another organic container, `169.254.169.254`, RFC 1918
and public addresses are all unreachable.

Docker itself adds `HOSTNAME` and `HOME` to the environment; nothing else is
injected.

## Cleanup and image retention

Deactivation, failed assignments and restart recovery call
`StopCleanup` with the persisted `<instance>` name and `<state>/<instance>.oci`
directory: `docker rm --force`, then — under a per-artifact lock ordered
against concurrent launches — the artifact tag is removed only when no
container on the engine still uses it, and finally the instance directory is
deleted. Every step is idempotent.

## Runtime ingress (§6.9) and probe attestation v2 (§17.2)

For an organic endpoint the agent accepts a `/runtime/<endpoint_id>/...`
request only with exactly one `X-Miss-Edge-Authorization` that
`organic.VerifyEdgeRuntimeRequest` accepts for the request actually received
(method, escaped path after the endpoint, raw query, body SHA-256) under the
addressed ticket's `validator_service_public_key`, fresh within 10 s (+2 s
skew), whose nonce has never been seen (durable replay store, in-memory
without one). Anything else is answered 401 before the container is
contacted. Every `X-Miss-*` header is stripped in both directions, the app
receives `Host: <route_host>` and the edge's `X-Forwarded-*` values, and
bodies are bounded at 1 MiB.

A request that also carries `X-Miss-Organic-Probe-Authorization` (canonical
base64 of the canonical `organic-probe-authorization` JSON, without the
stored-form newline) is admitted only when it names this endpoint and
generation, the received method and path with no query, was issued within
30 s, and its nonce is unused. The response (bounded at 16 MiB) then leaves
with one `X-Miss-Probe-Attestation`: canonical base64 of the canonical
`miner-probe-attestation` v2 document signed with the miner service key
(`organic.SignProbeAttestationV2`), binding the ticket digest, artifact
digest, validator hotkey, nonce, status, body digest and end-to-end
response-header digest.

## Integration seams

- **sr25519.** The miner does not verify the validator hotkey signature of a
  probe authorization; the edge must (contract open item). The miner binds
  what it attests to an edge-signed request, the endpoint incarnation,
  freshness and a one-time nonce.
- **Python runtime hop (§8).** The neuron forwards the escaped path, raw query,
  `OPTIONS`, and both organic authorization headers verbatim; response header
  pass-through, compression and the 16 MiB response limit remain with the
  edge track.
- **Synthetic path removed.** `runtime.Runtime`, `LocalRuntime`, the
  `pkg/workload` layer server, `cmd/workload`, the agent's synthetic
  assignment branch and challenge attestation are deleted (§13). Every
  runtime-ingress request goes through the same edge-authorized proxy with the
  §8 request rewrite and response sanitization; only an organic probe carries
  an attestation.
