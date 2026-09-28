# Miner quickstart

This guide takes a Linux server from a fresh install to a miner that
validators can discover, assign work to, and probe. Read
[getting-started.md](getting-started.md) first for installation and
[keys-and-secrets.md](keys-and-secrets.md) for key handling.

## How a miner works

A miner is **two local processes** on one host:

```text
        internet (validators, public edge)
                     │  HTTPS, self-signed leaf pinned by fingerprint
                     ▼
  misscomputer-miner  (Python axon, default 0.0.0.0:8091)
    - btauth/1 request signatures, metagraph checks, validator permit + stake
    - hotkey-signs the Go service key binding
                     │  HMAC-signed loopback bridge (shared bridge secret)
                     ▼
  miner-agent        (Go, default 127.0.0.1:9101)
    - verifies deployment.v4 tickets, fetches + re-hashes OCI artifacts
    - runs them in Docker under the small-v1 profile on an isolated network
    - signs receipts and probe attestations with its Ed25519 service key
```

1. You register a hotkey on the subnet and publish a **numeric public IP and
   port** as its axon.
2. Validators read the metagraph, capture your TLS leaf certificate, and send
   a signed capability request. Your axon answers with a hotkey-signed binding
   that includes the certificate's SHA-256 pin and the Go agent's service key.
   Only miners whose agent advertises `organic-oci-v1` receive assignments.
3. A validator sends a signed `deployment.v4` ticket. The agent verifies it,
   downloads the named artifact from the artifact store, re-hashes every
   blob, loads it into Docker, runs it, checks its health, and returns a
   signed receipt.
4. App traffic and validator hidden probes arrive through the public edge at
   `https://<your-ip>:<port>/runtime/<endpoint_id>/...`. Your score is the
   **availability** of those assigned endpoints as measured by validators'
   hidden probes. See
   [organic-availability-scoring.md](organic-availability-scoring.md).

Protocol detail: [protocol.md](protocol.md). Runtime detail:
[miner-oci-runtime.md](miner-oci-runtime.md).

## Local versus live

| Step | Local only | Live network |
| --- | --- | --- |
| Install, build, unit tests | ✔ | |
| Mock-mode axon smoke test ([getting-started](getting-started.md#local-smoke-test-mock-mode-miner)) | ✔ | |
| TLS certificate generation | ✔ (writes files only) | |
| Hotkey registration | | ✔ transaction, costs TAO |
| Go agent + Python axon with TLS | | ✔ reads the chain, serves the internet |
| `btcli axon set` | | ✔ transaction |

A full end-to-end assignment needs live validators, the operator's artifact
store, and the public edge; it cannot be reproduced from this repository
alone.

## Prerequisites

- Everything in [getting-started.md](getting-started.md#prerequisites), with
  Python 3.12, Go 1.23, and the Go agent built at `build/miner-agent`.
- **Docker Engine** able to run `linux/amd64` images, with enough disk for
  loaded images and per-replica state.
- **`iptables`** and root (or equivalent `CAP_NET_ADMIN` plus Docker access)
  for the Go agent, which creates an internal Docker network and installs a
  host firewall rule at startup.
- A **static, public, numeric IPv4 or IPv6 address**. Validators reject
  hostnames and private, loopback, or other special-purpose addresses for
  live axons.
- One **inbound TCP port** open to the internet for the Python axon (default
  `8091`). Do **not** expose the Go agent port.
- A **registered hotkey** on the subnet (below).
- **Artifact store access.** Live assignments name artifacts in an
  S3-compatible store operated by the subnet operator. Its endpoint, bucket,
  and read-only credentials are not published in this repository; obtain them
  through the subnet's official channels. Do not guess them.

Each running replica uses the fixed `small-v1` profile: 1 CPU, 1024 MiB
memory (no swap), 256 PIDs, read-only root filesystem with a 64 MiB `/tmp`.
Size the host for the number of replicas you want to carry.

## Step 1: set your variables

Every later command uses these. The Go agent runs as root, so the simplest
path is to work through Steps 3 to 8 in one root shell (`sudo -i`) and set the
variables there; `sudo` prefixes in the examples are then harmless. Replace
each placeholder:

```bash
export MC_NETWORK=finney                 # SDK network name: finney (mainnet) or test
export MC_NETUID=<NETUID>                # the subnet netuid from official announcements
export MC_WALLET=<wallet-name>
export MC_HOTKEY=<hotkey-name>
export MC_HOTKEY_SS58=<hotkey-ss58-address>
export MC_PUBLIC_IP=<public-numeric-ip>
export MC_AXON_PORT=8091
export MC_REPO=/path/to/misscomputer-subnet
```

`MC_UID` is added in Step 2 after registration.

## Step 2: register the hotkey (live transaction)

Registration spends TAO from the coldkey. Run it where the coldkey lives
(checked against `btcli` 9.23; confirm with `btcli subnets register --help`):

```bash
btcli subnets register --netuid "$MC_NETUID" --network "$MC_NETWORK" \
  --wallet-name "$MC_WALLET" --hotkey "$MC_HOTKEY"
```

Then read your UID back with the
[read-only chain check](getting-started.md#read-only-chain-check), or with
`btcli subnets show --netuid "$MC_NETUID" --network "$MC_NETWORK"`, and set:

```bash
export MC_UID=<your-uid>
```

Copy only the hotkey to the server as described in
[keys-and-secrets.md](keys-and-secrets.md#wallet-creation-trusted-workstation).

## Step 3: create directories and the bridge secret

The Go agent needs root for Docker and `iptables`. The example below runs both
processes as root for simplicity; if you run the Python axon as a separate
unprivileged user, make that user own the TLS directory, the bridge secret,
and the axon's state database (root can still read the secret).

```bash
sudo install -d -m 0700 /etc/misscomputer-miner /var/lib/misscomputer-miner \
  /var/lib/misscomputer-miner/oci
sudo sh -c 'umask 077; openssl rand -hex 32 > /etc/misscomputer-miner/bridge.secret'
```

The secret must be at least 32 bytes after trimming whitespace; both processes
must read the **same** file.

## Step 4: issue the TLS certificate

The axon serves a self-signed, non-CA leaf certificate whose only identity is
your numeric IP. Validators pin its SHA-256 fingerprint. Use the bundled
script; it refuses to write inside the repository, requires an absolute root,
and never prints private material:

```bash
sudo "$MC_REPO/scripts/manage-miner-tls.sh" issue /etc/misscomputer-miner/tls "$MC_PUBLIC_IP" 90
```

`DAYS` is optional (default 30, maximum 825). Expected output:

```text
miner TLS issue complete
certificate: /etc/misscomputer-miner/tls/current/miner.crt
private key: /etc/misscomputer-miner/tls/current/miner.key
leaf sha256: <64 lowercase hex characters>
notBefore=...
notAfter=...
restart the miner and require a fresh validator capability handshake
```

Save the pin; the Go agent needs it:

```bash
export MC_TLS_SHA256=<leaf sha256 from the output>
```

You can print it again at any time with
`sudo "$MC_REPO/scripts/manage-miner-tls.sh" check /etc/misscomputer-miner/tls`.

## Step 5: start the Go agent

Configure the artifact store credentials in the agent's environment only (for
example a root-owned, mode-`0600` systemd `EnvironmentFile`), never on the
command line:

```bash
export S3_ACCESS_KEY_ID='<read-only-access-key-id>'
export S3_SECRET_ACCESS_KEY='<read-only-secret-access-key>'
```

Then start the agent from the same root shell (variables exported in another
user's shell are not passed through `sudo`):

```bash
"$MC_REPO/build/miner-agent" \
  --network "$MC_NETWORK" \
  --netuid "$MC_NETUID" \
  --hotkey "$MC_HOTKEY_SS58" \
  --uid "$MC_UID" \
  --bridge-secret-file /etc/misscomputer-miner/bridge.secret \
  --service-key-file /var/lib/misscomputer-miner/agent-service.key \
  --state-db /var/lib/misscomputer-miner/agent-state.sqlite \
  --docker-state-dir /var/lib/misscomputer-miner/oci \
  --artifact-backend s3 \
  --s3-endpoint '<artifact-store-endpoint-url>' \
  --s3-bucket '<artifact-bucket>' \
  --tls-certificate-sha256 "$MC_TLS_SHA256"
```

On startup the agent validates its flags, creates the service key if it is
missing (mode `0600`), opens its state database, creates or validates the
internal Docker network `misscomputer-organic` (host interface
`miss-organic0`), installs the host isolation rule if missing, and cleans up
any replicas left from a previous run. Then it logs:

```text
... INFO miner agent ready bind=127.0.0.1:9101 network=<network> netuid=<netuid> hotkey=<ss58>
```

Health (no authentication needed):

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9101/healthz   # 204
sudo iptables -C INPUT -i miss-organic0 -m conntrack --ctstate NEW -j DROP && echo rule-present
docker network inspect misscomputer-organic --format '{{.Internal}}'      # true
```

The agent only advertises `organic-oci-v1` (and so only becomes eligible for
assignments) when the network and host rule checks pass; otherwise it exits
with an error.

## Step 6: start the Python axon

The agent keeps running in the foreground, so use a second root shell (and set
the Step 1 variables there too), or run both under a supervisor as shown in
[Running as services](#running-as-services-example).

```bash
. "$MC_REPO/.venv/bin/activate"

misscomputer-miner \
  --netuid "$MC_NETUID" \
  --subtensor-network "$MC_NETWORK" \
  --wallet-name "$MC_WALLET" \
  --wallet-hotkey "$MC_HOTKEY" \
  --uid "$MC_UID" \
  --axon-port "$MC_AXON_PORT" \
  --tls-cert-file /etc/misscomputer-miner/tls/current/miner.crt \
  --tls-key-file /etc/misscomputer-miner/tls/current/miner.key \
  --bridge-secret-file /etc/misscomputer-miner/bridge.secret \
  --state-db /var/lib/misscomputer-miner/axon-nonces.sqlite
```

Healthy JSON log lines on stderr include, every `--sync-interval` seconds:

```text
{"timestamp":"...","level":"info","logger":"misscomputer_subnet.miner","message":"metagraph synchronized","hotkey":"<ss58>","block":<n>}
```

Health, from the host:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' "https://127.0.0.1:$MC_AXON_PORT/healthz"   # 204
```

`/healthz` returns `204` once the hotkey is in the metagraph with the chain's
`active` flag set and the expected UID, and `503` before that. Validators
likewise only consider metagraph records whose `active` flag is set, so check
it with the [read-only chain check](getting-started.md#read-only-chain-check)
if the miner never becomes ready. `-k` is needed because the
certificate is self-signed; validators pin it instead.

## Step 7: publish the axon (live transaction)

Publishing the numeric endpoint is a separate chain transaction and is
intentionally not automated. It is signed by the hotkey:

```bash
btcli axon set --netuid "$MC_NETUID" --network "$MC_NETWORK" \
  --ip "$MC_PUBLIC_IP" --port "$MC_AXON_PORT" \
  --wallet-name "$MC_WALLET" --hotkey "$MC_HOTKEY"
```

For an IPv6 address add `--ip-type 6`. The published IP must be exactly the IP
in your certificate.

## Step 8: verify from outside

From another machine:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' "https://$MC_PUBLIC_IP:$MC_AXON_PORT/healthz"   # 204

openssl s_client -connect "$MC_PUBLIC_IP:$MC_AXON_PORT" </dev/null 2>/dev/null \
  | openssl x509 -outform DER | openssl dgst -sha256 -r | awk '{print $1}'
# must equal $MC_TLS_SHA256
```

Then re-run the [read-only chain check](getting-started.md#read-only-chain-check)
and confirm `axon=<your-ip>:<port>`.

Once validators discover you, the axon's access log shows signed
`POST /api/v1/capabilities` requests answered `200`, followed later by
`/api/v1/deploy`, `/api/v1/status`, and `/runtime/...` traffic. Requests from
callers without a validator permit or below `--min-validator-stake` are
answered `403`; that is expected filtering, not a fault.

## Values that must match

The two processes check each other on every capability request. A mismatch
makes validators see `500 local Go identity is misconfigured`.

| Setting | Python axon | Go agent |
| --- | --- | --- |
| Network name | `--subtensor-network` | `--network` (exactly the same string) |
| Netuid | `--netuid` | `--netuid` |
| Hotkey | wallet selected by `--wallet-*` | `--hotkey` (its SS58 address) |
| UID | from the metagraph (or `--uid`) | `--uid` (must be set to the same UID) |
| Transport pin | fingerprint of `--tls-cert-file` | `--tls-certificate-sha256` |
| Bridge | `--go-agent-url` (default `http://127.0.0.1:9101`) | `--bind` (default `127.0.0.1:9101`) |
| Bridge secret | `--bridge-secret-file` | `--bridge-secret-file` |

## Configuration reference

### `misscomputer-miner`

| Flag | Default | Notes |
| --- | --- | --- |
| `--netuid` | required | |
| `--subtensor-network` | `$BT_NETWORK` or `finney` | |
| `--wallet-name` / `--wallet-hotkey` | `$BT_WALLET` / `$BT_WALLET_HOTKEY`, else `default` | Hotkey only is loaded |
| `--wallet-path` | `$BT_WALLET_PATH` or `~/.bittensor/wallets` | |
| `--uid` | learned from metagraph | If set and different from the metagraph, the miner stays unready |
| `--axon-host` / `--axon-port` | `0.0.0.0` / `8091` | Public HTTPS listener |
| `--tls-cert-file` / `--tls-key-file` | required for live | Regular non-symlink files; key must not be group/world accessible |
| `--go-agent-url` | `http://127.0.0.1:9101` | |
| `--bridge-secret-file` | required | ≥ 32 bytes |
| `--state-db` | required | SQLite nonce/replay store |
| `--min-validator-stake` | `1000.0` | Minimum caller TAO stake (validators also need a permit) |
| `--sync-interval` | `12.0` seconds | Metagraph refresh |
| `--max-concurrency` | `4` | Concurrent deploys; highest-stake callers go first |
| `--log-level` | `INFO` | |
| `--allow-insecure-mock-http`, `--mock-uri`, `--mock-peers`, `--mock-capability-fault-file` | off | Local mock only; refused without `--mock-uri` |

### `miner-agent`

| Flag | Default | Notes |
| --- | --- | --- |
| `--bind` | `127.0.0.1:9101` | Loopback only unless `--allow-non-loopback` (unsafe) |
| `--network` / `--netuid` / `--hotkey` / `--uid` | `local` / `0` / required / `-1` | Must match the axon; set `--network` and `--uid` explicitly |
| `--bridge-secret-file` | none | Falls back to env `MISS_BRIDGE_SECRET` (`--bridge-secret-env`) |
| `--service-key-file` | required | Created with mode `0600` if missing |
| `--state-db` | required | SQLite assignment/receipt/replay state; use a different file from the axon's |
| `--artifact-backend` | `file` | `file` (with `--artifact-dir`) or `s3` |
| `--s3-endpoint` / `--s3-bucket` / `--s3-region` | none / none / `auto` | `http` or `https` endpoint without credentials in the URL |
| `--s3-access-key-env` / `--s3-secret-key-env` | `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | Names of the environment variables, not values |
| `--s3-request-timeout` / `--s3-max-attempts` | `2m0s` / `3` | |
| `--runtime` | `docker` | Only supported value |
| `--docker-state-dir` | `<tmp>/misscomputer-oci` | Set it to a persistent directory |
| `--organic-network` / `--organic-bridge` | `misscomputer-organic` / `miss-organic0` | Bridge name at most 15 characters |
| `--host-isolation` | `enforce` | `enforce` installs the iptables rule if missing; `verify` only checks |
| `--miner-transport` | `https` | `http` only with `--allow-insecure-mock-http` on a `local`/`mock` network |
| `--tls-certificate-sha256` | required for `https` | Lowercase hex pin of the axon's leaf |

The `file` backend reads artifacts from a local directory with the layout in
[protocol.md](protocol.md#artifact-layout); it is useful for tests and local
development, not for receiving live assignments.

## Running as services (example)

Any supervisor works. A minimal systemd sketch; adjust paths, and keep the S3
variables in a root-owned mode-`0600` `EnvironmentFile`:

```ini
# /etc/systemd/system/misscomputer-miner-agent.service
[Unit]
Description=Miss Computer miner Go agent
After=docker.service network-online.target
Requires=docker.service

[Service]
EnvironmentFile=/etc/misscomputer-miner/agent.env
ExecStart=/path/to/misscomputer-subnet/build/miner-agent --network finney --netuid <NETUID> --hotkey <hotkey-ss58> --uid <uid> --bridge-secret-file /etc/misscomputer-miner/bridge.secret --service-key-file /var/lib/misscomputer-miner/agent-service.key --state-db /var/lib/misscomputer-miner/agent-state.sqlite --docker-state-dir /var/lib/misscomputer-miner/oci --artifact-backend s3 --s3-endpoint <artifact-store-endpoint-url> --s3-bucket <artifact-bucket> --tls-certificate-sha256 <leaf-sha256>
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/misscomputer-miner.service
[Unit]
Description=Miss Computer miner axon
After=misscomputer-miner-agent.service
Requires=misscomputer-miner-agent.service

[Service]
ExecStart=/path/to/misscomputer-subnet/.venv/bin/misscomputer-miner --netuid <NETUID> --subtensor-network finney --wallet-name <wallet-name> --wallet-hotkey <hotkey-name> --uid <uid> --tls-cert-file /etc/misscomputer-miner/tls/current/miner.crt --tls-key-file /etc/misscomputer-miner/tls/current/miner.key --bridge-secret-file /etc/misscomputer-miner/bridge.secret --state-db /var/lib/misscomputer-miner/axon-nonces.sqlite
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Logs: `journalctl -u misscomputer-miner-agent -f` and
`journalctl -u misscomputer-miner -f`.

## Day-2 operations

**Certificate rotation.** Rotate before expiry (the `check` action fails when
the certificate expires within `WARN_BEFORE_SECONDS`, default one week):

```bash
sudo "$MC_REPO/scripts/manage-miner-tls.sh" rotate /etc/misscomputer-miner/tls "$MC_PUBLIC_IP" 90
```

Update the Go agent's `--tls-certificate-sha256` to the new `leaf sha256`,
then restart the agent and the axon. `rollback` swaps back to the previous
release (update the pin again). Validators pick up the new pin on their next
capability handshake.

Every assignment ticket is bound to the certificate pin that was current when
it was issued, and the agent refuses status, deactivation, and runtime traffic
for a ticket whose pin differs from its own. Combined with the agent restart
below, a rotation therefore ends all current assignments: rotate well before
expiry, in a planned window, and not more often than needed.

**IP change.** Issue a certificate for the new IP (`rotate`), update the pin,
restart both processes, and run `btcli axon set` with the new IP.

**Re-registration or UID change.** Update `--uid` on both processes and
restart.

**Restarts and upgrades.** Stop the axon, then the agent. Restarting the agent
is disruptive: on shutdown, and again on the next start, it deactivates every
replica it was running (removing the containers) before it accepts new
assignments. Those endpoints stop serving, which can cost availability, so
keep agent restarts rare and planned. The axon can be
restarted on its own without touching replicas. Keep the service key, both
state databases, and the TLS directory across upgrades. After `git pull`, reinstall (`python -m pip install -e .`) and
rebuild (`go build -o build/miner-agent ./cmd/miner-agent`).

**Logs.** The axon writes JSON lines with `timestamp`, `level`, `logger`,
`message`, and fields such as `hotkey`, `block`, `endpoint_id`, and
`request_id`; request bodies and credentials are never logged. The agent uses
Go's structured text logger on stderr.

Problems: see [troubleshooting.md](troubleshooting.md#miner).
