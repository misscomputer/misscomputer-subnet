# Keys, secrets, and state files

Every credential and durable state file a miner or validator uses, where it
comes from, and how to protect it. The software refuses several unsafe
configurations on its own (noted below), but it cannot protect a key you have
already copied somewhere unsafe.

## Ground rules

- **Never commit** a wallet, hotkey, private key, bridge secret, probe seed,
  certificate, or state database. `.gitignore` excludes `*.key`, `*.pem`,
  `*.crt`, `*.sqlite`, and similar, and CI fails on tracked private-key
  markers or literal credential values
  (`scripts/check-repository-secrets.sh`). Keep all of these files outside
  the repository checkout.
- **Never paste** a mnemonic, private key, secret file, or S3 secret into an
  issue, chat, log excerpt, or AI assistant prompt. Share public SS58
  addresses, certificate fingerprints, and SHA-256 digests instead.
- **Keep the coldkey off servers.** The miner and validator processes load
  only the hotkey (`bt.Wallet(name, hotkey, path=...)` resolved to a hotkey
  signer). Create and register the wallet on a trusted workstation and copy
  only the hotkey files to the server.
- **One value per host.** Generate bridge secrets and probe seeds per host
  and per validator; never reuse them.
- Examples in these docs use placeholders such as `<hotkey-ss58>` or
  `<NETUID>`. Replace them with your own values; never with a value copied
  from another operator.

## Inventory

| Item | Role | Created by | Required protection | Loss/rotation impact |
| --- | --- | --- | --- | --- |
| Coldkey (wallet) | both | `btcli wallet new-coldkey` | Offline or on a trusted workstation; encrypted; mnemonic backed up offline | Controls funds and registration. Not needed on the server |
| Hotkey (wallet) | both | `btcli wallet new-hotkey` | Owner-only files under the wallet path on the server | Identity on the subnet; a new hotkey needs a new registration |
| Miner TLS private key | miner | `scripts/manage-miner-tls.sh issue` | Mode `0600`, never group/world readable (the miner refuses to start otherwise) | Rotate any time; validators re-pin after a fresh capability handshake |
| Miner TLS certificate | miner | same | Public; its SHA-256 is the transport pin | Must list the public IP you publish with `btcli axon set` |
| Bridge secret | miner (validator operator) | you, e.g. `openssl rand -hex 32` | Owner-only; ≥ 32 bytes after trimming whitespace; different per host | Both local processes must read the same value; rotate by replacing it and restarting both |
| Go service key | miner | auto-created by `miner-agent` at `--service-key-file` (mode `0600`) | Owner-only; the agent refuses a group/world-accessible key | Signs receipts and probe attestations. A new key is picked up through the next hotkey-signed handshake; keep it persistent and backed up to avoid churn |
| S3 read credentials | miner | the artifact store owner | Environment variables only (`S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` by default); never on the command line or in a committed file | Read-only access is sufficient; miners never need delete permission |
| Probe seed (32 bytes) | validator | `head -c 32 /dev/urandom` | Owner-only; never published or shared between validators | Anyone holding it can predict your probe schedule; rotate like a key |
| Trust policy files and digests | validator | the subnet operator, out of band | Owner-only copy; the digest must come from an independent trusted channel | Wrong or swapped policy means every run is rejected |
| Probe state root, manifest archive, epoch records | validator | the CLIs | Owner-only; never edited by hand | These are the audit trail for your weights; back up while stopped |
| Checkpoint ledger state root | validator | `misscomputer-score-checkpoint-relay` | Owner-only; never edited by hand | Append-only; restore only complete, anchored backups |
| Miner state databases | miner | the processes | Owner-only | Nonce/replay and assignment state; keep across restarts |

## Wallet creation (trusted workstation)

`btcli` is a separate package (`pip install bittensor-cli` in its own virtual
environment). Commands below were checked against `btcli` 9.23; confirm with
`btcli <command> --help` for your version.

```bash
btcli wallet new-coldkey --wallet-name '<wallet-name>'
btcli wallet new-hotkey --wallet-name '<wallet-name>' --hotkey '<hotkey-name>'
```

Write the mnemonics down offline. Then copy only the hotkey to the server,
keeping the default layout so `--wallet-name`, `--wallet-hotkey`, and
`--wallet-path` resolve it:

```text
~/.bittensor/wallets/<wallet-name>/hotkeys/<hotkey-name>
```

Restrict it to the account that runs the neuron:

```bash
chmod 700 ~/.bittensor ~/.bittensor/wallets ~/.bittensor/wallets/<wallet-name> \
  ~/.bittensor/wallets/<wallet-name>/hotkeys
chmod 600 ~/.bittensor/wallets/<wallet-name>/hotkeys/<hotkey-name>
```

`btcli` creates hotkeys without a password by default, which the unattended
neurons need; coldkeys are password-protected by default, so keep them that
way. Registration is a chain transaction paid from the coldkey, so run it
where the coldkey lives. `btcli axon set` is signed with the hotkey only
(btcli 9.23 unlocks just the hotkey for it), so miners can run it on the
server (see the miner guide).

## Secret files: create them safely

Create secret files with a restrictive umask so they are never briefly
world-readable:

```bash
(umask 077; openssl rand -hex 32 > /etc/misscomputer-miner/bridge.secret)
```

Pass secrets by **file path** (`--bridge-secret-file`,
`--probe-seed-file`) rather than on the command line, where they would appear
in process listings and shell history. The Go agent can fall back to the
`MISS_BRIDGE_SECRET` environment variable, but a file is preferred.

## Validator input paths

The hardened validator CLIs (`misscomputer-assignment-probe`,
`misscomputer-organic-window`, `misscomputer-score-checkpoint-relay`) load
their input files through a strict loader. Plan directory names accordingly:

- paths must be absolute and normalized;
- input files must be regular, single-link files owned by the running user,
  readable by the owner, with no group/other permission bits (`chmod 600`);
- parent directories must be owned by root or the running user and not group-
  or world-writable;
- no path component may be named `.env`, `.ssh`, `credential(s)`,
  `secret(s)`, `wallet(s)`, `private-key`, `private_key`, `id_rsa`, or
  `id_ed25519`, or end in `.key`, `.pem`, `.p12`, or `.pfx`. Such paths are
  rejected as `input_path_sensitive`, so do **not** keep your probe seed in a
  directory called `secrets/`.

A layout such as `/srv/misscomputer-validator/probe/seed.bin` works; the
validator guide uses it.

## Backups

- Back up wallets (mnemonics offline), the miner Go service key, and validator
  state roots.
- Take state-root backups only while the owning CLI is stopped, preserving
  owner, mode, link count, file names, and bytes. Record the last printed
  state or ledger anchor digest alongside the backup.
- Never restore an older state root to make a rollback or fork error go away;
  see the fork/rollback sections of the
  [probe runbook](public-validator-live-probe-runbook.md) and the
  [checkpoint relay runbook](signed-score-checkpoint-relay-runbook.md).
