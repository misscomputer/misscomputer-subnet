# Explicit operator access

Miner control and customer-linked organic probes require a locally configured
operator allowlist. Chain registration, stake, validator permits and election as
the Null consensus weight setter do not, by themselves, authorize this access.
There is no self-hotkey, subnet-owner, chain-winner or legacy-validator fallback.

## Configuration and rollout

Both `misscomputer-miner` and `misscomputer-validator` accept repeatable
`--operator-hotkey <canonical-SS58-address>` flags. Alternatively set
`MC_OPERATOR_HOTKEYS` to comma-separated canonical SS58 addresses, without spaces:

```bash
export MC_OPERATOR_HOTKEYS='<operator-hotkey-ss58>,<second-authorized-hotkey-ss58>'
```

These are placeholders, not valid addresses. Obtain the intended operator
identities through a trusted channel, independently of the current chain leader.
Any CLI entries **replace**, rather than extend, the environment list. An absent
configuration, or an empty list supplied to the Python constructors, denies every
caller. Empty entries (including an explicitly empty environment value), leading
or trailing whitespace, invalid checksums and noncanonical addresses reject
startup. An invalid entry is never silently dropped. Configuration is validated
before CLI startup accesses secrets or the chain; restart to apply changes.

Before upgrading, configure each miner with the controller hotkey(s) authorized
to send signed control requests, and configure the validator bridge with the
hotkey(s) authorized to sign organic probes. Configure the probing hotkey even
when it is the validator bridge's own hotkey. Use the list for the process's
configured `--subtensor-network` and `--netuid`; it grants no cross-subnet
exception to existing chain, request or signed service-binding checks.

The miner check applies to all signed control routes, including capabilities,
deploy/status/deactivate, static assignments and opt-in sandbox transport. The
validator check applies to `POST /v1/organic-probes/authorize`, inside the existing
authenticated loopback bridge. The list does not authorize ordinary website
visitors or replace runtime edge signatures, tenant checks or workload isolation.
An unconfigured miner can still pass health checks while refusing all control
requests; verify a signed authorized request after configuration.

## Additive migration boundary

This is the first, additive authority boundary, not a live consensus switch.
Configured miner callers must still be uniquely registered, hold a validator
permit, meet the existing minimum stake, and satisfy rate, signature, replay,
network/netuid, freshness and service-binding checks. Configured organic-probe
signers must still be uniquely registered and permitted and present a valid
hotkey signature; the Go edge retains probe freshness, nonce and routing checks.
Sandbox transport remains default-off.

The validator's `_admit_snapshot` still requires its **own** validator permit.
Removing that dependency and separating control-plane identity from the elected
weight setter require a later, separately reviewed slice. This change does not
alter weight submission, chain parameters, the wire protocol, tenant boundaries,
or deployment authorization keys.

Keep website inventories, deployment mappings, probe targets and customer-linked
evidence private to the operator. These generic configuration examples contain no
customer inventory. An allowlist closes unauthorized control/probe access; it does
not remove pre-existing public files or make public websites undiscoverable.
