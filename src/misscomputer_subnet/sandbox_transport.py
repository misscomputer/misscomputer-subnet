# SPDX-License-Identifier: AGPL-3.0-only
"""``subnet-sandbox-synapse.v1``: transport for sandbox-lease-v1 documents.

Off by default. The neurons register these routes only with
``--sandbox-leases on``; without it the axon and the validator bridge are
exactly what they were before this lane existed.

The five sandbox-lease-v1 documents are owned by the Go contract
(``pkg/protocol/sandbox_v1.go``, ``docs/sandbox-lease-v1.md``). Python models
and generated schemas for them are a later parity step, so this module does
not validate them. The Python neurons only authenticate and forward: they read
the routing header every validator document carries (schema, identity and
the static-v1 ``subnet`` binding), apply the same btauth, metagraph and
handshake identity checks as a static ticket, and pass the document object
through unchanged. The Go miner agent runs the full validation, signature and
``VerifyBoundSandbox*V1`` admission; the Go runtime verifies the miner-signed
receipt that comes back.

Placement is never decided here: which miner, which resources, and whether to
reserve, commit, renew or release all come from the validator Go runtime.

This module has no clock, network, file, process, environment, wallet or
randomness capability.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator

from misscomputer_subnet.contract_codec import StrictFrozenModel
from misscomputer_subnet.organic_contracts import Count, Hotkey, PositiveCount
from misscomputer_subnet.organic_contracts import ServiceKeyBinding as ServiceKeyBinding
from misscomputer_subnet.static_contracts import RequestID, StaticSubnetBinding

SYNAPSE_VERSION: Final = "subnet-sandbox-synapse.v1"
#: Advertised by a miner agent that runs the sandbox lane (``pkg/sandbox``).
CAPABILITY_FEATURE: Final = "sandbox-lease-v1"
REPLAY_CAPABILITY_FEATURE: Final = "sandbox-reservation-replay-v1"
# Typed agent refusals that must survive both Python hops. A 410 remains
# ambiguous until the caller proves every non-hold authority window current.
REPLAY_REFUSAL_CODES: Final = frozenset(
    {
        "sandbox_replay_hold_absent",
        "sandbox_replay_fenced",
        "sandbox_replay_not_held",
        "sandbox_conflict",
        "sandbox_lane_closed",
        "expired_assignment",
        "expired_binding",
        "binding_rollback",
    }
)
_SCHEMA_PREFIX: Final = "miss.computer/misscomputer-subnet/"
#: Route segment -> the one validator document schema that route carries.
#: Miner axon ``/api/v1/sandbox/<kind>``, Go agent ``/v1/sandbox/<kind>``,
#: validator bridge ``/v1/miners/{hotkey}/sandbox-<kind>``.
DOCUMENT_SCHEMAS: Final[dict[str, str]] = {
    "reservations": _SCHEMA_PREFIX + "sandbox-reservation-ticket",
    "leases": _SCHEMA_PREFIX + "sandbox-lease-ticket",
    "renewals": _SCHEMA_PREFIX + "sandbox-lease-renewal",
    "releases": _SCHEMA_PREFIX + "sandbox-lease-release",
}
RECEIPT_SCHEMA: Final = _SCHEMA_PREFIX + "sandbox-lease-receipt"
#: Stable bridge detail for a sandbox document the validator refused to send
#: because the miner does not advertise ``sandbox-lease-v1``. The document
#: never reached the miner; the runtime treats it as ineligible, not faulty.
SANDBOX_CAPABILITY_UNSUPPORTED: Final = "sandbox_capability_unsupported"
#: Stable detail when the agent's answer is not a receipt for this document.
SANDBOX_RECEIPT_MISMATCH: Final = "sandbox_receipt_mismatch"

SandboxID = Annotated[str, StringConstraints(pattern=r"^sbx-[0-9a-f]{32}$")]
#: A sandbox document as a JSON object, forwarded without reinterpretation.
SandboxDocument = dict[str, JsonValue]


class _RoutingView(BaseModel):
    """Read-only view of the members routing needs; every other member is
    left to the Go contract, which rejects unknown or invalid ones."""

    model_config = ConfigDict(extra="ignore", strict=True, frozen=True, populate_by_name=True)

    contract_schema: str = Field(alias="schema")
    schema_version: Literal[1]
    sandbox_id: SandboxID
    generation: PositiveCount
    miner_id: Hotkey


class SandboxDocumentHeader(_RoutingView):
    subnet: StaticSubnetBinding

    @model_validator(mode="after")
    def miner_is_bound(self) -> Self:
        if self.miner_id != self.subnet.miner_hotkey:
            raise ValueError("miner_id_mismatch")
        return self


class _ReceiptView(_RoutingView):
    document_schema: str


def document_header(document: SandboxDocument, kind: str) -> SandboxDocumentHeader:
    """The routing header of a validator document sent on route ``kind``.

    Raises ``ValueError`` with a stable code: ``sandbox_document_kind_mismatch``
    for a document of another kind (a lease on the reservation route, a
    receipt, a ``deployment.v4`` or static ticket), ``sandbox_document_invalid``
    for a missing or malformed identity or binding.
    """

    expected = DOCUMENT_SCHEMAS.get(kind)
    if expected is None:
        raise ValueError("sandbox_route_unknown")
    if document.get("schema") != expected:
        raise ValueError("sandbox_document_kind_mismatch")
    try:
        return SandboxDocumentHeader.model_validate(document)
    except ValueError as exc:
        # A stable code: validation messages would echo document members.
        raise ValueError("sandbox_document_invalid") from exc


def receipt_answers(receipt: SandboxDocument, header: SandboxDocumentHeader, kind: str) -> None:
    """Refuse an agent answer that is not a receipt for exactly this document.

    The miner signature and the document digest are verified by the Go
    runtime; this only keeps a miswired answer from being relayed.
    """

    try:
        view = _ReceiptView.model_validate(receipt)
    except ValueError as exc:
        raise ValueError(SANDBOX_RECEIPT_MISMATCH) from exc
    if (
        view.contract_schema != RECEIPT_SCHEMA
        or view.document_schema != DOCUMENT_SCHEMAS[kind]
        or view.sandbox_id != header.sandbox_id
        or view.generation != header.generation
        or view.miner_id != header.miner_id
    ):
        raise ValueError(SANDBOX_RECEIPT_MISMATCH)


class SandboxSynapseV1(StrictFrozenModel):
    """Validator -> miner: one validator-signed sandbox document."""

    protocol: Literal["subnet-sandbox-synapse.v1"]
    request_id: RequestID
    current_block: Count
    caller_hotkey: Hotkey
    validator_binding: ServiceKeyBinding
    document: SandboxDocument


class LocalSandboxRequestV1(StrictFrozenModel):
    """Miner Python -> Go agent loopback form of one btauth-verified document."""

    protocol: Literal["subnet-sandbox-synapse.v1"]
    request_id: RequestID
    current_block: Count
    caller_hotkey: Hotkey
    binding_verified: Literal[True]
    validator_binding: ServiceKeyBinding
    document: SandboxDocument


class BridgeSandboxRequestV1(StrictFrozenModel):
    """Validator runtime -> validator neuron loopback request to send one document."""

    protocol: Literal["subnet-sandbox-synapse.v1"]
    request_id: RequestID
    document: SandboxDocument


class SandboxResponseV1(StrictFrozenModel):
    """Go agent -> miner -> validator: the miner-signed receipt for the document."""

    protocol: Literal["subnet-sandbox-synapse.v1"]
    request_id: RequestID
    receipt: SandboxDocument


# ``subnet-sandbox-ops-synapse.v1``: transport for sandbox-ops-v1 op requests
# (``docs/sandbox-ops-v1.md``). Off by default and separate from the lease
# envelope: the neurons register the ops routes only with ``--sandbox-ops on``
# (which requires ``--sandbox-leases on``). As for leases, Python only
# authenticates and forwards: the op document, its payload and the receipt's
# result bytes travel unchanged; the Go agent verifies the document and the
# payload binding, and the Go runtime verifies the receipt and result.

OPS_SYNAPSE_VERSION: Final = "subnet-sandbox-ops-synapse.v1"
#: Advertised by a miner agent whose lane runs the ops extension.
OPS_CAPABILITY_FEATURE: Final = "sandbox-ops-v1"
OP_REQUEST_SCHEMA: Final = _SCHEMA_PREFIX + "sandbox-op-request"
OP_RECEIPT_SCHEMA: Final = _SCHEMA_PREFIX + "sandbox-op-receipt"
#: Stable bridge detail for an op the validator refused to send because the
#: miner does not advertise both ``sandbox-lease-v1`` and ``sandbox-ops-v1``.
SANDBOX_OPS_CAPABILITY_UNSUPPORTED: Final = "sandbox_ops_capability_unsupported"
#: A payload or result chunk: at most 512 KiB raw, standard padded base64.
OpChunk = Annotated[str, StringConstraints(max_length=699052, pattern=r"^[A-Za-z0-9+/]*={0,2}$")]


def op_header(document: SandboxDocument) -> SandboxDocumentHeader:
    """The routing header of a validator-signed op request.

    Raises ``ValueError`` with ``sandbox_document_kind_mismatch`` for any other
    document and ``sandbox_document_invalid`` for a missing or malformed
    identity or binding.
    """

    if document.get("schema") != OP_REQUEST_SCHEMA:
        raise ValueError("sandbox_document_kind_mismatch")
    try:
        return SandboxDocumentHeader.model_validate(document)
    except ValueError as exc:
        raise ValueError("sandbox_document_invalid") from exc


class _OpReceiptView(_RoutingView):
    op_id: str


def op_receipt_answers(receipt: SandboxDocument, header: SandboxDocumentHeader) -> None:
    """Refuse an agent answer that is not an op receipt for this request.

    The miner signature, the document digest and the result binding are
    verified by the Go runtime; this only keeps a miswired answer from being
    relayed.
    """

    try:
        view = _OpReceiptView.model_validate(receipt)
    except ValueError as exc:
        raise ValueError(SANDBOX_RECEIPT_MISMATCH) from exc
    if (
        view.contract_schema != OP_RECEIPT_SCHEMA
        or view.sandbox_id != header.sandbox_id
        or view.generation != header.generation
        or view.miner_id != header.miner_id
    ):
        raise ValueError(SANDBOX_RECEIPT_MISMATCH)


class SandboxOpsSynapseV1(StrictFrozenModel):
    """Validator -> miner: one validator-signed op request and its payload."""

    protocol: Literal["subnet-sandbox-ops-synapse.v1"]
    request_id: RequestID
    current_block: Count
    caller_hotkey: Hotkey
    validator_binding: ServiceKeyBinding
    document: SandboxDocument
    payload_b64: OpChunk | None


class LocalSandboxOpsRequestV1(StrictFrozenModel):
    """Miner Python -> Go agent loopback form of one btauth-verified op."""

    protocol: Literal["subnet-sandbox-ops-synapse.v1"]
    request_id: RequestID
    current_block: Count
    caller_hotkey: Hotkey
    binding_verified: Literal[True]
    validator_binding: ServiceKeyBinding
    document: SandboxDocument
    payload_b64: OpChunk | None


class BridgeSandboxOpsRequestV1(StrictFrozenModel):
    """Validator runtime -> validator neuron loopback request to send one op."""

    protocol: Literal["subnet-sandbox-ops-synapse.v1"]
    request_id: RequestID
    document: SandboxDocument
    payload_b64: OpChunk | None


class SandboxOpsResponseV1(StrictFrozenModel):
    """Go agent -> miner -> validator: the miner-signed op receipt and result."""

    protocol: Literal["subnet-sandbox-ops-synapse.v1"]
    request_id: RequestID
    receipt: SandboxDocument
    result_b64: OpChunk | None
