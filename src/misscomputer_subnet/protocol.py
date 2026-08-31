# SPDX-License-Identifier: AGPL-3.0-only
"""Versioned Python/Go contracts carried over Bittensor btauth/1 HTTP."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from datetime import datetime
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

SYNAPSE_VERSION: Final[Literal["subnet-synapse.v2"]] = "subnet-synapse.v2"
BOUND_TICKET_VERSION: Final[Literal["deployment.v3"]] = "deployment.v3"
SERVICE_BINDING_VERSION: Final[Literal["service-binding.v2"]] = "service-binding.v2"

Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
HexSignature = Annotated[str, StringConstraints(pattern=r"^(?:0x)?[0-9a-f]{128}$")]
NonEmpty = Annotated[str, StringConstraints(min_length=1, max_length=2048)]

_RFC3339_NANO = re.compile(
    r"^(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?P<zone>Z|[+-][0-9]{2}:[0-9]{2})$"
)
_MONTH_DAYS = (0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _is_leap_year(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _civil_day(year: int, month: int, day: int) -> int:
    """Return a proleptic Gregorian day number, including Go's year zero."""
    adjusted_year = year - (1 if month <= 2 else 0)
    era = adjusted_year // 400
    year_of_era = adjusted_year - era * 400
    shifted_month = month + (-3 if month > 2 else 9)
    day_of_year = (153 * shifted_month + 2) // 5 + day - 1
    return era * 146_097 + year_of_era * 365 + year_of_era // 4 - year_of_era // 100 + day_of_year


def _rfc3339nano_instant(value: str) -> int:
    """Parse a Go RFC3339Nano string without losing its signed nanoseconds."""
    match = _RFC3339_NANO.fullmatch(value)
    if match is None:
        raise ValueError("timestamp must use Go RFC3339Nano format")
    parts = {
        name: int(match.group(name))
        for name in ("year", "month", "day", "hour", "minute", "second")
    }
    month = parts["month"]
    if month < 1 or month > 12:
        raise ValueError("timestamp month is out of range")
    month_days = _MONTH_DAYS[month] + (1 if month == 2 and _is_leap_year(parts["year"]) else 0)
    if parts["day"] < 1 or parts["day"] > month_days:
        raise ValueError("timestamp day is out of range")
    if parts["hour"] > 23 or parts["minute"] > 59 or parts["second"] > 59:
        raise ValueError("timestamp time is out of range")

    fraction = match.group("fraction") or ""
    if fraction.endswith("0"):
        raise ValueError("timestamp must use canonical Go RFC3339Nano format")

    zone = match.group("zone")
    offset_seconds = 0
    if zone != "Z":
        offset_hours = int(zone[1:3])
        offset_minutes = int(zone[4:6])
        if offset_hours > 23 or offset_minutes > 59:
            raise ValueError("timestamp UTC offset is out of range")
        offset_seconds = (offset_hours * 60 + offset_minutes) * 60
        if offset_seconds == 0:
            raise ValueError("timestamp must use canonical Go RFC3339Nano format")
        if zone[0] == "-":
            offset_seconds = -offset_seconds

    nanoseconds = int(fraction.ljust(9, "0")) if fraction else 0
    local_seconds = (
        _civil_day(parts["year"], month, parts["day"]) * 86_400
        + parts["hour"] * 3_600
        + parts["minute"] * 60
        + parts["second"]
    )
    return (local_seconds - offset_seconds) * 1_000_000_000 + nanoseconds


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ResourceLimits(StrictModel):
    cpu_millis: int = Field(ge=1, le=128_000)
    memory_mb: int = Field(ge=16, le=1_048_576)
    disk_mb: int = Field(ge=16, le=10_485_760)


class HealthSpec(StrictModel):
    path: Annotated[str, StringConstraints(pattern=r"^/", max_length=1024)]
    expected_status: int = Field(ge=100, le=599)
    interval_millis: int = Field(ge=1, le=300_000)
    timeout_millis: int = Field(ge=1, le=900_000)
    consecutive_failure: int = Field(ge=1, le=100)


class AttestationPolicy(StrictModel):
    technology: str = ""
    allowed_measurements: list[str] = Field(default_factory=list, max_length=128)
    kbs_grant_id: str = ""


class SubnetBinding(StrictModel):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"miner_transport": {"const": "https"}},
                        "required": ["miner_transport"],
                    },
                    "then": {
                        "properties": {
                            "miner_tls_certificate_sha256": {
                                "pattern": r"^[0-9a-f]{64}$",
                                "type": "string",
                            }
                        }
                    },
                },
                {
                    "if": {
                        "properties": {"miner_transport": {"const": "http"}},
                        "required": ["miner_transport"],
                    },
                    "then": {"properties": {"miner_tls_certificate_sha256": {"type": "null"}}},
                },
            ]
        }
    )
    network: NonEmpty
    netuid: int = Field(ge=0, le=65_535)
    validator_hotkey: NonEmpty
    miner_hotkey: NonEmpty
    miner_uid: int | None = Field(default=None, ge=0, le=65_535)
    # Normalized assignment-time miner axon, signed into every v3 ticket.
    # Legacy tickets use older protocol versions and fail before this model.
    miner_axon_url: NonEmpty
    miner_transport: Literal["https", "http"]
    miner_tls_certificate_sha256: Hex64 | None
    chain_block: int = Field(ge=0)
    epoch: int = Field(ge=0)
    expires_at_block: int = Field(ge=1)
    validator_service_public_key: Hex64
    miner_service_public_key: Hex64

    @model_validator(mode="after")
    def valid_block_window(self) -> SubnetBinding:
        if self.expires_at_block <= self.chain_block:
            raise ValueError("expires_at_block must follow chain_block")
        if self.miner_transport == "https" and self.miner_tls_certificate_sha256 is None:
            raise ValueError("HTTPS miner binding requires a TLS certificate fingerprint")
        if self.miner_transport == "http" and self.miner_tls_certificate_sha256 is not None:
            raise ValueError("HTTP miner binding must not carry a TLS certificate fingerprint")
        return self


class Ticket(StrictModel):
    version: Literal["deployment.v3"]
    deployment_id: NonEmpty
    generation: int = Field(ge=1)
    image_digest: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    manifest_key: NonEmpty
    miner_id: NonEmpty
    route_host: NonEmpty
    assignment_nonce: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    challenge_path: Annotated[str, StringConstraints(pattern=r"^/", max_length=1024)]
    challenge_sha256: Hex64
    resources: ResourceLimits
    health: HealthSpec
    # Signed Go RFC3339Nano values must remain exact strings. Python datetime
    # normalizes to microseconds and would invalidate the Ed25519 signature.
    issued_at: NonEmpty
    expires_at: NonEmpty
    attestation: AttestationPolicy | None = None
    encrypted_image_key: str = ""
    subnet: SubnetBinding
    signature: HexSignature

    @model_validator(mode="after")
    def exact_identity(self) -> Ticket:
        if self.miner_id != self.subnet.miner_hotkey:
            raise ValueError("miner_id must equal subnet.miner_hotkey")
        issued = _rfc3339nano_instant(self.issued_at)
        expires = _rfc3339nano_instant(self.expires_at)
        if expires <= issued:
            raise ValueError("expires_at must follow issued_at")
        return self


class Receipt(StrictModel):
    version: Literal["deployment.v3"]
    deployment_id: NonEmpty
    generation: int = Field(ge=1)
    assignment_nonce: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    miner_id: NonEmpty
    replica_id: NonEmpty
    endpoint_id: NonEmpty
    image_digest: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    manifest_key: NonEmpty
    route_host: NonEmpty
    # A literal is deliberate: strict Pydantic models reject a JSON string when
    # the destination is an Enum, even though strings are the on-wire format.
    stage: Literal["accepted", "ready", "failed"]
    assignment_seen: NonEmpty
    pull_started: NonEmpty
    pull_completed: NonEmpty
    runtime_started: NonEmpty
    health_passed: NonEmpty
    error: str = ""
    subnet: SubnetBinding
    signature: HexSignature


class MinerResult(StrictModel):
    receipt: Receipt
    endpoint_id: NonEmpty

    @model_validator(mode="after")
    def endpoint_matches(self) -> MinerResult:
        if self.endpoint_id != self.receipt.endpoint_id:
            raise ValueError("result endpoint_id must equal receipt endpoint_id")
        return self


class ServiceKeyBinding(StrictModel):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"role": {"const": "validator"}},
                        "required": ["role"],
                    },
                    "then": {
                        "properties": {
                            "transport": {"const": "local"},
                            "transport_certificate_sha256": {"type": "null"},
                        }
                    },
                },
                {
                    "if": {
                        "properties": {"role": {"const": "miner"}},
                        "required": ["role"],
                    },
                    "then": {"properties": {"transport": {"enum": ["https", "http"]}}},
                },
                {
                    "if": {
                        "properties": {"transport": {"const": "https"}},
                        "required": ["transport"],
                    },
                    "then": {
                        "properties": {
                            "transport_certificate_sha256": {
                                "pattern": r"^[0-9a-f]{64}$",
                                "type": "string",
                            }
                        }
                    },
                },
                {
                    "if": {
                        "properties": {"transport": {"enum": ["local", "http"]}},
                        "required": ["transport"],
                    },
                    "then": {"properties": {"transport_certificate_sha256": {"type": "null"}}},
                },
            ]
        }
    )
    protocol: Literal["service-binding.v2"] = "service-binding.v2"
    role: Literal["validator", "miner"]
    transport: Literal["local", "https", "http"]
    transport_certificate_sha256: Hex64 | None
    network: NonEmpty
    netuid: int = Field(ge=0, le=65_535)
    hotkey: NonEmpty
    uid: int | None = Field(default=None, ge=0, le=65_535)
    service_public_key: Hex64
    generation: int = Field(ge=1)
    valid_from_block: int = Field(ge=0)
    expires_at_block: int = Field(ge=1)
    challenge: NonEmpty
    signature: str = ""

    @model_validator(mode="after")
    def valid_window(self) -> ServiceKeyBinding:
        if self.expires_at_block <= self.valid_from_block:
            raise ValueError("service binding expiry must follow its start block")
        if self.role == "validator":
            if self.transport != "local" or self.transport_certificate_sha256 is not None:
                raise ValueError("validator service bindings must use pinless local transport")
        elif self.transport == "https":
            if self.transport_certificate_sha256 is None:
                raise ValueError("HTTPS miner service bindings require a TLS certificate pin")
        elif self.transport == "http":
            if self.transport_certificate_sha256 is not None:
                raise ValueError("HTTP miner service bindings must not carry a TLS certificate pin")
        else:
            raise ValueError("miner service bindings must use HTTPS or explicit mock HTTP")
        return self

    def signing_payload(self) -> bytes:
        value = self.model_dump(mode="json", exclude={"signature"})
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class CapabilitiesSynapse(StrictModel):
    protocol: Literal["subnet-synapse.v2"] = "subnet-synapse.v2"
    request_id: NonEmpty
    network: NonEmpty
    netuid: int = Field(ge=0, le=65_535)
    chain_block: int = Field(ge=0)
    caller_hotkey: NonEmpty
    challenge: NonEmpty


class CapabilitiesResponse(StrictModel):
    protocol: Literal["subnet-synapse.v2"] = "subnet-synapse.v2"
    request_id: NonEmpty
    miner_hotkey: NonEmpty
    miner_uid: int | None = Field(default=None, ge=0, le=65_535)
    features: list[str]
    max_body_bytes: int = Field(ge=1, le=16 << 20)
    service_binding: ServiceKeyBinding


class DeploySynapse(StrictModel):
    protocol: Literal["subnet-synapse.v2"] = "subnet-synapse.v2"
    request_id: NonEmpty
    current_block: int = Field(ge=0)
    caller_hotkey: NonEmpty
    validator_binding: ServiceKeyBinding
    ticket: Ticket


class DeployResponse(StrictModel):
    protocol: Literal["subnet-synapse.v2"] = "subnet-synapse.v2"
    request_id: NonEmpty
    result: MinerResult
    idempotent: bool = False


class StatusSynapse(StrictModel):
    protocol: Literal["subnet-synapse.v2"] = "subnet-synapse.v2"
    request_id: NonEmpty
    current_block: int = Field(ge=0)
    caller_hotkey: NonEmpty
    endpoint_id: NonEmpty


class StatusResponse(StrictModel):
    protocol: Literal["subnet-synapse.v2"] = "subnet-synapse.v2"
    request_id: NonEmpty
    status: Literal["absent", "processing", "accepted", "ready", "failed", "deactivated"]
    receipt: Receipt | None = None


class DeactivateSynapse(StrictModel):
    protocol: Literal["subnet-synapse.v2"] = "subnet-synapse.v2"
    request_id: NonEmpty
    current_block: int = Field(ge=0)
    caller_hotkey: NonEmpty
    endpoint_id: NonEmpty
    deployment_id: NonEmpty


class DeactivateResponse(StrictModel):
    protocol: Literal["subnet-synapse.v2"] = "subnet-synapse.v2"
    request_id: NonEmpty
    status: Literal["deactivated", "absent"]


class LocalCapabilities(StrictModel):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"transport": {"const": "https"}},
                        "required": ["transport"],
                    },
                    "then": {
                        "properties": {
                            "transport_certificate_sha256": {
                                "pattern": r"^[0-9a-f]{64}$",
                                "type": "string",
                            }
                        }
                    },
                },
                {
                    "if": {
                        "properties": {"transport": {"const": "http"}},
                        "required": ["transport"],
                    },
                    "then": {"properties": {"transport_certificate_sha256": {"type": "null"}}},
                },
            ]
        }
    )
    protocol: Literal["subnet-synapse.v2"]
    network: NonEmpty
    netuid: int
    miner_hotkey: NonEmpty
    miner_uid: int | None = None
    service_public_key: Hex64
    transport: Literal["https", "http"]
    transport_certificate_sha256: Hex64 | None
    features: list[str]
    max_body_bytes: int

    @model_validator(mode="after")
    def valid_transport(self) -> LocalCapabilities:
        if self.transport == "https" and self.transport_certificate_sha256 is None:
            raise ValueError("HTTPS miner capabilities require a TLS certificate pin")
        if self.transport == "http" and self.transport_certificate_sha256 is not None:
            raise ValueError("HTTP miner capabilities must not carry a TLS certificate pin")
        return self


class ControlCapabilities(StrictModel):
    protocol: Literal["subnet-synapse.v2"]
    service_public_key: Hex64
    features: list[str]
    weights_enabled: bool


class RecoveryResponse(StrictModel):
    protocol: Literal["subnet-synapse.v2"]
    non_deactivated_assignments: int = Field(ge=0)
    # Unresolved members of the control plane's immutable startup recovery
    # snapshot; assignments created by the running process never enter it.
    pending_startup_assignments: int = Field(ge=0)


class BridgeAssignRequest(StrictModel):
    protocol: Literal["subnet-synapse.v2"]
    request_id: NonEmpty
    ticket: Ticket


class BridgeDeactivateRequest(StrictModel):
    """Cleanup bound to the exact authenticated identity of one assignment.

    A deactivation is transport for retiring durable state, so it must never
    resolve to a handle that merely shares the hotkey: the expected UID, axon,
    and service-key fingerprint pin the assignment's authenticated identity.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"miner_transport": {"const": "https"}},
                        "required": ["miner_transport"],
                    },
                    "then": {
                        "properties": {
                            "miner_tls_certificate_sha256": {
                                "pattern": r"^[0-9a-f]{64}$",
                                "type": "string",
                            }
                        }
                    },
                },
                {
                    "if": {
                        "properties": {"miner_transport": {"const": "http"}},
                        "required": ["miner_transport"],
                    },
                    "then": {"properties": {"miner_tls_certificate_sha256": {"type": "null"}}},
                },
            ]
        }
    )
    protocol: Literal["subnet-synapse.v2"]
    request_id: NonEmpty
    endpoint_id: NonEmpty
    deployment_id: NonEmpty
    miner_hotkey: NonEmpty
    miner_uid: int | None = Field(default=None, ge=0, le=65_535)
    axon_url: NonEmpty
    miner_service_public_key: Hex64
    miner_transport: Literal["https", "http"]
    miner_tls_certificate_sha256: Hex64 | None

    @model_validator(mode="after")
    def valid_transport(self) -> BridgeDeactivateRequest:
        if self.miner_transport == "https" and self.miner_tls_certificate_sha256 is None:
            raise ValueError("HTTPS cleanup identity requires a TLS certificate pin")
        if self.miner_transport == "http" and self.miner_tls_certificate_sha256 is not None:
            raise ValueError("HTTP cleanup identity must not carry a TLS certificate pin")
        return self


class MinerRegistration(StrictModel):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "service_binding": {
                                "properties": {"transport": {"const": "https"}},
                                "required": ["transport"],
                            }
                        },
                        "required": ["service_binding"],
                    },
                    "then": {"properties": {"transport_certificate_der_base64": {"minLength": 1}}},
                },
                {
                    "if": {
                        "properties": {
                            "service_binding": {
                                "properties": {"transport": {"const": "http"}},
                                "required": ["transport"],
                            }
                        },
                        "required": ["service_binding"],
                    },
                    "then": {"properties": {"transport_certificate_der_base64": {"const": ""}}},
                },
            ]
        }
    )
    protocol: Literal["subnet-synapse.v2"]
    network: NonEmpty
    netuid: int = Field(ge=0, le=65_535)
    hotkey: NonEmpty
    uid: int | None = Field(default=None, ge=0, le=65_535)
    axon_url: NonEmpty
    bridge_url: NonEmpty
    service_binding: ServiceKeyBinding
    transport_certificate_der_base64: str

    @model_validator(mode="after")
    def valid_transport_certificate(self) -> MinerRegistration:
        if self.service_binding.transport == "https":
            if not self.transport_certificate_der_base64:
                raise ValueError("HTTPS miner registration requires public certificate DER")
        elif self.transport_certificate_der_base64:
            raise ValueError("HTTP mock registration must not carry public certificate DER")
        return self

    @model_validator(mode="after")
    def valid_transport(self) -> MinerRegistration:
        binding = self.service_binding
        if binding.role != "miner":
            raise ValueError("miner registration requires a miner service binding")
        if binding.transport == "https":
            if not self.transport_certificate_der_base64:
                raise ValueError("HTTPS miner registration requires leaf certificate material")
            try:
                der = base64.b64decode(self.transport_certificate_der_base64, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ValueError("miner leaf certificate must use canonical base64 DER") from exc
            if (
                not der
                or len(der) > 64 << 10
                or base64.b64encode(der).decode() != self.transport_certificate_der_base64
                or hashlib.sha256(der).hexdigest() != binding.transport_certificate_sha256
            ):
                raise ValueError("miner leaf certificate does not match its signed pin")
        elif self.transport_certificate_der_base64:
            raise ValueError("HTTP miner registration must not carry certificate material")
        return self


class MinerSet(StrictModel):
    protocol: Literal["subnet-synapse.v2"]
    network: NonEmpty
    netuid: int = Field(ge=0, le=65_535)
    block: int = Field(ge=0)
    hotkeys: list[NonEmpty]


class ChainState(StrictModel):
    protocol: Literal["subnet-synapse.v2"]
    network: NonEmpty
    netuid: int = Field(ge=0, le=65_535)
    block: int = Field(ge=0)
    epoch: int = Field(ge=0)
    tempo: int = Field(ge=1)
    validator_hotkey: NonEmpty
    validator_binding: ServiceKeyBinding


class HealthObservation(StrictModel):
    protocol: Literal["subnet-synapse.v2"]
    deployment_id: NonEmpty
    replica_id: NonEmpty
    miner_hotkey: NonEmpty
    vantage: NonEmpty
    reachable: bool
    correct: bool
    fraudulent: bool
    latency_ms: int = Field(ge=0)
    availability: float = Field(ge=0, le=1)
    observed_at: datetime


def utc_now() -> datetime:
    return datetime.now().astimezone()
