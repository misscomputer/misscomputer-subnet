# SPDX-License-Identifier: AGPL-3.0-only
"""Versioned Python/Go contracts carried over Bittensor btauth/1 HTTP."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Iterable
from datetime import datetime
from typing import Annotated, Final, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, model_validator

SYNAPSE_VERSION: Final[Literal["subnet-synapse.v2"]] = "subnet-synapse.v2"
HEALTH_OBSERVATION_VERSION: Final[Literal["subnet-synapse.v3"]] = "subnet-synapse.v3"
SERVICE_BINDING_VERSION: Final[Literal["service-binding.v2"]] = "service-binding.v2"

Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
NonEmpty = Annotated[str, StringConstraints(min_length=1, max_length=2048)]
EndpointID = Annotated[str, StringConstraints(min_length=3, max_length=320)]

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
    # Normalized assignment-time miner axon, signed into every deployment.v4
    # ticket.
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


class StatusSynapse(StrictModel):
    protocol: Literal["subnet-synapse.v2"] = "subnet-synapse.v2"
    request_id: NonEmpty
    current_block: int = Field(ge=0)
    caller_hotkey: NonEmpty
    endpoint_id: NonEmpty


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


#: Control-plane capability: the runtime accepts ``miner-registration.v3``.
MINER_REGISTRATION_V3_FEATURE: Final = "miner-registration-v3"
MINER_REGISTRATION_V3_PROTOCOL: Final = "subnet-synapse.v3"
MAX_REGISTRATION_FEATURES = 32
_FEATURE_TOKEN = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")


def registration_features(advertised: Iterable[str]) -> list[str]:
    """The deterministic feature set a v3 registration carries.

    Only well-formed tokens from the miner's capability response are kept,
    sorted and de-duplicated, at most ``MAX_REGISTRATION_FEATURES``. A miner
    whose list is malformed therefore only loses capabilities; it can never
    make its registration (and so its organic work) invalid.
    """

    tokens = sorted({item for item in advertised if _FEATURE_TOKEN.fullmatch(item)})
    return tokens[:MAX_REGISTRATION_FEATURES]


class MinerRegistrationV3(MinerRegistration):
    """``miner-registration.v3``: v2 plus the capability features.

    ``features`` are exactly the (normalized) ``features`` of the capability
    response that carried this registration's hotkey-signed service binding,
    received over the connection pinned to that binding's TLS leaf. Absent
    features mean "not capable"; there is no default capability.
    """

    protocol: Literal["subnet-synapse.v3"]  # type: ignore[assignment]
    features: list[str] = Field(max_length=MAX_REGISTRATION_FEATURES)

    @model_validator(mode="after")
    def canonical_features(self) -> MinerRegistrationV3:
        if self.features != registration_features(self.features):
            raise ValueError("registration features must be sorted, unique feature tokens")
        return self


def parse_miner_registration(value: object) -> MinerRegistration:
    """Parse a v2 or v3 registration by its ``protocol``."""

    if isinstance(value, dict) and value.get("protocol") == MINER_REGISTRATION_V3_PROTOCOL:
        return MinerRegistrationV3.model_validate(value)
    return MinerRegistration.model_validate(value)


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
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        json_schema_extra={
            "allOf": [
                {
                    "if": {"properties": {"correct": {"const": True}}, "required": ["correct"]},
                    "then": {"properties": {"reachable": {"const": True}}},
                },
                {
                    "if": {
                        "properties": {"fraudulent": {"const": True}},
                        "required": ["fraudulent"],
                    },
                    "then": {
                        "properties": {
                            "correct": {"const": False},
                            "reachable": {"const": True},
                        }
                    },
                },
            ]
        },
    )
    protocol: Literal["subnet-synapse.v3"]
    deployment_id: NonEmpty
    replica_id: NonEmpty
    endpoint_id: EndpointID
    miner_hotkey: NonEmpty
    vantage: NonEmpty
    reachable: bool
    correct: bool
    fraudulent: bool
    latency_ms: int = Field(ge=0, le=9_223_372_036_854_775_807)
    availability: float = Field(ge=0, le=1)
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_evidence_semantics(self) -> HealthObservation:
        if self.correct and not self.reachable:
            raise ValueError("a correct response must be reachable")
        if self.fraudulent and (not self.reachable or self.correct):
            raise ValueError("fraud evidence must be reachable and incorrect")
        return self


def utc_now() -> datetime:
    return datetime.now().astimezone()
