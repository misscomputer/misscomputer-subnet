# SPDX-License-Identifier: AGPL-3.0-only
"""Version-stable public-address policy shared with the Go control plane."""

from __future__ import annotations

import ipaddress
import json
from importlib import resources
from pathlib import Path
from typing import Any

POLICY_NAME = "iana-special-purpose-address-policy"
POLICY_VERSION = 1
POLICY_RESOURCE = "iana-special-purpose.v1.json"


def _read_policy() -> bytes:
    packaged = resources.files("misscomputer_subnet").joinpath(POLICY_RESOURCE)
    try:
        return packaged.read_bytes()
    except FileNotFoundError:
        # Editable source checkouts consume the exact file embedded by Go. The
        # wheel force-includes that same file at the packaged path above.
        source = Path(__file__).resolve().parents[2] / "pkg" / "netpolicy" / POLICY_RESOURCE
        return source.read_bytes()


def _load_policy() -> tuple[
    dict[int, tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]], dict[str, Any]
]:
    parsed: Any = json.loads(_read_policy())
    if not isinstance(parsed, dict):
        raise RuntimeError("shared address policy must be a JSON object")
    if parsed.get("policy") != POLICY_NAME or parsed.get("version") != POLICY_VERSION:
        raise RuntimeError("shared address policy has an unexpected identity")
    raw_prefixes = parsed.get("deny_prefixes")
    if not isinstance(raw_prefixes, list) or not raw_prefixes:
        raise RuntimeError("shared address policy has no denied prefixes")
    grouped: dict[int, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {4: [], 6: []}
    for raw in raw_prefixes:
        if not isinstance(raw, str):
            raise RuntimeError("shared address policy contains a non-string prefix")
        network = ipaddress.ip_network(raw, strict=True)
        # strict=True rejects host bits. Do not compare with_prefixlen text:
        # Python 3.10 renders the IPv4-mapped /96 with dotted IPv4 while newer
        # versions retain hexadecimal text, even though the network is exact.
        grouped[network.version].append(network)
    return {version: tuple(networks) for version, networks in grouped.items()}, parsed


_DENIED_PREFIXES, _DOCUMENT = _load_policy()


def canonical_public_address(value: str) -> str:
    """Return one stable numeric identity or reject special-purpose space."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("address is not a public numeric IP") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
        raise ValueError("scoped IPv6 addresses are not public endpoint identities")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        raise ValueError("IPv4-mapped IPv6 addresses are not public endpoint identities")
    if any(address in network for network in _DENIED_PREFIXES[address.version]):
        raise ValueError("address belongs to denied special-purpose space")
    return address.compressed


def regression_cases() -> tuple[dict[str, Any], ...]:
    """Expose immutable copies of the shared corpus to cross-runtime tests."""

    cases = _DOCUMENT.get("regression_cases")
    if not isinstance(cases, list):
        raise RuntimeError("shared address policy has no regression corpus")
    if not all(isinstance(item, dict) for item in cases):
        raise RuntimeError("shared address regression corpus is malformed")
    return tuple(dict(item) for item in cases)
