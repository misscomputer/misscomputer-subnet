# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit operator identity configuration; chain eligibility is not authority."""

from collections.abc import Collection, Sequence

import bittensor as bt


def validate_operator_hotkeys(hotkeys: Collection[str]) -> frozenset[str]:
    """Validate canonical SS58 hotkeys without discovering or adding identities."""

    if isinstance(hotkeys, (str, bytes)):
        raise ValueError("operator hotkeys must be a collection of SS58 addresses")
    for hotkey in hotkeys:
        if not isinstance(hotkey, str) or not hotkey or hotkey != hotkey.strip():
            raise ValueError("operator hotkey must be a nonempty canonical SS58 address")
        try:
            canonical = bt.sp_core.ss58_encode(bt.sp_core.ss58_decode(hotkey))
        except (ValueError, TypeError) as exc:
            raise ValueError("operator hotkey must be a canonical SS58 address") from exc
        if canonical != hotkey:
            raise ValueError("operator hotkey must use the canonical Bittensor SS58 format")
    return frozenset(hotkeys)


def configured_operator_hotkeys(
    cli_hotkeys: Sequence[str] | None, env_value: str | None
) -> frozenset[str]:
    """CLI replaces env configuration; no configuration means deny everyone."""

    hotkeys = (
        cli_hotkeys
        if cli_hotkeys is not None
        else ([] if env_value is None else env_value.split(","))
    )
    return validate_operator_hotkeys(hotkeys)
