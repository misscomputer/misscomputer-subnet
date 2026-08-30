# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical fail-closed validation for trusted Ed25519 public keys."""

from __future__ import annotations

import base64
import binascii
from typing import Final, Literal

Ed25519PublicKeyRejection = Literal[
    "ed25519_public_key_encoding_invalid",
    "ed25519_public_key_small_order",
]


class Ed25519PublicKeyValidationError(ValueError):
    """Stable rejection for an invalid trusted Ed25519 public key."""

    def __init__(self, code: Ed25519PublicKeyRejection) -> None:
        super().__init__(code)
        self.code = code


# The complete small-order blacklist used by Ed25519 verification libraries,
# represented with the encoded x-sign bit cleared. Checking the input with that
# bit cleared covers both encodings for each point, including the non-canonical
# identity encodings. A trust anchor on any of these points is unsafe even when
# a particular verification backend happens to reject some forged signatures.
_SMALL_ORDER_ED25519_ENCODINGS: Final = frozenset(
    bytes.fromhex(value)
    for value in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )
)


def decode_ed25519_public_key_base64(value: str) -> bytes:
    """Decode one canonical padded-base64 Ed25519 public key and reject torsion."""

    try:
        if not isinstance(value, str):
            raise TypeError
        public_bytes = base64.b64decode(value, validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise Ed25519PublicKeyValidationError("ed25519_public_key_encoding_invalid") from exc
    if len(public_bytes) != 32 or base64.b64encode(public_bytes).decode("ascii") != value:
        raise Ed25519PublicKeyValidationError("ed25519_public_key_encoding_invalid")
    sign_cleared = public_bytes[:31] + bytes((public_bytes[31] & 0x7F,))
    if sign_cleared in _SMALL_ORDER_ED25519_ENCODINGS:
        raise Ed25519PublicKeyValidationError("ed25519_public_key_small_order")
    return public_bytes
