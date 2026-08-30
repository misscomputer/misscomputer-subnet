# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import base64

import pytest

from misscomputer_subnet.ed25519_trust import (
    Ed25519PublicKeyValidationError,
    decode_ed25519_public_key_base64,
)


def test_complete_small_order_encoding_set_is_rejected(
    small_order_ed25519_public_key: bytes,
) -> None:
    encoded = base64.b64encode(small_order_ed25519_public_key).decode("ascii")
    with pytest.raises(Ed25519PublicKeyValidationError) as caught:
        decode_ed25519_public_key_base64(encoded)
    assert caught.value.code == "ed25519_public_key_small_order"
    assert str(caught.value) == "ed25519_public_key_small_order"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "!" * 44,
        base64.b64encode(b"x" * 31).decode("ascii"),
        base64.b64encode(b"x" * 33).decode("ascii"),
        base64.b64encode(b"x" * 32).decode("ascii").rstrip("="),
    ],
)
def test_noncanonical_or_wrong_length_public_key_encoding_is_rejected(value: str) -> None:
    with pytest.raises(Ed25519PublicKeyValidationError) as caught:
        decode_ed25519_public_key_base64(value)
    assert caught.value.code == "ed25519_public_key_encoding_invalid"
    assert str(caught.value) == "ed25519_public_key_encoding_invalid"


@pytest.mark.parametrize(
    "public_hex",
    [
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    ],
)
def test_representative_valid_public_keys_are_preserved(public_hex: str) -> None:
    public_bytes = bytes.fromhex(public_hex)
    encoded = base64.b64encode(public_bytes).decode("ascii")
    assert decode_ed25519_public_key_base64(encoded) == public_bytes
