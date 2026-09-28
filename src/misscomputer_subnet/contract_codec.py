# SPDX-License-Identifier: AGPL-3.0-only
"""Shared canonical JSON, digest, and strict parsing helpers for versioned contracts.

Every versioned contract in this package is sealed the same way: the document
is rendered as sorted-key, compact, ASCII-only JSON; its self digest is the
SHA-256 of that rendering without the digest field; the on-disk and on-wire
form adds exactly one trailing newline. The pre-existing contract families keep
their private copies of these helpers untouched; the contract-checkpoint
modules share this one so that they cannot drift from each other.

This module is pure: no clock, network, file, process, environment, wallet,
chain, randomness, or signing capability.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Final, NoReturn, cast

from pydantic import BaseModel, ConfigDict

MAX_CONTRACT_DOCUMENT_BYTES: Final = 64 * 1_024 * 1_024


class StrictFrozenModel(BaseModel):
    """Base for every checkpoint contract: unknown keys, coercion, and mutation are refused."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


def canonical_json(value: object) -> bytes:
    """Render the canonical ASCII JSON bytes shared by every Miss Computer contract."""

    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("canonical_json_invalid") from exc
    return rendered.encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def model_document(model: BaseModel, *, exclude: set[str] | None = None) -> dict[str, object]:
    return cast(
        dict[str, object],
        model.model_dump(mode="json", by_alias=True, exclude=exclude),
    )


def verify_model_digest(model: BaseModel, field_name: str) -> None:
    document = model_document(model, exclude={field_name})
    if cast(str, getattr(model, field_name)) != digest(document):
        raise ValueError(f"{field_name}_mismatch")


def revalidate[ModelT: BaseModel](value: ModelT, model_type: type[ModelT]) -> ModelT:
    return model_type.model_validate(value.model_dump(mode="json", by_alias=True))


def model_bytes[ModelT: BaseModel](value: ModelT, model_type: type[ModelT]) -> bytes:
    """Canonical file/wire bytes: canonical JSON plus exactly one trailing newline."""

    value = revalidate(value, model_type)
    return canonical_json(model_document(value)) + b"\n"


def _reject_nonstandard_constant(value: str) -> NoReturn:
    raise ValueError(f"nonstandard_json_constant:{value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_key")
        value[key] = item
    return value


def parse_model[ModelT: BaseModel](
    rendered: bytes,
    model_type: type[ModelT],
    canonicalizer: Callable[[ModelT], bytes],
    *,
    maximum_bytes: int = MAX_CONTRACT_DOCUMENT_BYTES,
) -> ModelT:
    """Parse exact canonical bytes; any malleability or size violation is rejected."""

    if not rendered or len(rendered) > maximum_bytes:
        raise ValueError("document_size_invalid")
    try:
        document = json.loads(
            rendered.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonstandard_constant,
        )
        model = model_type.model_validate(document)
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError("document_invalid") from exc
    if rendered != canonicalizer(model):
        raise ValueError("document_not_canonical")
    return model
