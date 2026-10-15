# SPDX-License-Identifier: AGPL-3.0-only
"""Operator configuration must not silently discover, broaden, or repair identities."""

import sys
from types import ModuleType

import bittensor as bt
import pytest

from misscomputer_subnet import miner, validator
from misscomputer_subnet.operator_policy import (
    configured_operator_hotkeys,
    validate_operator_hotkeys,
)

OPERATOR = str(bt.sp_core.Keypair.create_from_uri("//Operator").ss58_address)
OTHER = str(bt.sp_core.Keypair.create_from_uri("//OtherOperator").ss58_address)


@pytest.mark.parametrize(
    ("cli", "env", "expected"),
    [
        (None, None, frozenset()),
        ([], OPERATOR, frozenset()),
        (None, OPERATOR + "," + OTHER, frozenset({OPERATOR, OTHER})),
        ([OPERATOR, OTHER], None, frozenset({OPERATOR, OTHER})),
        ([OPERATOR], OTHER, frozenset({OPERATOR})),
        ([OPERATOR], "invalid-env-is-overridden", frozenset({OPERATOR})),
    ],
)
def test_operator_configuration_selection(
    cli: list[str] | None, env: str | None, expected: frozenset[str]
) -> None:
    assert configured_operator_hotkeys(cli, env) == expected


@pytest.mark.parametrize(
    "entry",
    ["", " ", OPERATOR + " ", "//Operator", "not-an-address", OPERATOR[:-1] + "0"],
)
def test_constructor_policy_rejects_invalid_entries_without_dropping_them(entry: str) -> None:
    with pytest.raises(ValueError, match="operator hotkey"):
        validate_operator_hotkeys([OPERATOR, entry])


@pytest.mark.parametrize("module", [miner, validator])
@pytest.mark.parametrize("source", ["cli", "env"])
@pytest.mark.parametrize("entry", ["", "bad-address"])
def test_invalid_operator_configuration_fails_before_secret_or_chain_access(
    monkeypatch: pytest.MonkeyPatch, module: ModuleType, source: str, entry: str
) -> None:
    monkeypatch.delenv("MC_OPERATOR_HOTKEYS", raising=False)
    args = [
        "neuron",
        "--netuid",
        "24",
        "--bridge-secret-file",
        "/must-not-be-read",
        "--state-db",
        "/must-not-be-opened",
    ]
    if source == "env":
        monkeypatch.setenv("MC_OPERATOR_HOTKEYS", OPERATOR + "," + entry)
    else:
        args.extend(["--operator-hotkey", OPERATOR, "--operator-hotkey", entry])
    monkeypatch.setattr(sys, "argv", args)
    with pytest.raises(SystemExit, match="operator hotkey"):
        module.main()
