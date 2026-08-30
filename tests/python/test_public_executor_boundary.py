# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import ast
from pathlib import Path

import misscomputer_subnet.weight_executor as executor


def test_executor_imports_without_private_signer_implementation() -> None:
    source = Path(executor.__file__).read_text()
    tree = ast.parse(source)
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    )
    assert all(
        "weight_signer" not in name or name.endswith("weight_signer_protocol") for name in imported
    )
