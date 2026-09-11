#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Run the documented verifier-to-persistence composition, optionally at an old SHA.

Uses only synthetic fixture evidence and a temporary local state root. The old
module is read directly from git, not checked out or written over local code.
"""

from __future__ import annotations

import argparse
import inspect
import re
import shutil
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "python"))

from test_public_verifier import integration_inputs  # noqa: E402

import misscomputer_subnet.assignment_probe_cli as probe_cli  # noqa: E402
from misscomputer_subnet.assignment_probe import assignment_manifest_chain_state_bytes  # noqa: E402
from misscomputer_subnet.public_verifier import verify_public_relay_path  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-revision")
    revision = parser.parse_args().source_revision
    module = probe_cli
    if revision is not None:
        if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
            parser.error("source revision must be a complete commit SHA")
        git = shutil.which("git")
        if git is None:
            parser.error("git is required to read a pinned source revision")
        # The argument is restricted to a complete hexadecimal SHA plus a fixed path.
        source = subprocess.check_output(  # noqa: S603
            [git, "show", f"{revision}:src/misscomputer_subnet/assignment_probe_cli.py"],
            cwd=ROOT,
        )
        module = types.ModuleType("misscomputer_subnet._reproduction_probe_cli")
        module.__package__ = "misscomputer_subnet"
        sys.modules[module.__name__] = module
        # Execute exactly the user-selected local repository module, never shell text.
        exec(compile(source, f"{revision}:assignment_probe_cli.py", "exec"), module.__dict__)  # noqa: S102
    values = integration_inputs()
    result = verify_public_relay_path(**values)
    expected = result.manifest_verification.next_chain_state
    with tempfile.TemporaryDirectory(prefix="pr10-handoff-") as temporary:
        with module._StateRoot(temporary) as state:
            state.replace_state(assignment_manifest_chain_state_bytes(values["prior_chain_state"]))
        arguments = {
            "state_root": temporary,
            "trust_policy": values["trust_policy"],
            "history": values["history"],
            "evaluation_epoch": values["evaluation_epoch"],
            "expected_anchor_sha256": values["prior_chain_state"].state_digest_sha256,
            "expected_next_state_sha256": expected.state_digest_sha256,
        }
        # Follow the corresponding version's runbook/API. Before this repair
        # only the historical sequence was accepted; the current API explicitly
        # accepts and verifies the live head under the same lock.
        if (
            "head_manifest"
            in inspect.signature(module.persist_assignment_manifest_catch_up).parameters
        ):
            arguments.update(
                {
                    key: values[key]
                    for key in (
                        "head_manifest",
                        "head_signatures",
                        "current_finalized_height",
                    )
                }
            )
        try:
            persisted = module.persist_assignment_manifest_catch_up(**arguments)
        except module.AssignmentProbeCLIError as error:
            raise SystemExit(error.code) from None
        assert persisted == expected and persisted.last_sequence == 3
        print("verified and persisted exact live head: sequence=3")


if __name__ == "__main__":
    main()
