# SPDX-License-Identifier: AGPL-3.0-only
"""Private index ingestion through the shipped static and combined CLI boundaries."""

from __future__ import annotations

import functools
import os
import time
from pathlib import Path

import pytest
from organic_context import EPOCH_START
from static_cli_context import (
    FakeTime,
    alice_signer,
    cli_config,
    config_argv,
    secure_write,
    write_static_publication,
)

import misscomputer_subnet.assignment_probe_cli as combined_cli
import misscomputer_subnet.static_probe_cli as static_cli
from misscomputer_subnet.assignment_probe_cli import (
    EXIT_DEGRADED,
    EXIT_OK,
    EXIT_REJECTED,
    EXIT_USAGE,
)
from misscomputer_subnet.static_index import MAX_MANIFEST_BYTES
from misscomputer_subnet.static_scoring import parse_static_epoch_score


def _private_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, combined: bool = False):
    publication = write_static_publication(tmp_path / "publication")
    parent = tmp_path / "inventory-parent"
    parent.mkdir(mode=0o700)
    spool = parent / "private-index"
    spool.mkdir(mode=0o700)
    for key, payload in publication.world.documents.items():
        path = spool
        for part in key.split("/")[:-1]:
            path /= part
            path.mkdir(mode=0o700, exist_ok=True)
        secure_write(spool / key, payload)
    config = cli_config(publication, tmp_path / "run")
    fake = FakeTime(EPOCH_START)
    cli = combined_cli if combined else static_cli
    execute_name = "execute_assignment_probe" if combined else "execute_static_probe"
    monkeypatch.setattr(
        cli,
        execute_name,
        functools.partial(
            getattr(cli, execute_name),
            transport_factory=lambda _context: publication.world,
            signer_factory=alice_signer,
            clock=fake.clock,
            sleep=fake.sleep,
        ),
    )
    argv = config_argv(config)
    source = argv.index("--static-index-origin")
    argv[source : source + 2] = ["--static-index-root", str(spool)]
    if not combined:
        organic_only = {
            "--manifest-file",
            "--manifest-sha256",
            "--signature-file",
            "--signature-sha256",
            "--state-root",
            "--trusted-state-anchor",
            "--epoch-output",
            "--manifest-archive-dir",
            "--static-sites",
        }
        argv = [
            value
            for option, argument in zip(argv[::2], argv[1::2], strict=True)
            for value in (option, argument)
            if option not in organic_only
        ]
    return publication, spool, config, cli, argv


@pytest.mark.parametrize("combined", [False, True])
def test_private_index_cli_scores_without_inventory_network_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, combined: bool
) -> None:
    publication, _spool, config, cli, argv = _private_run(tmp_path, monkeypatch, combined=combined)

    assert cli.run_cli(argv) == EXIT_OK

    epoch = parse_static_epoch_score(Path(config.static_sites.epoch_output).read_bytes())
    assert epoch.epoch_status == "scored" and len(epoch.observations) == 9
    assert {item.disposition for item in epoch.endpoints} == {"eligible"}
    assert {kind for kind, _ in publication.world.calls} == (
        {"static", "organic"} if combined else {"static"}
    )


@pytest.mark.parametrize(
    "fault,code",
    [
        ("missing", "static_index_unavailable"),
        ("manifest_changed", "static_index_invalid"),
        ("release_changed", "static_index_invalid"),
        ("oversized", "static_index_unavailable"),
        ("public_file", "static_index_unavailable"),
        ("public_directory", "static_index_unavailable"),
        ("writable_ancestor", "static_index_unavailable"),
        ("file_symlink", "static_index_unavailable"),
        ("directory_symlink", "static_index_unavailable"),
        ("root_symlink", "static_index_unavailable"),
        ("ancestor_symlink", "static_index_unavailable"),
        ("expired_budget", "static_index_unavailable"),
        ("hardlink", "static_index_unavailable"),
        ("fifo", "static_index_unavailable"),
        ("file_replacement", "static_index_unavailable"),
        ("directory_replacement", "static_index_unavailable"),
    ],
)
def test_private_index_fault_abstains_without_public_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str, code: str
) -> None:
    publication, spool, config, cli, argv = _private_run(tmp_path, monkeypatch)
    manifest = next(spool.glob("static-sites/v1/manifests/*.json"))
    release = next(spool.glob("static-sites/v1/releases/*.json"))
    original = manifest.read_bytes()
    if fault == "missing":
        manifest.unlink()
    elif fault == "manifest_changed":
        manifest.write_bytes(b"{}\n")
    elif fault == "release_changed":
        release.write_bytes(b"{}\n")
    elif fault == "oversized":
        manifest.write_bytes(b"x" * (MAX_MANIFEST_BYTES + 1))
    elif fault == "public_file":
        manifest.chmod(0o644)
    elif fault == "public_directory":
        spool.chmod(0o755)
    elif fault == "writable_ancestor":
        spool.parent.chmod(0o777)
    elif fault == "file_symlink":
        external = secure_write(tmp_path / "outside.json", original)
        manifest.unlink()
        manifest.symlink_to(external)
    elif fault in {"directory_symlink", "root_symlink", "ancestor_symlink"}:
        path = (
            manifest.parent
            if fault == "directory_symlink"
            else spool
            if fault == "root_symlink"
            else spool.parent
        )
        external = tmp_path / "outside-directory"
        path.rename(external)
        path.symlink_to(external, target_is_directory=True)
    elif fault == "hardlink":
        os.link(manifest, tmp_path / "outside.json")
    elif fault == "fifo":
        manifest.unlink()
        os.mkfifo(manifest, mode=0o600)
    else:
        # Swap an actual opened filesystem object during its read. The reader
        # must reject the old pinned inode even when its signed bytes are valid.
        original_read = os.read
        inode = manifest.stat().st_ino
        replaced = False
        if fault == "expired_budget":
            import misscomputer_subnet.static_runtime as runtime

            monkeypatch.setattr(runtime, "STATIC_INDEX_LOAD_BUDGET_SECONDS", 0.02)

        def racing_read(descriptor: int, size: int) -> bytes:
            nonlocal replaced
            payload = original_read(descriptor, size)
            if os.fstat(descriptor).st_ino == inode and not replaced:
                replaced = True
                if fault == "expired_budget":
                    time.sleep(0.04)
                elif fault == "file_replacement":
                    temporary = secure_write(manifest.parent / "next.json", original)
                    temporary.replace(manifest)
                else:
                    manifest.parent.rename(tmp_path / "old-manifests")
                    manifest.parent.mkdir(mode=0o700)
                    secure_write(manifest, original)
            return payload

        monkeypatch.setattr(os, "read", racing_read)

    assert cli.run_cli(argv) == EXIT_DEGRADED
    epoch = parse_static_epoch_score(Path(config.static_sites.epoch_output).read_bytes())
    assert [item.record_code for item in epoch.index_abstentions] == [code]
    assert epoch.observations == []
    assert publication.world.calls == []  # HTTPS index remains healthy but is never consulted.
    if fault in {"file_replacement", "directory_replacement", "expired_budget"}:
        assert replaced


@pytest.mark.parametrize("selection", ["both", "neither", "traversal", "file_url"])
def test_private_index_cli_refuses_ambiguous_or_nonlocal_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, selection: str
) -> None:
    publication, spool, config, cli, argv = _private_run(tmp_path, monkeypatch)
    index = argv.index("--static-index-root")
    if selection == "both":
        argv += ["--static-index-origin", "https://index.mock.local"]
    elif selection == "neither":
        del argv[index : index + 2]
    elif selection == "traversal":
        argv[index + 1] = str(spool) + "/../private-index"
    else:
        argv[index + 1] = "file://" + str(spool)

    assert cli.run_cli(argv) == (EXIT_USAGE if selection in {"both", "neither"} else EXIT_REJECTED)
    assert publication.world.calls == []
    assert not Path(config.static_sites.state_root).exists()
