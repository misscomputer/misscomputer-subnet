# SPDX-License-Identifier: AGPL-3.0-only
"""Publication guards of scripts/sandbox-probes/publish-probes.sh, at the script boundary.

The tests run the real script. ``check-environment`` reads a local stand-in for GitHub's two
environment endpoints (through ``GITHUB_API_URL``); ``push`` runs against a stand-in ``oras``
on ``PATH`` that answers with the messages oras 1.3.4 prints. They pin the refusals the
security and integration reviews asked for: a publish environment that lets a dispatcher
approve their own run, and a tag lookup failure that only looks like "not found".
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sandbox-probes" / "publish-probes.sh"
REPO = "misscomputer/misscomputer-subnet"
ENVIRONMENT = "probe-publication"
REGISTRY = "ghcr.io/example/sandbox-probes"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("jq") is None, reason="needs bash and jq"
)


def run(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed script path and arguments
        [str(SCRIPT), *args], env=env, capture_output=True, text=True, check=False, timeout=120
    )


# ---- check-environment ---------------------------------------------------


class EnvironmentAPI(ThreadingHTTPServer):
    routes: dict[str, Any]


class EnvironmentHandler(BaseHTTPRequestHandler):
    server: EnvironmentAPI

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        body = self.server.routes.get(self.path)
        raw = json.dumps(body if body is not None else {"message": "Not Found"}).encode()
        self.send_response(200 if body is not None else 404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def api() -> Iterator[EnvironmentAPI]:
    server = EnvironmentAPI(("127.0.0.1", 0), EnvironmentHandler)
    server.routes = {}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def protected(**reviewer_rule: Any) -> dict[str, Any]:
    """The environment the owner steps describe; reviewer_rule overrides its reviewer rule."""
    rule = {
        "type": "required_reviewers",
        "prevent_self_review": True,
        "reviewers": [{"type": "User", "reviewer": {"login": "second-person"}}],
    }
    rule.update(reviewer_rule)
    rule = {key: value for key, value in rule.items() if value is not None}
    return {
        "name": ENVIRONMENT,
        "can_admins_bypass": False,
        "protection_rules": [rule, {"type": "branch_policy"}],
        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
    }


def check_environment(
    api: EnvironmentAPI, environment: dict[str, Any]
) -> subprocess.CompletedProcess[str]:
    base = f"/repos/{REPO}/environments/{ENVIRONMENT}"
    api.routes = {
        base: environment,
        base + "/deployment-branch-policies": {
            "total_count": 1,
            "branch_policies": [{"name": "main", "type": "branch"}],
        },
    }
    env = {
        **os.environ,
        "GITHUB_TOKEN": "test-token",
        "GITHUB_API_URL": f"http://127.0.0.1:{api.server_address[1]}",
    }
    return run("check-environment", REPO, ENVIRONMENT, env=env)


def test_check_environment_accepts_the_documented_environment(api: EnvironmentAPI) -> None:
    result = check_environment(api, protected())
    assert result.returncode == 0, result.stderr
    assert "no self-review" in result.stdout


@pytest.mark.parametrize("prevent_self_review", [False, None], ids=["off", "unset"])
def test_check_environment_refuses_self_review(
    api: EnvironmentAPI, prevent_self_review: bool | None
) -> None:
    result = check_environment(api, protected(prevent_self_review=prevent_self_review))
    assert result.returncode != 0
    assert "prevent self-review is off" in result.stderr


# ---- push: tag lookups ---------------------------------------------------

# A stand-in for oras 1.3.4: `resolve` answers a pushed reference with its digest and an
# unknown tag with the message chosen by FAKE_ORAS_LOOKUP; `cp` records what it copied.
FAKE_ORAS = """\
import json, os, sys
state_path = os.environ["FAKE_ORAS_STATE"]
state = json.load(open(state_path)) if os.path.exists(state_path) else {"refs": {}, "copies": []}
args = sys.argv[1:]
if args[0] == "cp":
    source, target = args[-2], args[-1]
    layout, name = source.rsplit(":", 1)
    index = json.load(open(os.path.join(layout, "index.json")))
    digest = next(m["digest"] for m in index["manifests"]
                  if m["annotations"]["org.opencontainers.image.ref.name"] == name)
    repository = target.rsplit(":", 1)[0]
    state["refs"][target] = digest
    state["refs"][repository + "@" + digest] = digest
    state["copies"].append(target)
elif args[0] == "resolve":
    reference = args[-1]
    if reference in state["refs"]:
        print(state["refs"][reference])
    else:
        lookup = os.environ["FAKE_ORAS_LOOKUP"]
        tag = reference.rsplit(":", 1)[1]
        messages = {
            "absent": "Error response from registry: failed to resolve digest: "
                      + reference + ": not found",
            "absent-other-reference": "Error response from registry: failed to resolve digest: "
                                      + reference + "-other: not found",
            "credential-helper": "Error: failed to resolve digest: HEAD "
                                 '"https://ghcr.io/v2/example/sandbox-probes/manifests/' + tag
                                 + '": exec: "docker-credential-gone": '
                                 "executable file not found in $PATH",
        }
        print(messages[lookup], file=sys.stderr)
        json.dump(state, open(state_path, "w"))
        sys.exit(1)
json.dump(state, open(state_path, "w"))
"""


@pytest.fixture(scope="module")
def layout(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("probes") / "layout"
    result = run("layout", str(out), env=dict(os.environ))
    assert result.returncode == 0, result.stderr
    return out


def push(
    tmp_path: Path, layout: Path, lookup: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    oras = bin_dir / "oras"
    oras.write_text(f"#!{sys.executable}\n" + FAKE_ORAS)
    oras.chmod(0o755)
    state = tmp_path / "oras-state.json"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "FAKE_ORAS_STATE": str(state),
        "FAKE_ORAS_LOOKUP": lookup,
    }
    result = run("push", str(layout), REGISTRY, env=env)
    return result, json.loads(state.read_text()) if state.exists() else {"copies": []}


def test_push_copies_every_probe_when_oras_reports_the_tags_absent(
    tmp_path: Path, layout: Path
) -> None:
    result, state = push(tmp_path, layout, "absent")
    assert result.returncode == 0, result.stderr
    assert len(state["copies"]) == 9
    assert result.stdout.count("pushed ") == 9


@pytest.mark.parametrize("lookup", ["credential-helper", "absent-other-reference"])
def test_push_stops_before_copying_on_any_other_lookup_failure(
    tmp_path: Path, layout: Path, lookup: str
) -> None:
    result, state = push(tmp_path, layout, lookup)
    assert result.returncode != 0
    assert "cannot tell whether" in result.stderr
    assert state["copies"] == []
