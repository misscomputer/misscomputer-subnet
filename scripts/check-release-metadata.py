#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Fail closed when release licensing/provenance metadata drifts."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "go.mod",
    "go.sum",
    "pkg/netpolicy/iana-special-purpose.v1.json",
}


def main() -> None:
    reuse = tomllib.loads((ROOT / "REUSE.toml").read_text())
    covered: set[str] = set()
    for annotation in reuse.get("annotations", []):
        paths = annotation.get("path", [])
        if annotation.get("SPDX-License-Identifier") == "AGPL-3.0-only":
            covered.update(path for path in paths if isinstance(path, str))
    missing = REQUIRED - covered
    if missing:
        raise SystemExit(f"REUSE coverage missing: {sorted(missing)}")
    for name in ("IANA-DATA-NOTICE.md", "THIRD_PARTY_NOTICES.md", "CONTRIBUTING.md"):
        if not (ROOT / name).is_file():
            raise SystemExit(f"release notice missing: {name}")
    sbom = json.loads((ROOT / "sbom.spdx.json").read_text())
    if sbom.get("SPDXID") != "SPDXRef-DOCUMENT" or sbom.get("dataLicense") != "CC0-1.0":
        raise SystemExit("invalid SPDX document metadata")
    packages = sbom.get("packages")
    if not isinstance(packages, list) or not any(
        item.get("name") == "misscomputer-subnet" and item.get("licenseDeclared") == "AGPL-3.0-only"
        for item in packages
        if isinstance(item, dict)
    ):
        raise SystemExit("SBOM does not identify the licensed root package")


if __name__ == "__main__":
    main()
