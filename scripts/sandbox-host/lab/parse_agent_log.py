#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Lab helper: extract the reports a miner agent logged.

The agent logs its startup report ("sandbox host preflight report") and
each instance report ("sandbox instance report") with Go's %+v struct
formatting inside slog text lines. This writes them as JSON:

    parse_agent_log.py AGENT_LOG OUT_DIR

OUT_DIR/startup-report.json and OUT_DIR/instance-reports.json hold
{"verdict", "profile_digest", "checks": [{id, class, status, evidence}]}
per report (instance reports also carry "sandbox" and "decision"). Exit 1
if the startup report is missing.
"""

import json
import re
import sys
from pathlib import Path

CHECK = re.compile(r"\{ID:(\S+) Class:(\S+) Status:(\S+) Evidence:(.*?)\}(?= \{ID:|\])")


def parse(line: str) -> dict:
    report = line.split('report="', 1)[1] if 'report="' in line else line
    report = report.replace('\\"', '"')
    verdict = re.search(r" Verdict:(\S+?)\}", report)
    digest = re.search(r"ProfileDigest:(\S+)", report)
    checks = [
        {"id": m.group(1), "class": m.group(2), "status": m.group(3), "evidence": m.group(4)}
        for m in CHECK.finditer(report)
    ]
    out = {
        "verdict": verdict.group(1) if verdict else None,
        "profile_digest": digest.group(1) if digest else None,
        "checks": checks,
    }
    for key in ("sandbox", "decision"):
        found = re.search(rf"\b{key}=(\S+)", line.split(" report=", 1)[0])
        if found:
            out[key] = found.group(1)
    return out


def main() -> int:
    log, out = Path(sys.argv[1]), Path(sys.argv[2])
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    startup = [parse(line) for line in lines if "sandbox host preflight report" in line]
    instances = [parse(line) for line in lines if "sandbox instance report" in line]
    last = startup[-1] if startup else None
    (out / "startup-report.json").write_text(json.dumps(last, indent=1) + "\n")
    (out / "instance-reports.json").write_text(json.dumps(instances, indent=1) + "\n")
    named = [("startup", last)] + [(f"instance {i}", r) for i, r in enumerate(instances)]
    for name, report in named:
        if report is None:
            print(f"{name}: missing")
            continue
        statuses = {}
        for check in report["checks"]:
            statuses[check["status"]] = statuses.get(check["status"], 0) + 1
        extra = ""
        if "decision" in report:
            extra = f" sandbox={report.get('sandbox')} decision={report.get('decision')}"
        print(
            f"{name}: verdict={report['verdict']} checks={len(report['checks'])} {statuses}{extra}"
        )
        for check in report["checks"]:
            print(f"  {check['id']} {check['class']} {check['status']}: {check['evidence'][:160]}")
    return 0 if startup else 1


if __name__ == "__main__":
    sys.exit(main())
