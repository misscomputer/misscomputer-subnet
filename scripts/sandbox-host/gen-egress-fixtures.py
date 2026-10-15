#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate the engine-egress readback fixtures with the real nft printer.

Renders the table exactly as provision-disposable.sh writes it, derives the
unsafe variants lane 8 found accepted by the old substring readback
(INT-27-07 P1-P8) plus the level, set and chain variants, loads each into a
throwaway network namespace and records `nft -j list` and `nft list` output.
Unit tests read the recorded output; conformance loads the same .nft files on
the disposable host and requires the observer to refuse every unsafe one.

Run unprivileged, as `unshare -rn python3 gen-egress-fixtures.py SLICE`:
SLICE must be an existing cgroup v2 path at level 1 (for example
user.slice); it is rewritten to the engine slice name in the recorded files.
Each variant is loaded in its own `unshare -n` child, so nothing persists.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROVISION = ROOT / "scripts" / "sandbox-host" / "provision-disposable.sh"
OUT = ROOT / "pkg" / "sandboxhost" / "testdata" / "egress"
TABLE = "mcsbx_engine_egress"
ENGINE = "mcsbxengine.slice"
MATCH = 'socket cgroupv2 level 1 "@SLICE@"'


def provisioned() -> str:
    text = PROVISION.read_text(encoding="utf-8")
    body = re.search(r"<<NFT\n(.*?)\nNFT\n", text, re.S)
    if not body:
        raise SystemExit("nft heredoc not found in provision-disposable.sh")
    return (
        body.group(1)
        .replace("$MCSBX_EGRESS_TABLE", TABLE)
        .replace('"$MCSBX_ENGINE_SLICE"', '"@SLICE@"')
    ) + "\n"


def variants(base: str) -> dict[str, str]:
    fib = f"{MATCH} fib daddr type local counter reject with icmpx admin-prohibited"
    v4 = next(line for line in base.splitlines() if " ip daddr { " in line).strip()
    v6 = next(line for line in base.splitlines() if " ip6 daddr { " in line).strip()
    policy = "type filter hook output priority filter; policy accept;"

    def first(line: str) -> str:
        return base.replace(policy, f"{policy}\n    {line}", 1)

    out = {
        "provisioned": base,
        "p1_fib_ipv4_only": base.replace(
            fib, fib.replace("fib daddr", "meta nfproto ipv4 fib daddr"), 1
        ),
        "p2_fib_narrowed_by_port": base.replace(
            fib, fib.replace(" counter", " tcp dport 1 counter"), 1
        ),
        "p3_unconditional_accept": first("accept"),
        "p4_accept_without_socket_match": first("ip daddr 152.236.4.60 accept"),
        "p5_unconditional_return": first("return"),
        "p6_accept_with_reject_comment": first(
            f'{MATCH} ip daddr 152.236.4.60 accept comment "reject"'
        ),
        "p7_prefix_reject_narrowed_by_port": base.replace(
            v4, v4.replace(" counter", " tcp dport 1 counter"), 1
        ),
        "p8_prefixes_as_saddr": base.replace(v4, v4.replace(" ip daddr ", " ip saddr ", 1), 1),
        "level2_fib": base.replace(fib, fib.replace("level 1", "level 2"), 1),
        "e2_missing_mapped_prefix": base.replace(v6, v6.replace(" ::ffff:0:0/96,", "", 1), 1),
        "f3_missing_local_nat64": base.replace(v6, v6.replace(" 64:ff9b:1::/48,", "", 1), 1),
        "extra_chain": base.rstrip().rstrip("}")
        + "  chain extra {\n    type filter hook output priority filter; policy accept;\n  }\n}\n",
        # SR-33-01: each structural guard on its own.
        "fifth_rule_after_rejects": base.replace(
            v6, f"{v6}\n    {MATCH} ip daddr 152.236.4.60 accept", 1
        ),
        "second_chain_nat_output": base.rstrip().rstrip("}")
        + "  chain natout {\n    type nat hook output priority -100; policy accept;\n  }\n}\n",
        "rule_with_comment": base.replace(fib, f'{fib} comment "lab"', 1),
        "named_counter": base.replace(policy, policy, 1)
        .replace(f"table inet {TABLE} {{", f"table inet {TABLE} {{\n  counter engine {{ }}", 1)
        .replace(fib, fib.replace(" counter ", ' counter name "engine" ', 1), 1),
        "policy_drop": base.replace("policy accept;", "policy drop;", 1),
        # INT-33-01: a dormant table holds its rules but enforces none of them.
        "dormant_table": base.replace(
            f"table inet {TABLE} {{", f"table inet {TABLE} {{\n  flags dormant;", 1
        ),
    }
    for name, text in out.items():
        if name != "provisioned" and text == base:
            raise SystemExit(f"variant {name} did not change the provisioned table")
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    slice_path = argv[0]
    OUT.mkdir(parents=True, exist_ok=True)
    for name, template in variants(provisioned()).items():
        (OUT / f"{name}.nft").write_text(template, encoding="utf-8")
        loaded = template.replace("@SLICE@", slice_path)
        script = (
            'nft -f - && nft -j list table inet "$1"'
            ' && echo "@@TEXT@@" && nft -a list table inet "$1"'
        )
        result = subprocess.run(  # noqa: S603,S607 - fixed nft commands in a private netns
            ["unshare", "-n", "sh", "-c", script, "sh", TABLE],  # noqa: S607
            input=loaded,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise SystemExit(f"{name}: nft refused the variant: {result.stderr.strip()}")
        listing_json, listing_text = result.stdout.split("@@TEXT@@\n", 1)
        # Trailing blanks are not significant to either listing (nft 1.0.9
        # leaves one where it truncates a dormant table's JSON).
        listing_json = "\n".join(line.rstrip() for line in listing_json.split("\n"))
        listing_text = "\n".join(line.rstrip() for line in listing_text.split("\n"))
        (OUT / f"{name}.json").write_text(
            listing_json.replace(slice_path, ENGINE), encoding="utf-8"
        )
        (OUT / f"{name}.txt").write_text(listing_text.replace(slice_path, ENGINE), encoding="utf-8")
        print(f"{name}: recorded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
