"""VulnScan's dependency findings against osv-scanner's, on the same tree
and the same day's OSV data (a development check: osv-scanner is a
reference here, never part of VulnScan).

    vulnscan scan ROOT --format json --output vulnscan.json
    osv-scanner scan source -r --no-ignore \\
        --experimental-plugins lockfile --experimental-plugins python/wheelegg \\
        --experimental-exclude node_modules \\
        --offline-vulnerabilities --download-offline-databases \\
        --all-packages --format json --output-file osv.json ROOT
    python scripts/compare_osv_scanner.py ROOT vulnscan.json osv.json \
        [--details out.json]

A package occurrence is (ecosystem, name, version, file). For each one
both tools report, their advisory groups are matched by shared ids or
aliases. The result: groups both report; groups only VulnScan reports
(decided, or undecided); groups only osv-scanner reports; and, for the
occurrences only one tool has, which files they come from.
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

Key = tuple[str, str, str, str]  # ecosystem, name, version, path


def _name(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name


def _version(ecosystem: str, version: str) -> str:
    """osv-scanner writes Go versions without their "v"; VulnScan as go.mod
    does."""
    return version.removeprefix("v") if ecosystem == "Go" else version


def vulnscan_side(
    report: dict[str, Any],
) -> tuple[set[Key], dict[Key, list[dict[str, Any]]]]:
    packages = {
        (
            p["ecosystem"],
            _name(p["ecosystem"], p["name"]),
            _version(p["ecosystem"], p["version"]),
            p["path"],
        )
        for p in report["inventory"]["packages"]
        if p.get("version") is not None and not p.get("local")
    }
    groups: dict[Key, list[dict[str, Any]]] = defaultdict(list)
    for f in report["findings"]:
        p = f["package"]
        key = (
            p["ecosystem"],
            _name(p["ecosystem"], p["name"]),
            _version(p["ecosystem"], p["version"]),
            p["path"],
        )
        groups[key].append(
            {
                "ids": {i.upper() for i in f["advisories"] + f["aliases"]},
                "first": f["advisories"][0],
                "certain": f["certain"],
                "severity": f["severity"],
                "score": f["score"],
            }
        )
    return packages, groups


def osv_side(
    report: dict[str, Any], root: Path
) -> tuple[set[Key], dict[Key, list[dict[str, Any]]], Counter[str]]:
    packages: set[Key] = set()
    groups: dict[Key, list[dict[str, Any]]] = defaultdict(list)
    sources: Counter[str] = Counter()
    for result in report.get("results", []):
        path = result["source"]["path"]
        try:
            rel = Path(path).relative_to(root).as_posix()
        except ValueError:
            rel = path
        for p in result["packages"]:
            pkg = p["package"]
            key = (
                pkg["ecosystem"],
                _name(pkg["ecosystem"], pkg["name"]),
                _version(pkg["ecosystem"], pkg.get("version", "")),
                rel,
            )
            packages.add(key)
            sources[result["source"]["type"]] += 1
            for g in p.get("groups", []):
                groups[key].append(
                    {
                        "ids": {i.upper() for i in g["ids"] + g.get("aliases", [])},
                        "first": g["ids"][0],
                        "score": g.get("max_severity") or None,
                    }
                )
    return packages, groups, sources


def kind(path: str) -> str:
    if "dist-info" in path or "egg-info" in path:
        return "installed (dist-info)"
    if path.endswith("bom.cdx.json"):
        return "SBOM (bom.cdx.json)"
    return path.rsplit("/", 1)[-1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("vulnscan", type=Path)
    parser.add_argument("osv", type=Path)
    parser.add_argument("--details", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    vs_packages, vs_groups = vulnscan_side(json.loads(args.vulnscan.read_text()))
    osv_packages, osv_groups, sources = osv_side(json.loads(args.osv.read_text()), root)

    both = vs_packages & osv_packages
    only_vs = vs_packages - osv_packages
    only_osv = osv_packages - vs_packages
    print(
        f"package occurrences: VulnScan {len(vs_packages)}, osv-scanner "
        f"{len(osv_packages)}, both {len(both)}"
    )
    print("  only VulnScan, by file:", dict(Counter(kind(k[3]) for k in only_vs)))
    print("  only osv-scanner, by file:", dict(Counter(kind(k[3]) for k in only_osv)))

    matched: list[dict[str, Any]] = []
    vs_only: list[dict[str, Any]] = []
    osv_only: list[dict[str, Any]] = []
    for key in sorted(both):
        theirs = list(osv_groups.get(key, []))
        for mine in vs_groups.get(key, []):
            partner = next((g for g in theirs if g["ids"] & mine["ids"]), None)
            record = {
                "package": list(key),
                "vulnscan": mine["first"],
                "certain": mine["certain"],
                "score": mine["score"],
            }
            if partner is None:
                vs_only.append(record)
            else:
                theirs.remove(partner)
                record["osv"] = partner["first"]
                record["osv_score"] = partner["score"]
                matched.append(record)
        for g in theirs:
            osv_only.append(
                {"package": list(key), "osv": g["first"], "osv_score": g["score"]}
            )
    unmatched_elsewhere = [
        {"package": list(k), "osv": g["first"]}
        for k in only_osv
        for g in osv_groups.get(k, [])
    ]

    decided = [m for m in matched if m["certain"]]
    undecided = [m for m in matched if not m["certain"]]
    print("\nadvisory groups on packages both tools found:")
    print(
        f"  both report: {len(matched)} ({len(decided)} decided by VulnScan, "
        f"{len(undecided)} undecided by VulnScan)"
    )
    print(
        f"  only VulnScan: {len(vs_only)} "
        f"({sum(r['certain'] for r in vs_only)} decided, "
        f"{sum(not r['certain'] for r in vs_only)} undecided)"
    )
    print(f"  only osv-scanner: {len(osv_only)}")
    print(
        "advisory groups on packages only osv-scanner found:", len(unmatched_elsewhere)
    )
    same_score = sum(
        1
        for m in decided
        if m["score"] is not None
        and m["osv_score"] is not None
        and abs(float(m["osv_score"]) - m["score"]) < 0.05
    )
    scored = sum(1 for m in decided if m["score"] is not None and m["osv_score"])
    print(f"severity score, where both give one: the same in {same_score} of {scored}")
    if args.details:
        args.details.write_text(
            json.dumps(
                {
                    "matched": matched,
                    "vulnscan_only": vs_only,
                    "osv_only": osv_only,
                    "osv_only_packages": sorted(map(list, only_osv)),
                    "vulnscan_only_packages": sorted(map(list, only_vs)),
                    "osv_findings_on_osv_only_packages": unmatched_elsewhere,
                },
                indent=1,
                default=list,
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
