"""Checks VulnScan's matching against OSV's own, on a real inventory.

    PYTHONPATH=src python scripts/check_against_osv_api.py REPORT.json

A development check, not part of VulnScan (which never queries anything):
it sends the public names and versions of the packages in a scan report
(``vulnscan scan --format json``) to OSV's query API (api.osv.dev), which
evaluates them with OSV's own code, and compares the advisories it names
with the ones VulnScan's local index and evaluation find. Local packages
are left out. Differences can also come from timing: the API is live, the
local index is a snapshot.
"""

import json
import sys
import urllib.request
from collections import Counter
from pathlib import Path

from vulnscan.advisories import DB_NAME, Database, data_dir, lookup
from vulnscan.advisories.osv import Verdict

API = "https://api.osv.dev/v1/querybatch"


def query(batch: list[dict[str, object]]) -> list[set[str]]:
    results: list[set[str]] = [set() for _ in batch]
    pending = list(range(len(batch)))
    tokens: dict[int, str] = {}
    while pending:
        body = []
        for i in pending:
            q = dict(batch[i])
            if i in tokens:
                q["page_token"] = tokens[i]
            body.append(q)
        request = urllib.request.Request(
            API,
            data=json.dumps({"queries": body}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=120) as response:
            answer = json.load(response)["results"]
        next_pending = []
        for i, result in zip(pending, answer, strict=True):
            results[i] |= {v["id"] for v in result.get("vulns", [])}
            if token := result.get("next_page_token"):
                tokens[i] = token
                next_pending.append(i)
        pending = next_pending
    return results


def main(report: Path) -> int:
    packages = json.loads(report.read_text())["inventory"]["packages"]
    targets = sorted(
        {
            (p["ecosystem"], p["name"], p["version"])
            for p in packages
            if p.get("version") and not p["local"] and p["name"] != "stdlib"
        }
    )
    db = Database(data_dir() / DB_NAME)
    counts: Counter[str] = Counter()
    differences: list[str] = []
    for start in range(0, len(targets), 500):
        chunk = targets[start : start + 500]
        theirs_all = query(
            [
                {"package": {"ecosystem": e, "name": n}, "version": v}
                for e, n, v in chunk
            ]
        )
        for (ecosystem, name, version), theirs in zip(chunk, theirs_all, strict=True):
            matches = lookup(db, ecosystem, name, version)
            ours = {m.advisory.id for m in matches if m.verdict is Verdict.AFFECTED}
            unknown = {m.advisory.id for m in matches if m.verdict is Verdict.UNKNOWN}
            counts["packages"] += 1
            counts["advisories agreed"] += len(ours & theirs)
            if ours == theirs:
                counts["packages agreeing"] += 1
                continue
            only_ours, only_theirs = ours - theirs, theirs - ours
            counts["only ours"] += len(only_ours)
            counts["only theirs"] += len(only_theirs)
            counts["only theirs, undecided here"] += len(only_theirs & unknown)
            differences.append(
                f"{ecosystem} {name} {version}: only ours {sorted(only_ours)}, "
                f"only theirs {sorted(only_theirs)} "
                f"(undecided here: {sorted(only_theirs & unknown)})"
            )
    db.close()
    print(dict(counts))
    for line in differences[:40]:
        print(" ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
