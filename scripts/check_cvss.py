"""Checks the hand-written CVSS 3 scoring against GitHub's own severity
words, on every GitHub advisory in the local index that has both.

    PYTHONPATH=src python scripts/check_cvss.py

GitHub's word (LOW, MODERATE, HIGH, CRITICAL) normally comes from the CVSS
score; where an advisory also has a CVSS 4.0 vector, GitHub may have used
that one instead, so the two can differ for good reason. Prints agreement
overall and for advisories with a CVSS 3 vector only.
"""

import json
from collections import Counter

from vulnscan.advisories import DB_NAME, data_dir
from vulnscan.advisories.db import Database
from vulnscan.cvss import base_score

WORDS = {"LOW": "low", "MODERATE": "medium", "HIGH": "high", "CRITICAL": "critical"}


def main() -> None:
    db = Database(data_dir() / DB_NAME, readonly=True)
    counts: Counter[str] = Counter()
    pairs: Counter[tuple[str, str]] = Counter()
    rows = db._db.execute(
        "SELECT id, severity, database_severity FROM advisory "
        "WHERE id LIKE 'GHSA-%' AND database_severity IS NOT NULL"
    )
    for _id, severity, word in rows:
        vectors = dict(json.loads(severity))
        v3 = vectors.get("CVSS_V3")
        if v3 is None or word not in WORDS:
            continue
        score = base_score(v3)
        if score is None:
            counts["CVSS 3 vector not read"] += 1
            continue
        only_v3 = "CVSS_V4" not in vectors
        key = "v3 only" if only_v3 else "v3 and v4"
        counts[f"{key}: compared"] += 1
        if score.rating == WORDS[word]:
            counts[f"{key}: same"] += 1
        else:
            pairs[(WORDS[word], score.rating)] += 1
    db.close()
    print(dict(sorted(counts.items())))
    print("differences (GitHub's, ours):", pairs.most_common(8))


if __name__ == "__main__":
    main()
