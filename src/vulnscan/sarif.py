"""Findings as SARIF 2.1.0, the format code-scanning tools read (GitHub's
among them).

Each advisory is a rule (its id, summary, help and references), carrying
the "security-severity" property GitHub uses to rank security results;
each finding is a result pointing at the file and line where the package
was found. An accepted finding carries a suppression with its reason.
The output is checked against OASIS's SARIF 2.1.0 schema in the tests.
"""

from typing import Any

from vulnscan import __version__
from vulnscan.findings import Finding

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "unknown": "warning",
    "low": "note",
    "none": "note",
}


def _rule(finding: Finding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": finding.advisories[0],
        "shortDescription": {"text": finding.summary or finding.advisories[0]},
        "help": {
            "text": (
                f"{finding.summary}\nAlso known as: "
                f"{', '.join([*finding.advisories[1:], *finding.aliases]) or 'none'}.\n"
                f"Severity: {finding.severity} ({finding.severity_source})."
            )
        },
        "defaultConfiguration": {"level": _LEVEL[finding.severity]},
        "properties": {
            "tags": ["security", finding.rule, finding.package.ecosystem],
        },
    }
    if finding.references:
        rule["helpUri"] = finding.references[0]
    if finding.score is not None:
        rule["properties"]["security-severity"] = f"{finding.score:.1f}"
    elif finding.severity in ("critical", "high", "medium", "low"):
        # GitHub's own bands, for a rating with no score.
        bands = {"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "0.1"}
        rule["properties"]["security-severity"] = bands[finding.severity]
    return rule


def to_sarif(findings: tuple[Finding, ...]) -> dict[str, Any]:
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = finding.advisories[0]
        if rule_id not in index:
            index[rule_id] = len(rules)
            rules.append(_rule(finding))
        p = finding.package
        location: dict[str, Any] = {"artifactLocation": {"uri": p.path}}
        if p.line is not None:
            location["region"] = {"startLine": p.line}
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": index[rule_id],
            "level": _LEVEL[finding.severity],
            "message": {
                "text": (
                    f"{p.ecosystem} {p.name} {p.version} "
                    f"{'is affected by' if finding.certain else 'may be affected by'} "
                    f"{rule_id}: {finding.summary} ({finding.fix_note})"
                )
            },
            "locations": [{"physicalLocation": location}],
            "partialFingerprints": {"vulnscan/v1": finding.fingerprint},
            "properties": {
                "package": f"{p.ecosystem}:{p.name}",
                "version": p.version,
                "found": p.how.value,
                "fixedIn": finding.fixed_in,
            },
        }
        if finding.accepted is not None:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "justification": (
                        f"{finding.accepted.reason} (until {finding.accepted.expires})"
                    ),
                }
            ]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "VulnScan",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
