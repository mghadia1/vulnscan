"""Findings as SARIF 2.1.0, the format code-scanning tools read (GitHub's
among them).

Each advisory is a rule (its id, summary, help and references), carrying
the "security-severity" property GitHub uses to rank security results;
each finding is a result pointing at the file and line where the package
was found. An accepted finding carries a suppression with its reason.
Each secret rule is a rule too (``secret/github-token``); a secret's result
says where it is and what it is, never what it is: no part of the value
beyond a format's fixed prefix. The output is checked against OASIS's SARIF
2.1.0 schema in the tests.
"""

from typing import Any

from vulnscan import __version__
from vulnscan.findings import Finding, severity_rank
from vulnscan.secrets import SecretFinding, commit_date

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "unknown": "warning",
    "low": "note",
    "none": "note",
}
# GitHub's own security-severity bands, for a rating with no score.
_BANDS = {"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "0.1"}


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
    elif finding.severity in _BANDS:
        rule["properties"]["security-severity"] = _BANDS[finding.severity]
    return rule


def _secret_rule(finding: SecretFinding, severity: str) -> dict[str, Any]:
    return {
        "id": f"secret/{finding.rule}",
        "shortDescription": {"text": f"{finding.title} in the repository"},
        "help": {
            "text": (
                "A credential committed to a repository is readable by anyone "
                "with a copy of it, including its history. Revoke it, issue a "
                "new one, and keep it out of git (the environment, or an "
                "ignored file)."
            )
        },
        "defaultConfiguration": {"level": _LEVEL[severity]},
        "properties": {
            "tags": ["security", "secret"],
            "security-severity": _BANDS[severity],
        },
    }


def _secret_result(f: SecretFinding, rule_index: int) -> dict[str, Any]:
    where = {
        "committed": "in the latest commit",
        "history": "in the history (no longer in the latest commit)",
        "file": "in a file not known to be committed",
        "uncommitted": "in a file that is not committed",
    }[f.state]
    first = (
        f" First committed in {f.commit[:10]} ({commit_date(f)})." if f.commit else ""
    )
    result: dict[str, Any] = {
        "ruleId": f"secret/{f.rule}",
        "ruleIndex": rule_index,
        "level": "note" if f.state == "uncommitted" else _LEVEL[f.severity],
        "message": {
            "text": (
                f"{f.title} ({f.shown}{'; ' + f.note if f.note else ''}) "
                f"{where}.{first} {f.advice[0].upper()}{f.advice[1:]}."
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }
            }
        ],
        "partialFingerprints": {"vulnscan/secret/v1": f.fingerprint},
        "properties": {
            "state": f.state,
            "commit": f.commit,
            "pushed": f.pushed,
        },
    }
    if f.accepted is not None:
        result["suppressions"] = [
            {
                "kind": "external",
                "justification": f"{f.accepted.reason} (until {f.accepted.expires})",
            }
        ]
    return result


def to_sarif(
    findings: tuple[Finding, ...], secrets: tuple[SecretFinding, ...] = ()
) -> dict[str, Any]:
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
    # A rule's severity is its worst finding's (a JWT's depends on expiry).
    worst: dict[str, str] = {}
    for secret in secrets:
        if severity_rank(secret.severity) > severity_rank(
            worst.get(secret.rule, "none")
        ):
            worst[secret.rule] = secret.severity
    for secret in secrets:
        rule_id = f"secret/{secret.rule}"
        if rule_id not in index:
            index[rule_id] = len(rules)
            rules.append(_secret_rule(secret, worst[secret.rule]))
        results.append(_secret_result(secret, index[rule_id]))
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
