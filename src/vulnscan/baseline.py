"""Accepted findings: ``.vulnscan.toml`` at the root of the target (or the
file given with ``--baseline``), kept in the repository so that accepting a
finding is a reviewed change like any other.

    [[accept]]
    advisory = "GHSA-3h5v-q93c-6h6q"   # any id or alias of the finding
    package = "npm:ws"                   # optional: only for this package
    reason = "no untrusted clients reach this server"
    expires = 2026-12-31

    [[accept]]
    secret = "3f9c0a1b2c3d4e5f"          # a secret finding's fingerprint
    reason = "a fake key the tests are built around"
    expires = 2027-03-31

Every acceptance needs a reason and an expiry date: an acceptance is a
decision to revisit, not a way to make a finding disappear. An accepted
finding is still reported (as accepted), and does not fail the scan; once
its date has passed it fails again, with a note that the acceptance
expired. An acceptance that matches no finding is reported too, so the
file does not fill with entries for things long fixed.
"""

import re
import tomllib
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path

from vulnscan.findings import Acceptance, Finding

FILE_NAME = ".vulnscan.toml"
_KEYS = {"advisory", "package", "reason", "expires", "secret"}
_FINGERPRINT = re.compile(r"[0-9a-f]{16}")


class BaselineError(Exception):
    """A baseline file that cannot be used as written: the scan stops."""


def load(path: Path) -> list[Acceptance]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as error:
        raise BaselineError(f"{path}: cannot be read: {error}") from error
    except tomllib.TOMLDecodeError as error:
        raise BaselineError(f"{path}: not valid TOML: {error}") from error
    unknown_tables = set(data) - {"accept"}
    if unknown_tables:
        raise BaselineError(f"{path}: unknown table {sorted(unknown_tables)[0]!r}")
    entries = data.get("accept", [])
    if not isinstance(entries, list):
        raise BaselineError(f"{path}: accept must be [[accept]] tables")
    accepted: list[Acceptance] = []
    for n, entry in enumerate(entries, start=1):
        where = f"{path}: accept #{n}"
        if not isinstance(entry, dict):
            raise BaselineError(f"{where}: not a table")
        unknown = set(entry) - _KEYS
        if unknown:
            raise BaselineError(f"{where}: unknown key {sorted(unknown)[0]!r}")
        advisory, reason, expires = (
            entry.get("advisory"),
            entry.get("reason"),
            entry.get("expires"),
        )
        package, secret = entry.get("package"), entry.get("secret")
        if (advisory is None) == (secret is None):
            raise BaselineError(
                f'{where}: needs advisory = "<id or alias>" or secret = '
                '"<fingerprint>" (one of them)'
            )
        if secret is not None:
            if not isinstance(secret, str) or not _FINGERPRINT.fullmatch(secret):
                raise BaselineError(
                    f"{where}: secret must be a fingerprint (16 hex digits), "
                    "never the secret itself"
                )
            if package is not None:
                raise BaselineError(f"{where}: package is for advisories")
        elif not isinstance(advisory, str) or not advisory.strip():
            raise BaselineError(f'{where}: needs advisory = "<id or alias>"')
        if not isinstance(reason, str) or not reason.strip():
            raise BaselineError(f"{where}: needs a reason")
        # A TOML date (2026-12-31, unquoted), not a date and time, not text.
        if type(expires) is not date:
            raise BaselineError(f"{where}: needs expires = YYYY-MM-DD (a TOML date)")
        if package is not None and (not isinstance(package, str) or ":" not in package):
            raise BaselineError(f'{where}: package must be "ecosystem:name"')
        accepted.append(
            Acceptance(
                advisory.strip() if isinstance(advisory, str) else None,
                package,
                reason.strip(),
                expires,
                secret,
            )
        )
    return accepted


@dataclass(frozen=True)
class Applied:
    findings: tuple[Finding, ...]  # with .accepted set where an acceptance holds
    expired: tuple[tuple[Acceptance, Finding], ...]  # matched, but past its date
    unused: tuple[Acceptance, ...]  # matched nothing


def _matches(acceptance: Acceptance, finding: Finding) -> bool:
    if acceptance.advisory is None or acceptance.advisory.upper() not in finding.ids:
        return False
    p = finding.package
    return acceptance.package is None or acceptance.package == f"{p.ecosystem}:{p.name}"


def apply(
    findings: tuple[Finding, ...], acceptances: list[Acceptance], today: date
) -> Applied:
    """Advisory acceptances only; secrets.apply does the same for secrets."""
    acceptances = [a for a in acceptances if a.advisory is not None]
    used: set[int] = set()
    expired: list[tuple[Acceptance, Finding]] = []
    result: list[Finding] = []
    for finding in findings:
        holding = None
        for n, acceptance in enumerate(acceptances):
            if not _matches(acceptance, finding):
                continue
            used.add(n)
            if acceptance.expires < today:
                expired.append((acceptance, finding))
            elif holding is None:
                holding = acceptance
        result.append(replace(finding, accepted=holding) if holding else finding)
    unused = tuple(a for n, a in enumerate(acceptances) if n not in used)
    return Applied(tuple(result), tuple(expired), unused)
