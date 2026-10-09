import json
import zipfile
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from conftest import OSV_DIR

from vulnscan.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main

SCHEMA = Path(__file__).parent / "data" / "sarif-schema-2.1.0.json"


def build_data(data: Path, tmp: Path) -> None:
    """An advisory index from the six real advisories in tests/data/osv:
    one export per ecosystem, as OSV's are."""
    by_ecosystem: dict[str, list[Path]] = {}
    for file in sorted(OSV_DIR.glob("*.json")):
        advisory = json.loads(file.read_text())
        for ecosystem in {a["package"]["ecosystem"] for a in advisory["affected"]}:
            by_ecosystem.setdefault(ecosystem, []).append(file)
    for ecosystem in ("PyPI", "npm", "Go"):
        archive = tmp / f"{ecosystem}.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            for file in by_ecosystem.get(ecosystem, []):
                zf.write(file, file.name)
        assert (
            main(["update", "--from", f"{ecosystem}={archive}", "--data", str(data)])
            == 0
        )


def planted_repo(root: Path) -> Path:
    """Known-vulnerable versions planted beside safe ones."""
    (root / "api").mkdir(parents=True)
    (root / "requirements.txt").write_text("Django==3.2.18\nflask==3.0.0\n")
    (root / "api/requirements.txt").write_text("Django==4.2.16\n")  # safe
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {
                "name": "app",
                "dependencies": {"ws": "^8", "openlearnx": "^2", "x": "1"},
            },
            "node_modules/ws": {"version": "8.17.0"},
            "node_modules/x": {"version": "1.0.0"},
            "node_modules/x/node_modules/ws": {"version": "8.17.1"},  # safe
            "node_modules/openlearnx": {"version": "2.0.3"},
            "node_modules/--hiljson": {"version": "1.0.0", "dev": True},
        },
    }
    (root / "package-lock.json").write_text(json.dumps(lock, indent=2))
    (root / "go.mod").write_text(
        "module example.com/app\n\ngo 1.22\n\ntoolchain go1.22.1\n\n"
        "require golang.org/x/net v0.22.0\n"
    )
    return root


@pytest.fixture
def scanned(tmp_path: Path) -> tuple[Path, Path]:
    data = tmp_path / "data"
    build_data(data, tmp_path)
    return planted_repo(tmp_path / "repo"), data


def scan(repo: Path, data: Path, *extra: str) -> tuple[int, str]:
    out = repo.parent / "out"
    code = main(["scan", str(repo), "--data", str(data), "--output", str(out), *extra])
    return code, out.read_text()


def test_planted_vulnerabilities_are_found_and_safe_versions_are_not(
    scanned: tuple[Path, Path],
) -> None:
    repo, data = scanned
    code, out = scan(repo, data, "--format", "json")
    assert code == EXIT_FINDINGS
    report = json.loads(out)
    assert report["schema"] == 3
    rows = [
        (
            f["severity"],
            f["score"],
            f["package"]["name"],
            f["package"]["version"],
            f["advisories"],
            f["fixed_in"],
        )
        for f in report["findings"]
    ]
    assert rows == [
        ("critical", None, "--hiljson", "1.0.0", ["MAL-2022-2"], None),
        ("high", 7.5, "ws", "8.17.0", ["GHSA-3h5v-q93c-6h6q"], "8.17.1"),
        # The same bug in GitHub's database and Go's: one finding.
        (
            "medium",
            5.3,
            "golang.org/x/net",
            "v0.22.0",
            ["GHSA-4v7x-pqxf-cx7m", "GO-2024-2687"],
            "0.23.0",
        ),
        ("medium", None, "openlearnx", "2.0.3", ["GHSA-223g-f5mq-gw33"], "2.0.4"),
        ("unknown", None, "stdlib", "1.22.1", ["GO-2024-2687"], "1.22.2"),
        ("unknown", None, "django", "3.2.18", ["PYSEC-2023-61"], "3.2.19"),
    ]
    by_name = {f["package"]["name"]: f for f in report["findings"]}
    assert by_name["--hiljson"]["rule"] == "malicious-package"
    assert by_name["openlearnx"]["severity_source"].startswith("GitHub's rating")
    assert "CVE-2023-45288" in by_name["golang.org/x/net"]["aliases"]
    assert by_name["ws"]["package"]["line"] is not None
    assert all(f["failing"] for f in report["findings"])
    assert report["summary"]["findings"] == 6
    # All ten were looked up: flask, the safe versions, x and Go's standard
    # library too.
    assert report["advisories"]["packages_checked"] == 10


def test_sarif_is_valid_against_the_oasis_schema(scanned: tuple[Path, Path]) -> None:
    repo, data = scanned
    code, out = scan(repo, data, "--format", "sarif")
    assert code == EXIT_FINDINGS
    sarif = json.loads(out)
    jsonschema.validate(sarif, json.loads(SCHEMA.read_text()))
    [run] = sarif["runs"]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert rules["GHSA-3h5v-q93c-6h6q"]["properties"]["security-severity"] == "7.5"
    assert rules["MAL-2022-2"]["defaultConfiguration"]["level"] == "error"
    ws = next(r for r in run["results"] if r["ruleId"] == "GHSA-3h5v-q93c-6h6q")
    location = ws["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "package-lock.json"
    assert location["region"]["startLine"] > 1


def test_the_text_report(scanned: tuple[Path, Path]) -> None:
    repo, data = scanned
    code, out = scan(repo, data)
    assert code == EXIT_FINDINGS
    assert "6 findings, 6 failing (--fail-on low)" in out
    assert "  HIGH     7.5 npm ws 8.17.0  package-lock.json:" in out
    assert "upgrade to 8.17.1 or later" in out
    assert "remove it: it was published to do harm" in out


@pytest.mark.parametrize(
    ("threshold", "code"),
    [("high", EXIT_FINDINGS), ("critical", EXIT_FINDINGS), ("never", EXIT_CLEAN)],
)
def test_fail_on(scanned: tuple[Path, Path], threshold: str, code: int) -> None:
    repo, data = scanned
    assert scan(repo, data, "--fail-on", threshold)[0] == code


def test_unknown_severities_fail_any_threshold(
    tmp_path: Path, scanned: tuple[Path, Path]
) -> None:
    _, data = scanned
    repo = tmp_path / "only-django"
    repo.mkdir()
    (repo / "requirements.txt").write_text("Django==3.2.18\n")  # no score given
    assert scan(repo, data, "--fail-on", "critical")[0] == EXIT_FINDINGS


def accept(repo: Path, *entries: dict[str, Any]) -> None:
    lines = []
    for entry in entries:
        lines.append("[[accept]]")
        for key, value in entry.items():
            lines.append(f"{key} = {value if key == 'expires' else json.dumps(value)}")
    (repo / ".vulnscan.toml").write_text("\n".join(lines) + "\n")


def test_accepted_findings_pass_until_they_expire(scanned: tuple[Path, Path]) -> None:
    repo, data = scanned
    later = (date.today() + timedelta(days=30)).isoformat()
    earlier = (date.today() - timedelta(days=1)).isoformat()
    accept(
        repo,
        # By its CVE alias, for this package only.
        {
            "advisory": "CVE-2024-37890",
            "package": "npm:ws",
            "reason": "not exposed",
            "expires": later,
        },
        {"advisory": "MAL-2022-2", "reason": "dev only, removing", "expires": later},
        {"advisory": "GHSA-223g-f5mq-gw33", "reason": "x", "expires": later},
        {"advisory": "GO-2024-2687", "reason": "x", "expires": later},
        {"advisory": "PYSEC-2023-61", "reason": "was fine", "expires": earlier},
        {"advisory": "GHSA-0000-0000-0000", "reason": "long gone", "expires": later},
    )
    code, out = scan(repo, data, "--format", "json")
    report = json.loads(out)
    accepted = {f["package"]["name"] for f in report["findings"] if f["accepted"]}
    # GO-2024-2687 names both the module's finding and the standard library's.
    assert accepted == {"ws", "--hiljson", "openlearnx", "golang.org/x/net", "stdlib"}
    failing = [f["package"]["name"] for f in report["findings"] if f["failing"]]
    assert failing == ["django"]  # its acceptance expired
    assert code == EXIT_FINDINGS
    assert [e["advisory"] for e in report["baseline"]["expired"]] == ["PYSEC-2023-61"]
    assert [u["advisory"] for u in report["baseline"]["unused"]] == [
        "GHSA-0000-0000-0000"
    ]
    sarif = json.loads(scan(repo, data, "--format", "sarif")[1])
    suppressed = [r for r in sarif["runs"][0]["results"] if "suppressions" in r]
    assert len(suppressed) == 5
    assert scan(repo, data, "--no-baseline")[0] == EXIT_FINDINGS


@pytest.mark.parametrize(
    ("toml", "message"),
    [
        ('[[accept]]\nadvisory = "X"\nexpires = 2030-01-01\n', "needs a reason"),
        (
            '[[accept]]\nadvisory = "X"\nreason = "r"\nexpires = "2030-01-01"\n',
            "TOML date",
        ),
        (
            '[[accept]]\nadvisory = "X"\nreason = "r"\nexpires = 2030-01-01T00:00:00\n',
            "TOML date",
        ),
        (
            '[[accept]]\nadvisory = "X"\nreason = "r"\nexpires = 2030-01-01\nwhy = 1\n',
            "unknown key",
        ),
        (
            '[[accept]]\nadvisory = "X"\nreason = "r"\nexpires = 2030-01-01\n'
            'package = "ws"\n',
            "ecosystem:name",
        ),
        ("[ignore]\n", "unknown table"),
        ("[[accept]\n", "not valid TOML"),
    ],
)
def test_a_baseline_that_cannot_be_used_stops_the_scan(
    scanned: tuple[Path, Path],
    capsys: pytest.CaptureFixture[str],
    toml: str,
    message: str,
) -> None:
    repo, data = scanned
    (repo / ".vulnscan.toml").write_text(toml)
    assert scan_code(repo, data) == EXIT_ERROR
    assert message in capsys.readouterr().err


def scan_code(repo: Path, data: Path) -> int:
    return main(
        ["scan", str(repo), "--data", str(data), "--output", str(repo.parent / "o")]
    )


def test_without_advisory_data_a_scan_does_not_pass(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = planted_repo(tmp_path / "repo")
    assert main(["scan", str(repo), "--output", str(tmp_path / "o")]) == EXIT_ERROR
    assert "no advisory data" in capsys.readouterr().err
    # With only one ecosystem's data, the others are named as not checked.
    data = tmp_path / "data"
    archive = tmp_path / "PyPI.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.write(OSV_DIR / "PYSEC-2023-61.json", "PYSEC-2023-61.json")
    main(["update", "--from", f"PyPI={archive}", "--data", str(data)])
    capsys.readouterr()
    code, out = scan(repo, data)
    assert code == EXIT_ERROR
    assert "NOT CHECKED: 5 npm packages" in out
    assert "not checked, no advisory data" in capsys.readouterr().err
    # The inventory alone, on purpose.
    assert (
        main(["scan", str(repo), "--no-advisories", "--output", str(tmp_path / "o")])
        == 0
    )


def _advisory(
    id_: str, aliases: list[str], fixed: str, vector: str | None = None
) -> Any:
    from vulnscan.advisories.osv import parse_advisory

    data: dict[str, Any] = {
        "id": id_,
        "modified": "2026-01-01T00:00:00Z",
        "aliases": aliases,
        "summary": f"{id_} summary",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "pkg"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
            }
        ],
    }
    if vector:
        data["severity"] = [{"type": "CVSS_V3", "score": vector}]
    parsed = parse_advisory(data)
    assert not isinstance(parsed, str)
    return parsed


def _package(version: str = "1.0.0") -> Any:
    from vulnscan.inventory.model import Ecosystem, How, Package

    return Package(Ecosystem.NPM, "pkg", version, How.LOCKED, "package-lock.json", 3)


def test_one_finding_for_aliases_with_the_worst_score_and_the_fix_for_all() -> None:
    from vulnscan.advisories.osv import Verdict
    from vulnscan.findings import finding_for

    low = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 3.1
    high = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"  # 7.5
    a = _advisory("GHSA-aaaa-aaaa-aaaa", ["CVE-1"], "1.2.0", low)
    b = _advisory("GO-2026-1", ["CVE-1"], "1.5.0", high)
    finding = finding_for(_package(), [(a, Verdict.AFFECTED), (b, Verdict.AFFECTED)])
    assert (finding.score, finding.severity) == (7.5, "high")
    # 1.2.0 fixes one advisory, not the other: the fix is the version
    # that fixes both.
    assert finding.fixed_in == "1.5.0"
    assert finding.advisories == ("GHSA-aaaa-aaaa-aaaa", "GO-2026-1")


def test_the_fix_is_the_lowest_above_the_version_found() -> None:
    from vulnscan.advisories.osv import Verdict
    from vulnscan.findings import finding_for

    ws = _advisory("GHSA-bbbb-bbbb-bbbb", [], "8.17.1")
    finding = finding_for(_package("8.17.0"), [(ws, Verdict.AFFECTED)])
    assert finding.fixed_in == "8.17.1"
    real = json.loads((OSV_DIR / "GHSA-3h5v-q93c-6h6q.json").read_text())
    from vulnscan.advisories.osv import Affected, parse_advisory

    parsed = parse_advisory(real)
    assert not isinstance(parsed, str)
    # Four ranges with four fixes; for 6.1.0 the fix is 6.2.3, not 5.2.4.
    from vulnscan.findings import _fix

    entries: list[Affected] = list(parsed.affected)
    fixes = {fixed for e in entries if (fixed := _fix("6.1.0", e)[0]) is not None}
    assert min(fixes, key=lambda v: tuple(int(x) for x in v.split("."))) == "6.2.3"


def test_undecided_findings_do_not_fail(tmp_path: Path) -> None:
    data = tmp_path / "data"
    bad = {
        "id": "PYSEC-9999-1",
        "modified": "2026-01-01T00:00:00Z",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "torch"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"last_affected": "2.6.0-cu124"},
                        ],
                    }
                ],
            }
        ],
    }
    archive = tmp_path / "PyPI.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("PYSEC-9999-1.json", json.dumps(bad))
    main(["update", "--from", f"PyPI={archive}", "--data", str(data)])
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("torch==2.13.0\n")
    code, out = scan(repo, data)
    assert code == EXIT_CLEAN
    assert '"2.6.0-cu124", not a valid version' in out


def test_an_acceptance_for_one_package_covers_only_it(
    scanned: tuple[Path, Path],
) -> None:
    repo, data = scanned
    later = (date.today() + timedelta(days=30)).isoformat()
    accept(
        repo,
        {
            "advisory": "GO-2024-2687",
            "package": "Go:stdlib",
            "reason": "x",
            "expires": later,
        },
    )
    report = json.loads(scan(repo, data, "--format", "json")[1])
    accepted = {f["package"]["name"] for f in report["findings"] if f["accepted"]}
    assert accepted == {"stdlib"}  # not golang.org/x/net, though it shares the id
