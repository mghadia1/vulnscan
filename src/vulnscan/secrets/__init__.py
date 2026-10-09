"""Secrets committed to a repository: in its files and in its git history.

Where a secret is decides what to do about it, so every finding says:

- **committed**: in the commit checked out (HEAD), at this path.
- **history**: in an earlier commit, no longer at this path in HEAD.
  Deleting a file does not remove it from history: anyone with a clone
  still has it.
- **uncommitted**: in the working tree only, in a file git does not have
  in HEAD (an ``.env`` that is ignored, say, which is where a local secret
  belongs). Reported, never failing.
- **in-git**: in a commit, in a repository whose HEAD is not on this disk
  (its branch's ref moved to iCloud): whether the commit checked out still
  has it is not known, so it counts like committed.
- **file**: in a file outside any git repository, or in one whose history
  (or HEAD) could not be read: whether it is committed is not known, so it
  counts.

For committed and history findings: whether a commit containing it is
reachable from a remote-tracking ref (``refs/remotes/...``), that is,
pushed as of the last fetch. Once pushed, the secret is out: revoke it;
rewriting history afterwards does not take it back.

How: every distinct file content (blob) reachable from the repository's
refs is scanned once, then mapped to every path and commit that has it.
Working-tree files whose content is exactly HEAD's are not read twice.
Files over ``MAX_BYTES`` and binary files (a NUL byte in the first 8,000
bytes, as git decides) are counted and skipped. A working-tree file whose
content is not on this disk (an iCloud placeholder) is never read, since
reading it would download it: it is listed, with whether git has a file at
that path in HEAD (whose content the history scan did read). Commit
messages are not scanned.
"""

import os
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime
from pathlib import Path

from vulnscan.findings import Acceptance
from vulnscan.git import (
    GitError,
    History,
    Repository,
    blob_id,
    on_disk,
    walk_history,
)
from vulnscan.secrets.rules import TITLES, Hit, find, fingerprint
from vulnscan.walk import Tree

MAX_BYTES = 10 * 1024 * 1024
_BINARY_PROBE = 8000

STATES = ("committed", "history", "in-git", "file", "uncommitted")


@dataclass(frozen=True)
class SecretFinding:
    rule: str
    title: str
    severity: str
    path: str  # relative to the scan's target
    line: int
    column: int
    shown: str  # redacted: never the secret
    fingerprint: str
    state: str  # one of STATES
    repository: str | None  # its folder, relative to the target ("." the target)
    commit: str | None  # the first commit with it at this path
    commit_time: int | None
    pushed: bool | None  # None: not in history, or the repository has no remotes
    note: str | None
    accepted: Acceptance | None = field(default=None)

    @property
    def advice(self) -> str:
        if self.state == "uncommitted":
            return (
                "not committed: keep it out of git (.gitignore) or in the environment"
            )
        if self.state == "file":
            return "not known to be committed: check where this file goes"
        if self.pushed:
            where = {
                "committed": "in the latest commit",
                "history": "in history",
            }.get(self.state, "in a commit")
            return f"pushed ({where}): revoke it and issue a new one"
        if self.pushed is False:
            return (
                "not pushed (as of the last fetch): remove it from these commits "
                "before pushing, or revoke it"
            )
        return (
            "revoke it if it is real (whether it was pushed is not known: no "
            "remote-tracking refs, or --no-history)"
        )


@dataclass(frozen=True)
class RepositoryScan:
    path: str
    head: str | None
    commits: int
    blobs: int  # distinct file contents scanned
    missing: int
    remotes: bool
    error: str | None
    notes: tuple[str, ...]
    offline: int = 0  # files under .git not on this disk, so not read


@dataclass(frozen=True)
class SecretScan:
    history: bool  # all of each repository's history, or HEAD only
    findings: tuple[SecretFinding, ...]
    repositories: tuple[RepositoryScan, ...]
    files_scanned: int
    skipped_binary: int
    skipped_large: int
    unreadable: tuple[str, ...]
    # Files whose content is not on this disk (an iCloud placeholder), and
    # whether a file is at that path in HEAD (so its committed version was
    # scanned from git).
    offline: tuple[tuple[str, bool], ...] = ()


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _position(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    column = offset - (text.rfind("\n", 0, offset) + 1) + 1
    return line, column


def _text(data: bytes) -> str | None:
    if b"\0" in data[:_BINARY_PROBE]:
        return None
    return data.decode("utf-8", errors="replace")


@dataclass
class _Scanner:
    now: datetime
    fingerprints: dict[str, str] = field(default_factory=dict)
    skipped_binary: int = 0
    skipped_large: int = 0

    def hits(self, data: bytes, path: str) -> list[tuple[Hit, str, int, int]]:
        """Each secret in a file's content, with its fingerprint, line and
        column; [] for a binary or oversized file (counted)."""
        if len(data) > MAX_BYTES:
            self.skipped_large += 1
            return []
        text = _text(data)
        if text is None:
            self.skipped_binary += 1
            return []
        found = []
        for hit in find(text, path, self.now):
            fp = self.fingerprints.get(hit.value)
            if fp is None:
                fp = self.fingerprints[hit.value] = fingerprint(hit.value)
            found.append((hit, fp, *_position(text, hit.start)))
        return found


def _join(repo: str, path: str) -> str:
    return path if repo == "." else f"{repo}/{path}"


def _owner(path: str, repositories: Iterable[str]) -> str | None:
    """The innermost repository a path (relative to the target) is in."""
    best: str | None = None
    for repo in repositories:
        inside = repo == "." or path.startswith(repo + "/")
        if inside and (best is None or best == "." or len(repo) > len(best)):
            best = repo
    return best


def _from_history(
    scanner: _Scanner, repo: Repository, rel: str, history: History
) -> tuple[list[SecretFinding], int]:
    by_blob: dict[str, list[int]] = {}
    for n, occurrence in enumerate(history.occurrences):
        by_blob.setdefault(occurrence.blob, []).append(n)
    # (fingerprint, path, rule) -> the finding so far
    found: dict[tuple[str, str, str], SecretFinding] = {}
    for blob, indexes in by_blob.items():
        try:
            kind, data = repo.read(blob)
        except GitError:
            continue  # counted by the walk, or a damaged object
        if kind != "blob":
            continue
        some_path = history.occurrences[indexes[0]].path
        for hit, fp, line, column in scanner.hits(data, some_path):
            for n in indexes:
                o = history.occurrences[n]
                path = _join(rel, o.path)
                key = (fp, path, hit.rule)
                candidate = SecretFinding(
                    rule=hit.rule,
                    title=TITLES[hit.rule],
                    severity=hit.severity,
                    path=path,
                    line=line,
                    column=column,
                    shown=hit.shown,
                    fingerprint=fp,
                    state=(
                        "committed"
                        if o.in_head
                        else "history"
                        if history.head_known
                        else "in-git"
                    ),
                    repository=rel,
                    commit=o.first_commit,
                    commit_time=o.first_time,
                    pushed=o.pushed if history.remotes else None,
                    note=hit.note,
                )
                old = found.get(key)
                found[key] = candidate if old is None else _merge(old, candidate)
    return list(found.values()), len(by_blob)


def _merge(a: SecretFinding, b: SecretFinding) -> SecretFinding:
    """One secret at one path, seen in two file versions: committed if
    either is HEAD's (with HEAD's line), first seen in the earlier commit,
    pushed if either was."""
    head = a if a.state == "committed" else b if b.state == "committed" else None
    earliest = min(a, b, key=lambda f: (f.commit_time or 0, f.commit or ""))
    base = head or earliest
    pushed = None if a.pushed is None else (a.pushed or bool(b.pushed))
    return replace(
        base,
        commit=earliest.commit,
        commit_time=earliest.commit_time,
        pushed=pushed,
        severity=min(a.severity, b.severity, key=_SEVERITY_ORDER.__getitem__),
    )


def scan(target: Path, tree: Tree, history: bool = True) -> SecretScan:
    """Secrets in the files of ``tree`` (a walk of ``target``) and in the
    history of each git repository in it (``history=False``: HEAD only)."""
    scanner = _Scanner(now=datetime.now(UTC))
    findings: list[SecretFinding] = []
    summaries: list[RepositoryScan] = []
    head_files: dict[str, set[tuple[str, str]]] = {}  # repo -> (path, blob) in HEAD
    unreadable_repos: set[str] = set()

    for rel in tree.repositories:
        git_dir = (target if rel == "." else target / rel) / ".git"
        try:
            repo = Repository.open(git_dir)
        except (GitError, OSError) as error:
            unreadable_repos.add(rel)
            summaries.append(RepositoryScan(rel, None, 0, 0, 0, False, str(error), ()))
            continue
        try:
            walked = walk_history(repo, everything=history)
            found, blobs = _from_history(scanner, repo, rel, walked)
        except (GitError, OSError) as error:
            unreadable_repos.add(rel)
            summaries.append(
                RepositoryScan(
                    rel,
                    None,
                    0,
                    0,
                    0,
                    False,
                    str(error),
                    tuple(repo.notes),
                    len(repo.offline),
                )
            )
            continue
        finally:
            repo.close()
        findings += found
        head_files[rel] = {(o.path, o.blob) for o in walked.occurrences if o.in_head}
        notes = tuple(repo.notes)
        if repo.head_from_reflog:
            notes += ("HEAD read from its reflog: its ref is not on this disk",)
        if not walked.head_known:
            # Its files cannot be compared with HEAD: read as plain files.
            unreadable_repos.add(rel)
            notes += (
                "HEAD's branch is not on this disk (iCloud): which commit is "
                "checked out is not known",
            )
        summaries.append(
            RepositoryScan(
                rel,
                walked.head,
                walked.commits,
                blobs,
                walked.missing,
                walked.remotes,
                None,
                notes,
                len(repo.offline),
            )
        )

    committed = {
        (f.fingerprint, f.path) for f in findings if f.state in ("committed", "in-git")
    }
    readable = [r for r in tree.repositories if r not in unreadable_repos]
    head_paths = {
        repo: {path for path, _ in files} for repo, files in head_files.items()
    }
    files_scanned = 0
    unreadable: list[str] = []
    offline: list[tuple[str, bool]] = []
    for path in tree.files:
        repo_rel = _owner(path, tree.repositories)
        in_repo = repo_rel is not None and repo_rel in readable
        inner = path
        if in_repo and repo_rel != ".":
            assert repo_rel is not None
            inner = path[len(repo_rel) + 1 :]
        try:
            st = os.lstat(target / path)
            if not on_disk(st):
                # Reading it would download it: never done for a scan.
                committed_path = in_repo and inner in head_paths[repo_rel or "."]
                offline.append((path, committed_path))
                continue
            if st.st_size > MAX_BYTES:
                scanner.skipped_large += 1  # not read at all
                continue
            data = (target / path).read_bytes()
        except OSError:
            unreadable.append(path)
            continue
        if in_repo:
            assert repo_rel is not None
            if (inner, blob_id(data)) in head_files[repo_rel]:
                continue  # exactly HEAD's: scanned with the history
        files_scanned += 1
        for hit, fp, line, column in scanner.hits(data, path):
            if (fp, path) in committed:
                continue  # an edited file, but this secret is HEAD's
            findings.append(
                SecretFinding(
                    rule=hit.rule,
                    title=TITLES[hit.rule],
                    severity=hit.severity,
                    path=path,
                    line=line,
                    column=column,
                    shown=hit.shown,
                    fingerprint=fp,
                    state="uncommitted" if in_repo else "file",
                    repository=repo_rel if in_repo else None,
                    commit=None,
                    commit_time=None,
                    pushed=None,
                    note=hit.note,
                )
            )

    findings.sort(
        key=lambda f: (
            f.state == "uncommitted",  # last: never failing
            _SEVERITY_ORDER.get(f.severity, 9),
            f.path,
            f.line,
            f.rule,
        )
    )
    return SecretScan(
        history=history,
        findings=tuple(findings),
        repositories=tuple(summaries),
        files_scanned=files_scanned,
        skipped_binary=scanner.skipped_binary,
        skipped_large=scanner.skipped_large,
        unreadable=tuple(unreadable),
        offline=tuple(offline),
    )


@dataclass(frozen=True)
class AppliedSecrets:
    findings: tuple[SecretFinding, ...]
    expired: tuple[tuple[Acceptance, SecretFinding], ...]
    unused: tuple[Acceptance, ...]


def apply(
    findings: tuple[SecretFinding, ...], acceptances: list[Acceptance], today: date
) -> AppliedSecrets:
    """Acceptances by fingerprint (``secret = "..."`` in the baseline file),
    as for advisories: a reason and an expiry date, reported either way."""
    mine = [a for a in acceptances if a.secret is not None]
    used: set[int] = set()
    expired: list[tuple[Acceptance, SecretFinding]] = []
    result: list[SecretFinding] = []
    for finding in findings:
        holding = None
        for n, acceptance in enumerate(mine):
            if acceptance.secret != finding.fingerprint:
                continue
            used.add(n)
            if acceptance.expires < today:
                expired.append((acceptance, finding))
            elif holding is None:
                holding = acceptance
        result.append(replace(finding, accepted=holding) if holding else finding)
    unused = tuple(a for n, a in enumerate(mine) if n not in used)
    return AppliedSecrets(tuple(result), tuple(expired), unused)


def commit_date(finding: SecretFinding) -> str | None:
    if finding.commit_time is None:
        return None
    return datetime.fromtimestamp(finding.commit_time, UTC).date().isoformat()
