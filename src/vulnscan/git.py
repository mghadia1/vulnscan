"""Reads a git repository's history from its object store, by hand.

VulnScan never runs ``git``. Running it in a repository runs that
repository's configuration: ``core.fsmonitor``, ``core.pager`` and others
name programs that git starts, so a scanner that runs git in a directory
runs whatever that directory asks for. Git also refuses a repository owned
by another user ("dubious ownership"), which is how a scan in a container
sees one. Reading the files under ``.git`` directly does neither, needs no
git in the image, and writes nothing.

What is read:

- **Refs:** ``HEAD``, every file under ``refs/``, and ``packed-refs``. A
  link anywhere under ``.git`` is not followed.
- **Objects:** loose objects (``objects/xx/...``, zlib) and packs
  (``objects/pack/*.idx`` version 2 and ``*.pack``), with both kinds of
  delta (OFS_DELTA, REF_DELTA). Every object read is checked against its
  name: its SHA-1 must be the id it was asked for.
- **Not read, and said so:** SHA-256 repositories, alternates (object
  stores elsewhere on the machine), version 1 pack indexes, a ``.git`` that
  is a file (a worktree or submodule pointing elsewhere). Missing objects
  (a shallow or partial clone) are counted, not fatal.
- **Not on this disk:** a file under ``.git`` that macOS has moved to iCloud
  (a "dataless" placeholder) is not read, and is listed: reading it would
  download it, which took 12 seconds per 41-byte ref on the machine this
  was written on. A ref not on disk is skipped (its history may be
  missing); an object not on disk counts as missing.
"""

import hashlib
import mmap
import os
import re
import stat
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

# Object types, as packs number them.
_TYPES = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
_OFS_DELTA = 6
_REF_DELTA = 7

# Tree entry modes.
MODE_TREE = 0o040000
MODE_LINK = 0o120000
MODE_GITLINK = 0o160000  # a submodule's commit: not an object of this repo

_SHA_HEX = re.compile(r"[0-9a-f]{40}")
# macOS's flag for a file whose content is in the cloud, not on this disk.
DATALESS = 0x40000000
_CACHE_BYTES = 64 * 1024 * 1024  # resolved delta bases kept in memory


class GitError(Exception):
    """A repository that cannot be read as written."""


class MissingObject(GitError):
    pass


def on_disk(st: os.stat_result) -> bool:
    return not getattr(st, "st_flags", 0) & DATALESS


@dataclass
class _Pack:
    path: Path
    data: mmap.mmap
    offsets: dict[bytes, int]


@dataclass
class Repository:
    """One ``.git`` directory, opened for reading."""

    git_dir: Path
    notes: list[str] = field(default_factory=list)
    offline: set[str] = field(default_factory=set)  # under .git, not on disk
    # Set by head(): HEAD could not be resolved because a file it needs (its
    # branch's ref, say) is not on this disk. Then which commit is checked
    # out is not known, which is not the same as there being none.
    head_unknown: bool = False
    # Set by head(): HEAD was read from its reflog, because HEAD or its
    # branch's ref is not on this disk.
    head_from_reflog: bool = False
    _packs: list[_Pack] = field(default_factory=list)
    _cache: dict[tuple[int, int], tuple[str, bytes]] = field(default_factory=dict)
    _cached_bytes: int = 0

    def _state(self, path: Path) -> str | None:
        """ "file" for a regular file that is on this disk; "offline" for one
        that is not (counted); None for anything else (absent, a link)."""
        try:
            st = os.lstat(path)
        except OSError:
            return None
        if not stat.S_ISREG(st.st_mode):
            return None
        if not on_disk(st):
            self.offline.add(path.relative_to(self.git_dir).as_posix())
            return "offline"
        return "file"

    def _text(self, path: Path) -> str | None:
        if self._state(path) != "file":
            return None
        return path.read_text(encoding="utf-8", errors="replace")

    @classmethod
    def open(cls, git_dir: Path) -> Repository:
        if not git_dir.is_dir() or git_dir.is_symlink():
            raise GitError(f"{git_dir}: not a git directory")
        repo = cls(git_dir)
        config = repo._text(git_dir / "config")
        if config and re.search(r"(?im)^\s*objectformat\s*=\s*sha256\b", config):
            raise GitError("a SHA-256 repository (not read)")
        if repo._state(git_dir / "objects" / "info" / "alternates") is not None:
            repo.notes.append(
                "objects/info/alternates names object stores elsewhere: not read"
            )
        pack_dir = git_dir / "objects" / "pack"
        if pack_dir.is_dir() and not pack_dir.is_symlink():
            for idx in sorted(pack_dir.glob("pack-*.idx")):
                pack = idx.with_suffix(".pack")
                if repo._state(idx) != "file" or repo._state(pack) != "file":
                    continue
                try:
                    repo._packs.append(_open_pack(idx, pack))
                except GitError as error:
                    repo.notes.append(f"{idx.name}: {error}")
        return repo

    def close(self) -> None:
        for pack in self._packs:
            pack.data.close()
        self._packs.clear()
        self._cache.clear()

    # -- refs --------------------------------------------------------------

    def _resolve_ref(self, name: str, depth: int = 0, head: bool = False) -> str | None:
        if depth > 5:
            return None
        path = self.git_dir / name
        state = self._state(path)
        if state == "offline":
            if head:
                self.head_unknown = True
            return None  # not the packed value: that may be an older one
        if state == "file":
            text = path.read_text(encoding="utf-8", errors="replace").strip()
            if text.startswith("ref: "):
                return self._resolve_ref(text[5:].strip(), depth + 1, head)
            return text if _SHA_HEX.fullmatch(text) else None
        return self._packed_refs().get(name)

    def _packed_refs(self) -> dict[str, str]:
        refs: dict[str, str] = {}
        text = self._text(self.git_dir / "packed-refs")
        if text is None:
            return refs
        for line in text.splitlines():
            if line.startswith(("#", "^")):
                continue  # a comment, or the commit a tag above points at
            sha, _, name = line.partition(" ")
            if _SHA_HEX.fullmatch(sha) and name:
                refs[name.strip()] = sha
        return refs

    def head(self) -> str | None:
        """The commit checked out: None in a repository with no commits, or
        when that cannot be known (``head_unknown``).

        When HEAD, or the branch it names, is not on this disk, HEAD's own
        reflog (``logs/HEAD``) says: git adds a line to it whenever HEAD
        changes, a commit on the branch included, so its last line's new
        value is HEAD now (``head_from_reflog``)."""
        self.head_unknown = False
        self.head_from_reflog = False
        sha = self._resolve_ref("HEAD", head=True)
        if sha is None and self.head_unknown:
            logged = self._reflog_tip("logs/HEAD")
            if logged is not None:
                self.head_unknown = False
                self.head_from_reflog = True
                return logged
        return sha

    def _reflog_tip(self, name: str) -> str | None:
        """The value a reflog says its ref has now: its last line's new
        value ("<old> <new> <who> <when>\t<message>")."""
        text = self._text(self.git_dir / name)
        if not text:
            return None
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines:
            return None
        fields = lines[-1].split(" ", 2)
        if len(fields) < 2 or not _SHA_HEX.fullmatch(fields[1]):
            return None
        return None if fields[1] == "0" * 40 else fields[1]

    def refs(self) -> dict[str, str]:
        """Every ref's name and the object it names (commits or tags)."""
        refs = self._packed_refs()
        root = self.git_dir / "refs"
        if root.is_dir() and not root.is_symlink():
            for here, dirs, names in os.walk(root, followlinks=False):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(here, d))]
                for name in names:
                    path = Path(here) / name
                    ref = path.relative_to(self.git_dir).as_posix()
                    sha = self._resolve_ref(ref)
                    if sha is not None:
                        refs[ref] = sha
        head = self.head()
        if head is not None:
            refs["HEAD"] = head
        return refs

    def shallow(self) -> frozenset[str]:
        """Commits whose parents a shallow clone does not have."""
        text = self._text(self.git_dir / "shallow")
        return frozenset(_SHA_HEX.findall(text)) if text else frozenset()

    # -- objects -----------------------------------------------------------

    def read(self, sha: str) -> tuple[str, bytes]:
        """An object's type and content, checked against its name."""
        raw = bytes.fromhex(sha)
        for n, pack in enumerate(self._packs):
            offset = pack.offsets.get(raw)
            if offset is not None:
                kind, data = self._unpack(n, offset)
                break
        else:
            kind, data = self._loose(sha)
        header = f"{kind} {len(data)}\0".encode()
        if hashlib.sha1(header + data, usedforsecurity=False).hexdigest() != sha:
            raise GitError(f"object {sha} does not match its name (damaged)")
        return kind, data

    def _loose(self, sha: str) -> tuple[str, bytes]:
        path = self.git_dir / "objects" / sha[:2] / sha[2:]
        if self._state(path) != "file":
            raise MissingObject(f"object {sha} not found (or not on this disk)")
        try:
            compressed = path.read_bytes()
        except OSError as error:
            raise MissingObject(f"object {sha} not found") from error
        try:
            data = zlib.decompress(compressed)
        except zlib.error as error:
            raise GitError(f"object {sha}: {error}") from error
        header, sep, content = data.partition(b"\0")
        kind, _, size = header.decode("ascii", errors="replace").partition(" ")
        if not sep or kind not in _TYPES.values() or not size.isdigit():
            raise GitError(f"object {sha}: not a git object")
        if int(size) != len(content):
            raise GitError(f"object {sha}: size {size} but {len(content)} bytes")
        return kind, content

    def _unpack(self, n: int, offset: int) -> tuple[str, bytes]:
        cached = self._cache.get((n, offset))
        if cached is not None:
            return cached
        data = self._packs[n].data
        kind_number, size, pos = _object_header(data, offset)
        if kind_number in _TYPES:
            result = (_TYPES[kind_number], _inflate(data, pos, size))
        elif kind_number == _OFS_DELTA:
            distance, pos = _offset_distance(data, pos)
            if distance <= 0 or distance > offset:
                raise GitError(f"a delta at {offset} points outside its pack")
            base = self._unpack(n, offset - distance)
            result = (base[0], apply_delta(base[1], _inflate(data, pos, size)))
        elif kind_number == _REF_DELTA:
            base_sha = bytes(data[pos : pos + 20]).hex()
            base = self.read(base_sha)
            result = (base[0], apply_delta(base[1], _inflate(data, pos + 20, size)))
        else:
            raise GitError(f"unknown object type {kind_number} at {offset}")
        # Deltas are mostly against recent bases: keep some, within a budget.
        if self._cached_bytes + len(result[1]) > _CACHE_BYTES:
            self._cache.clear()
            self._cached_bytes = 0
        self._cache[(n, offset)] = result
        self._cached_bytes += len(result[1])
        return result

    def object_ids(self) -> Iterator[str]:
        """Every object in the store, loose and packed (used by tests)."""
        seen: set[str] = set()
        for pack in self._packs:
            for raw in pack.offsets:
                seen.add(raw.hex())
        objects = self.git_dir / "objects"
        for prefix in sorted(os.listdir(objects)) if objects.is_dir() else []:
            if len(prefix) == 2 and (objects / prefix).is_dir():
                for rest in os.listdir(objects / prefix):
                    if _SHA_HEX.fullmatch(prefix + rest):
                        seen.add(prefix + rest)
        yield from sorted(seen)


def _open_pack(idx_path: Path, pack_path: Path) -> _Pack:
    idx = idx_path.read_bytes()
    if idx[:4] != b"\xfftOc":
        raise GitError("a version 1 pack index (not read)")
    if int.from_bytes(idx[4:8]) != 2:
        raise GitError(f"pack index version {int.from_bytes(idx[4:8])} (not read)")
    count = int.from_bytes(idx[8 + 255 * 4 : 8 + 256 * 4])
    names_at = 8 + 256 * 4
    offsets_at = names_at + 24 * count  # past the names and their CRC-32s
    large_at = offsets_at + 4 * count
    if len(idx) < large_at + 40:
        raise GitError("a truncated pack index")
    offsets: dict[bytes, int] = {}
    for i in range(count):
        name = idx[names_at + 20 * i : names_at + 20 * (i + 1)]
        offset = int.from_bytes(idx[offsets_at + 4 * i : offsets_at + 4 * (i + 1)])
        if offset & 0x80000000:  # an index into the table of 8-byte offsets
            at = large_at + 8 * (offset & 0x7FFFFFFF)
            offset = int.from_bytes(idx[at : at + 8])
        offsets[name] = offset
    with pack_path.open("rb") as f:
        data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    if data[:4] != b"PACK" or int.from_bytes(data[4:8]) not in (2, 3):
        data.close()
        raise GitError("not a pack file")
    return _Pack(pack_path, data, offsets)


def _object_header(data: mmap.mmap, pos: int) -> tuple[int, int, int]:
    """A packed object's type number and size, and where its data starts."""
    byte = data[pos]
    kind = (byte >> 4) & 7
    size = byte & 0x0F
    shift = 4
    pos += 1
    while byte & 0x80:
        byte = data[pos]
        size |= (byte & 0x7F) << shift
        shift += 7
        pos += 1
    return kind, size, pos


def _offset_distance(data: mmap.mmap, pos: int) -> tuple[int, int]:
    """OFS_DELTA's distance back to its base (git's own variable-length
    encoding, which adds one per continuation byte)."""
    byte = data[pos]
    distance = byte & 0x7F
    pos += 1
    while byte & 0x80:
        byte = data[pos]
        distance = ((distance + 1) << 7) | (byte & 0x7F)
        pos += 1
    return distance, pos


def _inflate(data: mmap.mmap, pos: int, size: int) -> bytes:
    """``size`` bytes, inflated from the zlib stream starting at ``pos``.
    Fed in chunks: a pack is one file, and inflating "the rest of it" would
    copy everything after the object each time."""
    inflater = zlib.decompressobj()
    out = bytearray()
    view = memoryview(data)
    try:
        while not inflater.eof and pos < len(data):
            chunk = view[pos : pos + 65536]
            pos += len(chunk)
            out += inflater.decompress(chunk)
    except zlib.error as error:
        raise GitError(f"a damaged object in a pack: {error}") from error
    finally:
        view.release()
    if len(out) != size:
        raise GitError(f"a packed object of {len(out)} bytes, expected {size}")
    return bytes(out)


def _varint(delta: bytes, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if pos >= len(delta):
            raise GitError("a truncated delta")
        byte = delta[pos]
        value |= (byte & 0x7F) << shift
        shift += 7
        pos += 1
        if not byte & 0x80:
            return value, pos


def apply_delta(base: bytes, delta: bytes) -> bytes:
    """Git's delta format: the base's size, the result's size, then
    instructions that copy a range of the base or insert new bytes."""
    base_size, pos = _varint(delta, 0)
    result_size, pos = _varint(delta, pos)
    if base_size != len(base):
        raise GitError(f"a delta for a {base_size}-byte base, given {len(base)}")
    out = bytearray()
    while pos < len(delta):
        op = delta[pos]
        pos += 1
        if op & 0x80:  # copy: which offset and size bytes follow is a bitmap
            offset = size = 0
            for i in range(4):
                if op & (1 << i):
                    offset |= delta[pos] << (8 * i)
                    pos += 1
            for i in range(3):
                if op & (0x10 << i):
                    size |= delta[pos] << (8 * i)
                    pos += 1
            if size == 0:
                size = 0x10000
            if offset + size > len(base):
                raise GitError("a delta copies past the end of its base")
            out += base[offset : offset + size]
        elif op:  # insert the next op bytes
            if pos + op > len(delta):
                raise GitError("a truncated delta")
            out += delta[pos : pos + op]
            pos += op
        else:
            raise GitError("a delta with the reserved instruction 0")
    if len(out) != result_size:
        raise GitError(f"a delta made {len(out)} bytes, expected {result_size}")
    return bytes(out)


# -- commits and trees --------------------------------------------------------


@dataclass(frozen=True)
class Commit:
    sha: str
    tree: str
    parents: tuple[str, ...]
    time: int  # the committer's, seconds since 1970


def parse_commit(sha: str, data: bytes) -> Commit:
    tree = ""
    parents: list[str] = []
    time = 0
    for line in data.split(b"\n"):
        if not line:
            break  # the headers end at the first empty line
        key, _, value = line.partition(b" ")
        if key == b"tree":
            tree = value.decode("ascii", errors="replace")
        elif key == b"parent":
            parents.append(value.decode("ascii", errors="replace"))
        elif key == b"committer":
            # "Name <email> 1700000000 +0100": the time is second from last.
            fields = value.rsplit(b" ", 2)
            if len(fields) == 3 and fields[1].isdigit():
                time = int(fields[1])
    if not _SHA_HEX.fullmatch(tree):
        raise GitError(f"commit {sha} has no tree")
    return Commit(sha, tree, tuple(parents), time)


def parse_tag_target(data: bytes) -> str | None:
    for line in data.split(b"\n"):
        if line.startswith(b"object "):
            target = line[7:].decode("ascii", errors="replace")
            return target if _SHA_HEX.fullmatch(target) else None
        if not line:
            break
    return None


def parse_tree(data: bytes) -> list[tuple[int, str, str]]:
    """A tree's entries: (mode, name, object id)."""
    entries: list[tuple[int, str, str]] = []
    pos = 0
    while pos < len(data):
        space = data.find(b" ", pos)
        nul = data.find(b"\0", space + 1)
        if space < 0 or nul < 0 or nul + 21 > len(data):
            raise GitError("a damaged tree")
        mode = int(data[pos:space], 8)
        name = data[space + 1 : nul].decode("utf-8", errors="surrogateescape")
        entries.append((mode, name, data[nul + 1 : nul + 21].hex()))
        pos = nul + 21
    return entries


def file_at(repo: Repository, commit: str, path: str) -> bytes | None:
    """The content of the file at ``path`` in ``commit`` (None if there is
    no regular file there)."""
    kind, data = repo.read(commit)
    if kind != "commit":
        return None
    tree = parse_commit(commit, data).tree
    parts = path.split("/")
    for n, part in enumerate(parts):
        kind, data = repo.read(tree)
        found = {name: (mode, sha) for mode, name, sha in parse_tree(data)}
        if part not in found:
            return None
        mode, sha = found[part]
        if n == len(parts) - 1:
            if mode & 0o170000 != 0o100000:
                return None
            return repo.read(sha)[1]
        if mode != MODE_TREE:
            return None
        tree = sha
    return None


def blob_id(content: bytes) -> str:
    """The id git gives this content as a file (``git hash-object``)."""
    header = f"blob {len(content)}\0".encode()
    return hashlib.sha1(header + content, usedforsecurity=False).hexdigest()


# -- history ------------------------------------------------------------------


@dataclass(frozen=True)
class Occurrence:
    """A file's content (a blob) at one path, across the commits that have
    it there."""

    path: str
    blob: str
    first_commit: str  # the earliest, by committer time
    first_time: int
    in_head: bool  # this content is at this path in the commit checked out
    pushed: bool  # some commit with it is reachable from a remote-tracking ref


@dataclass(frozen=True)
class History:
    head: str | None
    commits: int
    occurrences: tuple[Occurrence, ...]
    missing: int  # objects named but not present (shallow or partial clones)
    remotes: bool  # whether any remote-tracking ref exists
    head_known: bool = True  # False: HEAD's ref is not on this disk


@dataclass
class _First:
    commit: str
    time: int
    pushed: bool


def _peel(repo: Repository, sha: str) -> str | None:
    """A ref's commit: annotated tags are followed to what they tag."""
    for _ in range(10):
        kind, data = repo.read(sha)
        if kind == "commit":
            return sha
        if kind != "tag":
            return None  # a tag of a tree or blob: no history to walk
        target = parse_tag_target(data)
        if target is None:
            return None
        sha = target
    return None


def _is_file(mode: int) -> bool:
    return mode & 0o170000 == 0o100000


def walk_history(repo: Repository, everything: bool = True) -> History:
    """Every (path, content) pair in the history reachable from the refs
    (``everything``), or in the commit checked out only."""
    missing = 0
    tips: list[str] = []
    remote_tips: list[str] = []
    if everything:
        refs = repo.refs()
    else:
        head_sha = repo.head()
        refs = {"HEAD": head_sha} if head_sha else {}
    for name, sha in sorted(refs.items()):
        try:
            tip = _peel(repo, sha)
        except MissingObject:
            missing += 1
            continue
        if tip is None:
            continue
        tips.append(tip)
        if name.startswith("refs/remotes/"):
            remote_tips.append(tip)

    shallow = repo.shallow()
    commits: dict[str, Commit] = {}
    stack = list(tips)
    while stack:
        sha = stack.pop()
        if sha in commits:
            continue
        try:
            kind, data = repo.read(sha)
        except MissingObject:
            missing += 1
            continue
        if kind != "commit":
            continue
        commit = parse_commit(sha, data)
        commits[sha] = commit
        if everything and sha not in shallow:
            stack.extend(p for p in commit.parents if p not in commits)

    pushed_commits: set[str] = set()
    stack = list(remote_tips)
    while stack:
        sha = stack.pop()
        if sha in pushed_commits or sha not in commits:
            continue
        pushed_commits.add(sha)
        stack.extend(commits[sha].parents)

    trees: dict[str, list[tuple[int, str, str]]] = {}

    def entries(sha: str) -> list[tuple[int, str, str]]:
        nonlocal missing
        if sha not in trees:
            try:
                kind, data = repo.read(sha)
                trees[sha] = parse_tree(data) if kind == "tree" else []
            except MissingObject:
                missing += 1
                trees[sha] = []
        return trees[sha]

    head = repo.head()
    head_known = not repo.head_unknown
    in_head: set[tuple[str, str]] = set()
    if head is not None and head in commits:

        def flatten(sha: str, prefix: str) -> None:
            for mode, name, child in entries(sha):
                if mode == MODE_TREE:
                    flatten(child, f"{prefix}{name}/")
                elif _is_file(mode):
                    in_head.add((f"{prefix}{name}", child))

        flatten(commits[head].tree, "")

    # Oldest first, so the first commit to show a (path, content) is the one
    # that introduced it. A subtree already seen at the same place, from a
    # commit with the same pushed state, has nothing new to add.
    found: dict[tuple[str, str], _First] = {}
    seen: set[tuple[str, str, bool]] = set()

    def visit(sha: str, prefix: str, commit: Commit, pushed: bool) -> None:
        key = (prefix, sha, pushed)
        if key in seen:
            return
        seen.add(key)
        for mode, name, child in entries(sha):
            path = f"{prefix}{name}"
            if mode == MODE_TREE:
                visit(child, f"{path}/", commit, pushed)
            elif _is_file(mode):  # not links, not submodules
                first = found.get((path, child))
                if first is None:
                    found[(path, child)] = _First(commit.sha, commit.time, pushed)
                elif pushed:
                    first.pushed = True

    for commit in sorted(commits.values(), key=lambda c: (c.time, c.sha)):
        visit(commit.tree, "", commit, commit.sha in pushed_commits)

    occurrences = tuple(
        Occurrence(
            path=path,
            blob=blob,
            first_commit=first.commit,
            first_time=first.time,
            in_head=(path, blob) in in_head,
            pushed=first.pushed,
        )
        for (path, blob), first in sorted(found.items())
    )
    return History(
        head, len(commits), occurrences, missing, bool(remote_tips), head_known
    )
