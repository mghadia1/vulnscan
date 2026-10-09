"""Shared by the git and secret tests: repositories made with the real git
(to check the hand-written reader against), and fake secrets.

Every fake secret is built at run time from random characters, and no test
file contains one whole: the scanner, run on its own repository, must not
find its tests, and a push of them must not look like a leak.
"""

import json
import os
import random
import shutil
import string
import subprocess
from base64 import urlsafe_b64encode
from pathlib import Path

import pytest

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git is not installed")

ALNUM = string.ascii_letters + string.digits
BASE32 = string.ascii_uppercase + "234567"
BASE64 = ALNUM + "+/"


class Repo:
    """A repository built with git, isolated from the user's configuration;
    every commit one second after the last, so their order is known."""

    def __init__(self, path: Path, *init: str) -> None:
        self.path = path
        self.home = path.parent / f".home-{path.name}"
        self.home.mkdir(parents=True, exist_ok=True)
        self.time = 1_700_000_000
        path.mkdir(parents=True, exist_ok=True)
        self.git("init", "-q", "-b", "main", *init)

    @classmethod
    def clone(cls, source: Repo, path: Path, *args: str) -> Repo:
        """A clone of ``source`` (whose commits are then pushed, as far as
        the clone's remote-tracking refs say)."""
        source.git("clone", "-q", *args, str(source.path), str(path))
        repo = cls.__new__(cls)
        repo.path, repo.home, repo.time = path, source.home, source.time
        return repo

    def env(self) -> dict[str, str]:
        stamp = f"{self.time} +0000"
        return {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(self.home),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
            "GIT_AUTHOR_DATE": stamp,
            "GIT_COMMITTER_DATE": stamp,
        }

    def git(self, *args: str, input: bytes | None = None) -> bytes:
        assert GIT is not None
        return subprocess.run(
            [GIT, *args],
            cwd=self.path,
            env=self.env(),
            input=input,
            capture_output=True,
            check=True,
        ).stdout

    def write(self, name: str, content: str | bytes) -> Path:
        path = self.path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_bytes(content)
        return path

    def commit(self, message: str = "change") -> str:
        self.time += 1
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD").decode().strip()

    def objects(self) -> dict[str, tuple[str, bytes]]:
        """Every object, as ``git cat-file`` gives it."""
        out = self.git("cat-file", "--batch-all-objects", "--batch")
        objects: dict[str, tuple[str, bytes]] = {}
        pos = 0
        while pos < len(out):
            newline = out.index(b"\n", pos)
            sha, kind, size = out[pos:newline].decode().split()
            start = newline + 1
            objects[sha] = (kind, out[start : start + int(size)])
            pos = start + int(size) + 1
        return objects

    def files(self, commit: str) -> set[tuple[str, str]]:
        """(path, blob) of every regular file in a commit (``git ls-tree``)."""
        out = self.git("ls-tree", "-r", "-z", commit).decode()
        files = set()
        for entry in out.split("\0"):
            if not entry:
                continue
            meta, path = entry.split("\t", 1)
            mode, kind, sha = meta.split()
            if kind == "blob" and mode != "120000":
                files.add((path, sha))
        return files


def body(rng: random.Random, n: int, chars: str = ALNUM) -> str:
    return "".join(rng.choice(chars) for _ in range(n))


def _jwt_part(value: object) -> str:
    raw = json.dumps(value).encode()
    return urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(rng: random.Random, exp: int | None = None, alg: str = "HS256") -> str:
    payload: dict[str, object] = {"sub": body(rng, 8)}
    if exp is not None:
        payload["exp"] = exp
    signature = body(rng, 43, ALNUM + "_-")
    return f"{_jwt_part({'alg': alg, 'typ': 'JWT'})}.{_jwt_part(payload)}.{signature}"


# Each format rule's fakes, as (rule, a function of the random source).
# Prefixes are split so that this file holds no whole token.
FAKES = {
    "aws-access-key-id": lambda r: "AK" + "IA" + body(r, 16, BASE32),
    "github-token": lambda r: "gh" + "p_" + body(r, 36),
    "github-fine-grained-token": lambda r: (
        "github" + "_pat_" + body(r, 22) + "_" + body(r, 59)
    ),
    "slack-token": lambda r: (
        "xo"
        + "xb-"
        + body(r, 12, string.digits)
        + "-"
        + body(r, 13, string.digits)
        + "-"
        + body(r, 24)
    ),
    "slack-webhook": lambda r: (
        "https://hooks.slack"
        + ".com/services/T"
        + body(r, 10, BASE32)
        + "/B"
        + body(r, 10, BASE32)
        + "/"
        + body(r, 24)
    ),
    "stripe-secret-key": lambda r: "sk" + "_live_" + body(r, 24),
    "stripe-test-key": lambda r: "sk" + "_test_" + body(r, 24),
    "anthropic-api-key": lambda r: "sk-" + "ant-api03-" + body(r, 93, ALNUM + "_-"),
    "openai-api-key": lambda r: (
        "sk-" + "proj-" + body(r, 20) + "T3Blbk" + "FJ" + body(r, 20)
    ),
    "huggingface-token": lambda r: "h" + "f_" + body(r, 34),
    "groq-api-key": lambda r: "gs" + "k_" + body(r, 52),
    "google-api-key": lambda r: "AI" + "za" + body(r, 35, ALNUM + "_-"),
}

# The part of each fake that is the same in every token of its kind, which
# the redacted form may show.
FIXED = {
    "aws-access-key-id": 4,
    "github-token": 4,
    "github-fine-grained-token": 11,
    "slack-token": 5,
    "slack-webhook": len("https://hooks.slack.com/services/"),
    "stripe-secret-key": 8,
    "stripe-test-key": 8,
    "anthropic-api-key": len("sk-ant-api03-"),
    "openai-api-key": 3,
    "huggingface-token": 3,
    "groq-api-key": 4,
    "google-api-key": 4,
}


def private_key_body(rng: random.Random, n: int = 400) -> str:
    text = body(rng, n, BASE64)
    return "\n".join(text[i : i + 64] for i in range(0, len(text), 64))


def pem(kind: str, key_body: str, headers: str = "") -> str:
    label = f"{kind} PRIVATE KEY" if kind else "PRIVATE KEY"
    return f"-----BEGIN {label}-----\n{headers}{key_body}\n-----END {label}-----\n"


def leaks(secret: str, output: str, fixed: int = 0, window: int = 8) -> bool:
    """Whether any ``window`` characters of the secret's random part (past
    its fixed prefix) appear in the output."""
    random_part = secret[fixed:]
    return any(
        random_part[i : i + window] in output
        for i in range(len(random_part) - window + 1)
    )
