"""What a secret looks like: known token formats, private key blocks, JWTs,
and high-entropy values assigned to names that say "secret".

A match is never shown. What can be shown is its rule, where it is, how
long it is, and the fixed prefix a format puts in front of every token
(``ghp_``, ``AKIA``): the prefix says what kind of credential it is and is
the same in every token of that kind. The random part never appears in any
output; the fingerprint (``fingerprint``) identifies a value without
revealing it.

Formats are written from the providers' documented shapes and tested with
generated tokens of those shapes; no real token was used to write or test
them. No checksum is checked (GitHub's tokens carry one; its algorithm is
not checked against a real token here), and nothing is ever sent to a
provider to ask whether a token works: that would be a request to another
system, which VulnScan does not make.
"""

import base64
import binascii
import hashlib
import json
import math
import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

# Characters that continue a token: a match must not start or end inside a
# longer run of them (an "AKIA..." inside a base64 blob is not a key). "="
# ends base64 (padding), so it may come before a token: the first version
# had it here and missed every KEY=token line in an .env file (found on the
# portfolio).
_TOKEN_CHARS = r"A-Za-z0-9_+/=-"
_BEFORE = r"(?<![A-Za-z0-9_+/-])"
_AFTER = rf"(?![{_TOKEN_CHARS}])"

# Values that are someone's placeholder, not a secret.
_PLACEHOLDER = re.compile(
    r"(?i)example|x{6,}|\*{4,}|placeholder|change[_-]?me|your[_-]|redacted|dummy"
)

# The fingerprint is a slow hash (PBKDF2, 100,000 rounds): a fingerprint is
# shown and kept in baseline files, and a fast hash of a guessable value
# would let anyone check guesses against it at billions per second.
_SALT = b"vulnscan secret fingerprint v1"
_ROUNDS = 100_000


def fingerprint(value: str) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", value.encode(), _SALT, _ROUNDS)
    return digest.hex()[:16]


def entropy(value: str) -> float:
    """Shannon entropy, in bits per character, of the value's own
    character frequencies."""
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


@dataclass(frozen=True)
class Hit:
    """One match. ``value`` stays in memory, to be fingerprinted; nothing
    that is printed or written may be built from it."""

    rule: str
    severity: str
    start: int
    end: int
    value: str
    shown: str  # the redacted form: a fixed prefix at most, and the length
    note: str | None = None


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    prefix: Callable[[str], str]  # the fixed, non-secret start of a match


def _fixed(n: int) -> Callable[[str], str]:
    return lambda match: match[:n]


def _up_to(sep: str, count: int) -> Callable[[str], str]:
    """The prefix up to and including the ``count``-th ``sep``."""

    def prefix(match: str) -> str:
        at = -1
        for _ in range(count):
            at = match.find(sep, at + 1)
            if at < 0:
                return ""
        return match[: at + 1]

    return prefix


def _rule(
    id: str, title: str, severity: str, body: str, prefix: Callable[[str], str]
) -> Rule:
    return Rule(id, title, severity, re.compile(_BEFORE + body + _AFTER), prefix)


RULES: tuple[Rule, ...] = (
    _rule(
        "aws-access-key-id",
        "An AWS access key id",
        "high",
        r"(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}",
        _fixed(4),
    ),
    _rule(
        "github-token",
        "A GitHub token",
        "high",
        r"gh[pousr]_[A-Za-z0-9]{36}",
        _fixed(4),
    ),
    _rule(
        "github-fine-grained-token",
        "A GitHub fine-grained token",
        "high",
        r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
        _fixed(11),
    ),
    _rule(
        "slack-token",
        "A Slack token",
        "high",
        r"xox[abeoprs]-[0-9]{6,}-[A-Za-z0-9-]{8,}",
        _fixed(5),
    ),
    _rule(
        "slack-webhook",
        "A Slack incoming webhook",
        "medium",
        r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_-]{20,}",
        _up_to("/", 4),
    ),
    _rule(
        "stripe-secret-key",
        "A Stripe live secret key",
        "high",
        r"(?:sk|rk)_live_[A-Za-z0-9]{20,}",
        _fixed(8),
    ),
    _rule(
        "stripe-test-key",
        "A Stripe test-mode secret key",
        "low",
        r"(?:sk|rk)_test_[A-Za-z0-9]{20,}",
        _fixed(8),
    ),
    _rule(
        "anthropic-api-key",
        "An Anthropic API key",
        "high",
        r"sk-ant-[a-z]+[0-9]{2}-[A-Za-z0-9_-]{80,}",
        _up_to("-", 3),
    ),
    _rule(
        "openai-api-key",
        "An OpenAI API key",
        "high",
        # "T3BlbkFJ" is "OpenAI" in base64, in the middle of every key.
        r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}T3BlbkFJ[A-Za-z0-9_-]{16,}",
        _fixed(3),
    ),
    _rule(
        "huggingface-token",
        "A Hugging Face token",
        "high",
        r"hf_[A-Za-z0-9]{34}",
        _fixed(3),
    ),
    _rule(
        "groq-api-key",
        "A Groq API key",
        "high",
        r"gsk_[A-Za-z0-9]{52}",
        _fixed(4),
    ),
    _rule(
        "google-api-key",
        "A Google API key",
        # Often public by design (a Maps key in a web page, restricted to a
        # site), so not ranked with the others.
        "medium",
        r"AIza[A-Za-z0-9_-]{35}",
        _fixed(4),
    ),
)

TITLES = {rule.id: rule.title for rule in RULES} | {
    "private-key": "A private key",
    "jwt": "A signed JSON Web Token",
    "secret-assignment": "A high-entropy value assigned to a secret's name",
}


def _shown(prefix: str, value: str) -> str:
    return (
        f"{prefix}… ({len(value)} characters)"
        if prefix
        else (f"… ({len(value)} characters)")
    )


# Text each format's pattern cannot match without (a literal it requires):
# a format whose markers are all absent from a file is not searched for.
# Searching for a short literal is far cheaper than running the pattern, and
# most files hold none (measured: the format patterns were 57% of a scan of
# my portfolio's files before this).
_MARKERS = {
    "aws-access-key-id": ("AKIA", "ASIA", "ABIA", "ACCA"),
    "github-token": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    "github-fine-grained-token": ("github_pat_",),
    "slack-token": ("xox",),
    "slack-webhook": ("hooks.slack.com/",),
    "stripe-secret-key": ("_live_",),
    "stripe-test-key": ("_test_",),
    "anthropic-api-key": ("sk-ant-",),
    "openai-api-key": ("T3BlbkFJ",),
    "huggingface-token": ("hf_",),
    "groq-api-key": ("gsk_",),
    "google-api-key": ("AIza",),
}
assert set(_MARKERS) == {rule.id for rule in RULES}


def _known(text: str) -> Iterator[Hit]:
    for rule in RULES:
        if not any(marker in text for marker in _MARKERS[rule.id]):
            continue
        for m in rule.pattern.finditer(text):
            value = m.group()
            if _PLACEHOLDER.search(value):
                continue
            yield Hit(
                rule.id,
                rule.severity,
                m.start(),
                m.end(),
                value,
                _shown(rule.prefix(value), value),
            )


# -- private keys ------------------------------------------------------------

_KEY_BEGIN = re.compile(r"-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----")
_KEY_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
# In JSON (a notebook) or code, a key's lines are often joined with "\n"
# escapes, quotes and commas; none of those are part of it.
_KEY_NOISE = re.compile(r"\\[nr]|[\s\"',]")
_BASE64 = re.compile(r"[A-Za-z0-9+/=]")
_MAX_KEY = 20_000  # characters from BEGIN to END


def _openssh_cipher(body: str) -> str | None:
    """The cipher an OpenSSH key is encrypted with ("none": not
    encrypted), read from its own header."""
    try:
        data = base64.b64decode(body, validate=False)
    except binascii.Error, ValueError:
        return None
    magic = b"openssh-key-v1\0"
    if not data.startswith(magic) or len(data) < len(magic) + 4:
        return None
    length = int.from_bytes(data[len(magic) : len(magic) + 4])
    name = data[len(magic) + 4 : len(magic) + 4 + length]
    return name.decode("ascii", errors="replace") if len(name) == length else None


def _private_keys(text: str) -> Iterator[Hit]:
    for begin in _KEY_BEGIN.finditer(text):
        end = _KEY_END.search(text, begin.end(), begin.end() + _MAX_KEY)
        if end is None:
            continue  # a header alone (in documentation, say)
        raw = text[begin.end() : end.start()]
        # Armour headers ("Proc-Type: 4,ENCRYPTED" in a legacy PEM key,
        # "Version:" in a PGP one) are not key material.
        lines = re.split(r"\\n|\n", raw)
        encrypted_pem = any("Proc-Type: 4,ENCRYPTED" in line for line in lines)
        body = _KEY_NOISE.sub("", "".join(x for x in lines if ":" not in x))
        if len(body) < 64 or len(_BASE64.findall(body)) != len(body):
            continue
        if _PLACEHOLDER.search(body):
            continue
        kind = begin.group(1).strip()
        if kind == "OPENSSH":
            cipher = _openssh_cipher(body)
            encrypted = cipher is not None and cipher != "none"
        else:
            encrypted = kind == "ENCRYPTED" or encrypted_pem
        label = f"BEGIN {kind + ' ' if kind else ''}PRIVATE KEY"
        yield Hit(
            "private-key",
            "medium" if encrypted else "high",
            begin.start(),
            end.end(),
            body,
            f"{label}… ({len(body)} base64 characters)",
            "encrypted with a passphrase" if encrypted else None,
        )


# -- JWTs --------------------------------------------------------------------

_JWT = re.compile(
    _BEFORE + r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{16,}" + _AFTER
)


def _b64url_json(part: str) -> object:
    try:
        raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        return json.loads(raw)
    except binascii.Error, ValueError, UnicodeDecodeError:
        return None


def _jwts(text: str, now: datetime) -> Iterator[Hit]:
    for m in _JWT.finditer(text):
        value = m.group()
        header_part, payload_part, _ = value.split(".")
        header = _b64url_json(header_part)
        if not isinstance(header, dict) or "alg" not in header:
            continue
        if str(header["alg"]).lower() == "none":
            continue  # unsigned: grants nothing a server should accept
        payload = _b64url_json(payload_part)
        severity, note = "medium", None
        exp = payload.get("exp") if isinstance(payload, dict) else None
        if isinstance(exp, int | float) and not isinstance(exp, bool):
            try:
                when = datetime.fromtimestamp(exp, UTC)
            except OverflowError, OSError, ValueError:
                when = None
            if when is not None and when < now:
                severity, note = "low", f"expired {when.date().isoformat()}"
            elif when is not None:
                note = f"expires {when.date().isoformat()}"
        else:
            note = "no expiry"
        yield Hit(
            "jwt", severity, m.start(), m.end(), value, _shown("eyJ", value), note
        )


# -- high-entropy assignments -------------------------------------------------

# A name that says it holds a secret: one of these words, or one of the
# words before "key", as a whole part of the name (``db_password``,
# ``clientSecret``, ``API_KEY``; not ``tokenizer``, ``max_tokens``).
_SECRET_WORDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "credential",
        "credentials",
        "passphrase",
    }
)
_KEY_KINDS = frozenset(
    {
        "api",
        "access",
        "secret",
        "private",
        "signing",
        "encryption",
        "master",
        "client",
        "auth",
    }
)
# Last parts of a name that hold something about a secret, not the secret.
_NOT_THE_SECRET = frozenset(
    {
        "name",
        "names",
        "file",
        "path",
        "dir",
        "url",
        "uri",
        "env",
        "var",
        "field",
        "header",
        "type",
        "length",
        "len",
        "count",
        "size",
        "max",
        "min",
        "pattern",
        "regex",
        "prefix",
        "id",
        "ids",
        "hash",
        "checksum",
        "crc",
        "md",
        "digest",
        "sha",
        "sha256",
        "expiry",
        "expires",
        "ttl",
        "minutes",
        "seconds",
        "version",
        "label",
        "description",
        "help",
        "endpoint",
    }
)
_PARTS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
_KEYWORDS = re.compile(r"(?i)passw|pwd|secret|token|key|credential|passphrase")
_VALUE = r"[A-Za-z0-9_+/=.~-]{16,256}"
_ASSIGNMENT = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.-]{0,80})[\"']?\s*(?::=|=>|=|:)\s*"
    rf"(?:(?P<q>\\?[\"'`])(?P<quoted>{_VALUE})(?P=q)"
    rf"|(?P<bare>{_VALUE})(?=\s|$|[,;#}}\]]))"
)
_HEX = re.compile(r"[0-9a-f]+|[0-9A-F]+")
# Files in which a value is written without quotes (KEY=value, key: value).
_BARE_SUFFIXES = (
    ".env",
    ".yml",
    ".yaml",
    ".properties",
    ".ini",
    ".cfg",
    ".conf",
    ".sh",
    ".bash",
    ".zsh",
    ".toml",
)


def secret_name(name: str) -> bool:
    # Numbers are not words: "token_lengths_sha256" ends in "sha", a hash
    # (found on the portfolio: the first version read its last word as
    # "256" and called a SHA-256 of token lengths a secret).
    parts = [p.lower() for p in _PARTS.findall(name) if not p.isdigit()]
    if not parts or parts[-1] in _NOT_THE_SECRET:
        return False
    for i, part in enumerate(parts):
        if part in _SECRET_WORDS:
            return True
        if part == "key" and i > 0 and parts[i - 1] in _KEY_KINDS:
            return True
    return False


def random_enough(value: str) -> bool:
    """Long and varied enough to be a generated secret rather than a word,
    a name or a setting."""
    if not (re.search(r"[A-Za-z]", value) and re.search(r"[0-9]", value)):
        return False
    if _HEX.fullmatch(value):
        return len(value) >= 32 and entropy(value) >= 3.0
    return len(value) >= 16 and entropy(value) >= 3.5


def bare_values_allowed(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return (
        name.startswith(".env")
        or name.endswith(_BARE_SUFFIXES)
        or name.startswith(("dockerfile", "containerfile"))
        or "." not in name
    )


def _assignments(text: str, bare: bool) -> Iterator[Hit]:
    start = 0
    for line in text.splitlines(keepends=True):
        if _KEYWORDS.search(line):
            for m in _ASSIGNMENT.finditer(line):
                value = m.group("quoted") or (m.group("bare") if bare else None)
                if value is None or not secret_name(m.group("name")):
                    continue
                if _PLACEHOLDER.search(value) or not random_enough(value):
                    continue
                at = m.start("quoted") if m.group("quoted") else m.start("bare")
                yield Hit(
                    "secret-assignment",
                    "medium",
                    start + at,
                    start + at + len(value),
                    value,
                    f"{m.group('name')} = … ({len(value)} characters)",
                )
        start += len(line)


# -- all together --------------------------------------------------------------


def find(text: str, path: str, now: datetime | None = None) -> list[Hit]:
    """Every secret in ``text`` (the content of the file at ``path``), in
    order; a value found by a format rule is not found again as a
    high-entropy assignment."""
    hits = [*_known(text), *_private_keys(text), *_jwts(text, now or datetime.now(UTC))]
    taken = [(h.start, h.end) for h in hits]
    for hit in _assignments(text, bare_values_allowed(path)):
        if not any(s < hit.end and hit.start < e for s, e in taken):
            hits.append(hit)
    hits.sort(key=lambda h: (h.start, h.rule))
    return hits
