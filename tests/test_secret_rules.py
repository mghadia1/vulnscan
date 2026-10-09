"""The secret rules on generated fakes: each format found where it is
written, in the forms files hold it; never found inside a longer run of
token characters, as a placeholder, or as a value something else names;
and never shown."""

import json
import random
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscan.secrets.rules import (
    RULES,
    entropy,
    find,
    fingerprint,
    random_enough,
    secret_name,
)

from helpers import (
    BASE64,
    FAKES,
    FIXED,
    body,
    jwt,
    leaks,
    pem,
    private_key_body,
)

NOW = datetime(2026, 10, 8, tzinfo=UTC)


def _rules(text: str, path: str = "config.py") -> list[str]:
    return [h.rule for h in find(text, path, NOW)]


def test_every_format_rule_has_a_fake() -> None:
    assert set(FAKES) == {r.id for r in RULES}


@pytest.mark.parametrize("rule", sorted(FAKES))
@pytest.mark.parametrize(
    "template",
    [
        "{t}",
        'TOKEN = "{t}"\n',
        "TOKEN={t}\n",  # an .env line: "=" right before the token
        "token: {t}\n",
        '{{"token": "{t}"}}',
        "curl -H 'Authorization: Bearer {t}' https://example.invalid\n",
        '    "key = \\"{t}\\"\\n",\n',  # a notebook's source line
    ],
)
def test_each_format_is_found_where_it_is_written(rule: str, template: str) -> None:
    rng = random.Random(f"{rule}{template}")
    token = FAKES[rule](rng)
    text = template.format(t=token)
    hits = [h for h in find(text, ".env", NOW) if h.rule == rule]
    assert len(hits) == 1, (rule, template)
    hit = hits[0]
    assert text[hit.start : hit.end] == token
    assert hit.value == token
    # Shown: the format's fixed prefix at most, and the length.
    assert hit.shown == f"{token[: FIXED[rule]]}… ({len(token)} characters)"
    assert not leaks(token, hit.shown, FIXED[rule], window=4)


@pytest.mark.parametrize("rule", sorted(FAKES))
def test_never_part_of_a_longer_token(rule: str) -> None:
    """A match never starts or stops inside a longer run of token
    characters: the token itself is not found inside one (a format with a
    variable length may match the whole run instead)."""
    rng = random.Random(rule)
    token = FAKES[rule](rng)
    for text in (f"x{token}", f"{token}x", f"/{token}", f"{token}/a", f"+{token}"):
        for hit in find(text, "a.txt", NOW):
            assert hit.value != token, text
            assert hit.start == 0 or text[hit.start - 1] not in "+/x", text
            assert hit.end == len(text) or text[hit.end] not in "/x", text


@pytest.mark.parametrize("rule", sorted(FAKES))
def test_placeholders_are_not_secrets(rule: str) -> None:
    token = FAKES[rule](random.Random(rule))
    # Same length and prefix, but saying what it is.
    for word in ("EXAMPLE", "example", "XXXXXXXX", "your_", "placeholder"):
        fixed = FIXED[rule]
        fake = token[:fixed] + word + token[fixed + len(word) :]
        assert rule not in _rules(fake), fake


def test_documented_example_keys_are_not_findings() -> None:
    # AWS's own documentation key id: ends in EXAMPLE.
    assert _rules("aws_access_key_id = " + "AKIA" + "IOSFODNN7" + "EXAMPLE") == []


def test_publishable_keys_and_hashes_are_not_secrets() -> None:
    rng = random.Random(1)
    texts = [
        "pk" + "_live_" + body(rng, 24),  # Stripe's publishable key: public
        '"integrity": "sha512-' + body(rng, 86, BASE64) + '=="',
        "sha256:" + body(rng, 64, "0123456789abcdef"),
        "commit " + body(rng, 40, "0123456789abcdef"),
        "data:image/png;base64," + body(rng, 400, BASE64),
    ]
    for text in texts:
        assert _rules(text) == [], text


# -- JWTs ----------------------------------------------------------------------


def test_jwts() -> None:
    rng = random.Random(2)
    live = jwt(rng, exp=int(NOW.timestamp()) + 3600)
    old = jwt(rng, exp=int(NOW.timestamp()) - 3600)
    forever = jwt(rng)
    found = {h.value: h for h in find(f"{live}\n{old}\n{forever}\n", "a.txt", NOW)}
    assert (found[live].severity, found[live].note) == ("medium", "expires 2026-10-08")
    assert (found[old].severity, found[old].note) == ("low", "expired 2026-10-07")
    assert (found[forever].severity, found[forever].note) == ("medium", "no expiry")
    assert found[live].shown == f"eyJ… ({len(live)} characters)"


def test_not_jwts() -> None:
    rng = random.Random(3)
    unsigned = jwt(rng, alg="none")
    # Three base64 parts that do not decode to a header with "alg".
    not_a_header = "eyJ" + body(rng, 20) + ".eyJ" + body(rng, 20) + "." + body(rng, 30)
    assert _rules(unsigned) == []
    assert _rules(not_a_header) == []


# -- private keys --------------------------------------------------------------


def test_private_key_blocks() -> None:
    rng = random.Random(4)
    key = pem("RSA", private_key_body(rng))
    hits = find(f"some text\n{key}more text", "id_rsa", NOW)
    assert [(h.rule, h.severity) for h in hits] == [("private-key", "high")]
    assert hits[0].shown.startswith("BEGIN RSA PRIVATE KEY… (")
    # The block's lines, joined with "\n" escapes in a JSON string.
    as_json = json.dumps({"key": key})
    assert [h.rule for h in find(as_json, "creds.json", NOW)] == ["private-key"]
    # In a notebook: one quoted line per line of the key.
    cell = json.dumps({"source": key.splitlines(keepends=True)}, indent=1)
    assert [h.rule for h in find(cell, "n.ipynb", NOW)] == ["private-key"]


def test_encrypted_private_keys_rank_lower() -> None:
    rng = random.Random(5)
    pkcs8 = pem("ENCRYPTED", private_key_body(rng))
    legacy = pem(
        "RSA",
        private_key_body(rng),
        headers="Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00FF\n\n",
    )
    for text in (pkcs8, legacy):
        [hit] = find(text, "k.pem", NOW)
        assert (hit.severity, hit.note) == ("medium", "encrypted with a passphrase")


def test_not_private_keys() -> None:
    rng = random.Random(6)
    texts = [
        "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----",
        "Paste a key like -----BEGIN PRIVATE KEY----- here.",  # no END
        pem("", "ABCD" * 10),  # too short to be a key
        pem("", private_key_body(rng)).replace("PRIVATE", "PUBLIC"),
        "-----BEGIN CERTIFICATE-----\n"
        + private_key_body(rng)
        + "\n-----END CERTIFICATE-----",
    ]
    for text in texts:
        assert _rules(text, "k.pem") == [], text


def _tool_key(tmp_path: Path, args: list[str], name: str) -> str:
    subprocess.run(args, cwd=tmp_path, capture_output=True, check=True)
    return (tmp_path / name).read_text()


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="no ssh-keygen")
def test_keys_made_by_ssh_keygen(tmp_path: Path) -> None:
    """Real key files, made for the test and never written to the repo:
    OpenSSH keys, unencrypted and with a passphrase (read from the key's
    own header)."""
    plain = _tool_key(
        tmp_path, ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "a"], "a"
    )
    locked = _tool_key(
        tmp_path,
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "a passphrase", "-f", "b"],
        "b",
    )
    [hit] = find(plain, "a", NOW)
    assert (hit.rule, hit.severity, hit.note) == ("private-key", "high", None)
    [hit] = find(locked, "b", NOW)
    assert (hit.severity, hit.note) == ("medium", "encrypted with a passphrase")


@pytest.mark.skipif(shutil.which("openssl") is None, reason="no openssl")
def test_keys_made_by_openssl(tmp_path: Path) -> None:
    plain = _tool_key(
        tmp_path,
        ["openssl", "genpkey", "-algorithm", "RSA", "-out", "a.pem"],
        "a.pem",
    )
    locked = _tool_key(
        tmp_path,
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-aes-128-cbc",
            "-pass",
            "pass:a passphrase",
            "-out",
            "b.pem",
        ],
        "b.pem",
    )
    [hit] = find(plain, "a.pem", NOW)
    assert (hit.rule, hit.severity) == ("private-key", "high")
    [hit] = find(locked, "b.pem", NOW)
    assert (hit.severity, hit.note) == ("medium", "encrypted with a passphrase")


# -- high-entropy assignments ----------------------------------------------------


def _value(rng: random.Random, n: int = 32) -> str:
    while True:
        value = body(rng, n)
        if random_enough(value):
            return value


@pytest.mark.parametrize(
    ("path", "line"),
    [
        ("app.py", 'DB_PASSWORD = "{v}"'),
        ("app.py", "client_secret='{v}'"),
        ("settings.py", 'SECRET_KEY = "{v}"'),
        ("server.js", "const apiKey = `{v}`;"),
        ("server.ts", "  authToken: '{v}',"),
        ("main.go", 'var accessKey = "{v}"'),
        ("App.java", 'private static final String API_KEY = "{v}";'),
        ("config.json", '{{"jwt_secret": "{v}"}}'),
        ("deploy.yml", "  password: {v}"),
        (".env", "STRIPE_SECRET={v}"),
        (".env.local", "export SIGNING_KEY={v}"),
        ("app.properties", "spring.datasource.password={v}"),
        ("n.ipynb", '    "hf_token = \\"{v}\\"\\n",'),
        ("Dockerfile", "ENV REGISTRY_TOKEN={v}"),
    ],
)
def test_secret_assignments(path: str, line: str) -> None:
    rng = random.Random(path + line)
    value = _value(rng)
    text = line.format(v=value) + "\n"
    hits = find(text, path, NOW)
    assert [(h.rule, h.value) for h in hits] == [("secret-assignment", value)]
    assert value not in hits[0].shown
    assert hits[0].shown.endswith(f"… ({len(value)} characters)")


@pytest.mark.parametrize(
    ("path", "line"),
    [
        # Not a secret's name.
        ("app.py", 'tokenizer = "{v}"'),
        ("app.py", 'max_tokens = "{v}"'),
        ("app.py", 'author = "{v}"'),
        ("app.py", 'monkey = "{v}"'),
        ("app.py", 'cache_key = "{v}"'),
        # A name about a secret, not the secret.
        ("app.py", 'token_url = "{v}"'),
        ("app.py", 'password_file = "{v}"'),
        ("app.py", 'secret_name = "{v}"'),
        ("app.py", 'api_key_header = "{v}"'),
        ("app.py", 'token_lengths_sha256 = "{v}"'),
        ("app.py", 'TOKEN_ID = "{v}"'),
        # A bare value in code is a name, not a literal.
        ("app.py", "password = {v}"),
        ("app.js", "token = {v}"),
    ],
)
def test_not_secret_assignments(path: str, line: str) -> None:
    rng = random.Random(path + line)
    assert _rules(line.format(v=_value(rng)) + "\n", path) == []


@pytest.mark.parametrize(
    "value",
    [
        "changeme-please-1",  # a placeholder
        "your_api_key_here_123",
        "${DB_PASSWORD}",  # a reference to the environment
        "os.environ['PASSWORD']",
        "aaaaaaaaaaaaaaaaaaaa1",  # long, but not varied
        "xyz789xyz789xyz789",  # six characters repeated: 2.6 bits each
        "correcthorsebatterystaple",  # no digits: a word or a name
        "0123456789",  # too short
        "deadbeef" * 3,  # hex, too short to be a hex secret
    ],
)
def test_values_that_are_not_secrets(value: str) -> None:
    for text in (f'password = "{value}"\n', f"PASSWORD={value}\n"):
        assert _rules(text, ".env") == [], text


def test_a_format_match_is_not_found_twice() -> None:
    token = FAKES["github-token"](random.Random(7))
    assert _rules(f'GITHUB_TOKEN = "{token}"\n') == ["github-token"]


def test_secret_names() -> None:
    for name in (
        "password",
        "DB_PASSWORD",
        "dbPassword",
        "client_secret",
        "clientSecret",
        "API_KEY",
        "apiKey",
        "apikey",
        "x-api-key",
        "spring.datasource.password",
        "AWS_SECRET_ACCESS_KEY",
        "private_key",
        "github_token",
        "PASSWORD2",
    ):
        assert secret_name(name), name
    for name in (
        "key",
        "keys",
        "tokenizer",
        "max_tokens",
        "token_count",
        "password_hash",
        "secret_path",
        "sort_key",
        "primary_key",
        "token_lengths_sha256",
        "passwordless",
    ):
        assert not secret_name(name), name


def test_entropy() -> None:
    assert entropy("aaaa") == 0
    assert entropy("abab") == 1
    assert entropy("abcd") == 2
    assert abs(entropy("0123456789abcdef") - 4) < 1e-9


def test_fingerprints() -> None:
    a, b = fingerprint("one value"), fingerprint("another value")
    assert len(a) == 16 and int(a, 16) >= 0
    assert a == fingerprint("one value") and a != b


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=500))
def test_any_text_is_read_without_error(text: str) -> None:
    for hit in find(text, "any.env", NOW):
        assert text[hit.start : hit.end] or hit.rule == "private-key"


@settings(max_examples=200, deadline=None)
@given(
    rule=st.sampled_from(sorted(FAKES)),
    seed=st.integers(),
    before=st.text(alphabet=" \n\t\"'=:,;({[<", max_size=5),
    after=st.text(alphabet=" \n\t\"',;)}]>#", max_size=5),
    filler=st.text(max_size=200),
)
def test_planted_tokens_are_found_in_any_surroundings(
    rule: str, seed: int, before: str, after: str, filler: str
) -> None:
    """A token between separators, anywhere in arbitrary text, is found,
    exactly where it is."""
    token = FAKES[rule](random.Random(seed))
    text = f"{filler}\n{before}{token}{after}\n{filler}"
    spans = [(h.start, h.end) for h in find(text, "x.txt", NOW) if h.rule == rule]
    start = text.index(token, len(filler))
    assert (start, start + len(token)) in spans
