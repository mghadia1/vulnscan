"""Risky settings in Dockerfiles and Compose files.

Each file is read with VulnScan's own parsers (``dockerfile.py``,
``yamlsub.py``). A file that macOS has moved to iCloud (a placeholder) is
not downloaded: its committed version is read from git's HEAD instead, and
the finding says so. A file that cannot be read as written is reported as
not read, with the reason, never guessed at.

Findings say what is wrong in words, never with a value that could be a
secret: "POSTGRES_PASSWORD is the same as POSTGRES_USER", not the password.
"""

import hashlib
import os
import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

from vulnscan.classify import Kind, classify
from vulnscan.containers.dockerfile import (
    Dockerfile,
    DockerfileError,
    assignments,
    parse,
    words,
)
from vulnscan.containers.shell import piped_downloads
from vulnscan.containers.yamlsub import Node, YamlError, load
from vulnscan.findings import Acceptance
from vulnscan.git import GitError, Repository, file_at, on_disk
from vulnscan.secrets.rules import secret_name
from vulnscan.walk import Tree

MAX_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    fix: str


RULES = {
    r.id: r
    for r in (
        Rule(
            "dockerfile/runs-as-root",
            "The image runs as root",
            "add a USER with a non-root user (and create it, if the base "
            "image has none)",
        ),
        Rule(
            "dockerfile/base-image-unpinned",
            "A base image with no tag, or :latest",
            "name a version tag, and ideally its digest (image:tag@sha256:...)",
        ),
        Rule(
            "dockerfile/base-image-no-digest",
            "A base image pinned by tag only",
            "add the digest (image:tag@sha256:...): a tag can be moved to "
            "another image",
        ),
        Rule(
            "dockerfile/add-from-url",
            "ADD downloads a file without checking it",
            "ADD --checksum=sha256:... (BuildKit), or download and check the "
            "hash in a RUN",
        ),
        Rule(
            "dockerfile/pipe-to-shell",
            "A download is run as code without being checked",
            "download to a file, check its hash or signature, then run it",
        ),
        Rule(
            "dockerfile/secret-in-env",
            "A secret's name set with ENV: it is stored in the image",
            "pass it when the container starts (environment, or a secrets "
            "file), not in the image",
        ),
        Rule(
            "dockerfile/secret-in-arg",
            "A secret's name as a build argument: kept in the image's history",
            "RUN --mount=type=secret,id=... (BuildKit secrets)",
        ),
        Rule(
            "dockerfile/no-healthcheck",
            "An image that serves a port has no HEALTHCHECK",
            "add a HEALTHCHECK (or a healthcheck in Compose for this service)",
        ),
        Rule(
            "compose/privileged",
            "A container with the host's privileges",
            "remove privileged: true; add only the capabilities it needs",
        ),
        Rule(
            "compose/host-namespace",
            "A container sharing the host's network, processes or IPC",
            "remove network_mode/pid/ipc: host; publish the ports it needs",
        ),
        Rule(
            "compose/docker-socket",
            "The Docker socket mounted into a container",
            "do not mount the socket; a container that controls Docker "
            "controls the host",
        ),
        Rule(
            "compose/database-port-published",
            "A database published on every network interface",
            'publish on 127.0.0.1 only ("127.0.0.1:5432:5432"), or not at '
            "all: services on the Compose network reach it by name",
        ),
        Rule(
            "compose/default-password",
            "A default or guessable password, or none",
            "set the password from the environment (${DB_PASSWORD}) or a "
            "secrets file, with a strong value",
        ),
    )
}

SEVERITY = {
    "dockerfile/runs-as-root": "medium",
    "dockerfile/base-image-unpinned": "medium",
    "dockerfile/base-image-no-digest": "low",
    "dockerfile/add-from-url": "medium",
    "dockerfile/pipe-to-shell": "medium",
    "dockerfile/secret-in-env": "high",
    "dockerfile/secret-in-arg": "medium",
    "dockerfile/no-healthcheck": "low",
    "compose/privileged": "high",
    "compose/host-namespace": "medium",
    "compose/docker-socket": "high",
    "compose/database-port-published": "medium",
    "compose/default-password": "medium",
}


@dataclass(frozen=True)
class ConfigFinding:
    rule: str
    severity: str
    path: str
    line: int
    subject: str  # what it is about: "stage gatekeeper", "service db"
    message: str  # what is wrong, in words (never a secret's value)
    fingerprint: str
    source: str  # "file", or "HEAD" (the file is not on this disk)
    accepted: Acceptance | None = field(default=None)

    @property
    def title(self) -> str:
        return RULES[self.rule].title

    @property
    def fix(self) -> str:
        return RULES[self.rule].fix


@dataclass(frozen=True)
class FileRead:
    path: str
    kind: str
    source: str | None  # "file", "HEAD", or None if not read
    error: str | None


@dataclass(frozen=True)
class ContainerScan:
    files: tuple[FileRead, ...]
    findings: tuple[ConfigFinding, ...]


def _finding(
    rule: str,
    path: str,
    line: int,
    subject: str,
    message: str,
    source: str,
    severity: str | None = None,
) -> ConfigFinding:
    key = f"{rule}|{path}|{subject}"
    return ConfigFinding(
        rule=rule,
        severity=severity or SEVERITY[rule],
        path=path,
        line=line,
        subject=subject,
        message=message,
        fingerprint=hashlib.sha256(key.encode()).hexdigest()[:16],
        source=source,
    )


# -- images ------------------------------------------------------------------------


@dataclass(frozen=True)
class Image:
    name: str  # registry/repository, without tag or digest
    tag: str | None
    digest: str | None

    @property
    def text(self) -> str:
        out = self.name
        if self.tag:
            out += f":{self.tag}"
        if self.digest:
            out += f"@{self.digest}"
        return out

    @property
    def short(self) -> str:
        """The repository's last part: "postgres" for docker.io/library/postgres."""
        return self.name.rsplit("/", 1)[-1]


def image(ref: str) -> Image:
    name, _, digest = ref.partition("@")
    tag = None
    slash = name.rfind("/")
    colon = name.rfind(":")
    if colon > slash:  # a colon before the last "/" is a registry's port
        name, tag = name[:colon], name[colon + 1 :]
    return Image(name, tag or None, digest or None)


# -- Dockerfiles -------------------------------------------------------------------


@dataclass
class _Stage:
    index: int
    name: str | None
    base: str  # as written, build arguments filled in where known
    base_stage: int | None  # the earlier stage it builds on, if it does
    line: int
    user: tuple[str, int] | None = None  # the last USER, and its line
    healthcheck: str | None = None  # "NONE" or "CMD"
    exposes: list[str] = field(default_factory=list)
    used: bool = False

    @property
    def label(self) -> str:
        return f"stage {self.name}" if self.name else f"stage {self.index}"


_VARIABLE = re.compile(
    r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|([A-Za-z_][A-Za-z0-9_]*))"
)
_ROOT_USERS = frozenset({"root", "0"})


def _substitute(text: str, values: dict[str, str | None]) -> str:
    def one(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(3)
        value = values.get(name)
        if value is not None:
            return value
        if m.group(2) is not None:
            return m.group(2)
        return m.group(0)

    return _VARIABLE.sub(one, text)


def _stage_ref(value: str, stages: list[_Stage]) -> int | None:
    for stage in stages:
        if stage.name is not None and stage.name.lower() == value.lower():
            return stage.index
    if value.isdigit() and int(value) < len(stages):
        return int(value)
    return None


def _nonroot_image(img: Image) -> bool:
    """Images known to set a non-root user: distroless and others' "nonroot"
    tags, and Chainguard's images."""
    return "nonroot" in (img.tag or "") or img.name.startswith("cgr.dev/chainguard/")


def _safe_url(url: str) -> str:
    """A URL to show: without any user name, password or query string."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port:
        host += f":{parts.port}"
    return f"{parts.scheme}://{host}{parts.path}"


def check_dockerfile(
    path: str, dockerfile: Dockerfile, source: str
) -> list[ConfigFinding]:
    found: list[ConfigFinding] = []
    escape = dockerfile.escape
    stages: list[_Stage] = []
    global_args: dict[str, str | None] = {}
    stage_args: dict[str, str | None] = {}

    def add(
        rule: str, line: int, subject: str, message: str, sev: str | None = None
    ) -> None:
        found.append(_finding(rule, path, line, subject, message, source, sev))

    def check_image(ref: str, line: int, where: str) -> None:
        if "$" in ref:
            return  # chosen by a build argument with no default
        if ref.lower() == "scratch":
            return
        img = image(ref)
        if img.digest:
            return
        if img.tag is None or img.tag == "latest":
            add(
                "dockerfile/base-image-unpinned",
                line,
                f"{img.text} ({where})",
                f"{where} uses {img.text}: "
                + ("no tag, so " if img.tag is None else "")
                + "whatever image is newest when it is built",
            )
        else:
            add(
                "dockerfile/base-image-no-digest",
                line,
                f"{img.text} ({where})",
                f"{where} uses {img.text}, a tag that can be moved to a "
                "different image",
            )

    for ins in dockerfile.instructions:
        k = ins.keyword
        if k == "FROM":
            parts = words(ins.rest, escape)
            if not parts:
                continue
            ref = _substitute(parts[0], global_args)
            name = parts[2] if len(parts) >= 3 and parts[1].lower() == "as" else None
            base_stage = _stage_ref(ref, stages)
            stage = _Stage(len(stages), name, ref, base_stage, ins.line)
            if base_stage is not None:
                stages[base_stage].used = True
            stages.append(stage)
            stage_args = {}
            if base_stage is None:
                check_image(ref, ins.line, stage.label)
            continue
        if k == "ARG":
            for name, default in assignments(ins.rest, escape):
                if not stages:
                    global_args[name] = default
                else:
                    stage_args[name] = default
                if secret_name(name):
                    written = default not in (None, "")
                    add(
                        "dockerfile/secret-in-arg",
                        ins.line,
                        f"ARG {name}",
                        f"build argument {name}"
                        + (
                            " has a default written in this file, and"
                            if written
                            else ""
                        )
                        + " is kept in the image's history (docker history) and "
                        "build provenance",
                        "high" if written else None,
                    )
            continue
        if not stages:
            continue
        stage = stages[-1]
        if k == "ENV":
            for name, value in assignments(ins.rest, escape):
                if secret_name(name) and value:
                    from_arg = "$" in value
                    add(
                        "dockerfile/secret-in-env",
                        ins.line,
                        f"ENV {name} ({stage.label})",
                        f"ENV {name} is set "
                        + ("from a build argument " if from_arg else "")
                        + "in the image: anyone with the image can read it "
                        "(docker inspect)",
                    )
        elif k == "USER":
            parts = words(ins.rest, escape)
            if parts:
                stage.user = (parts[0], ins.line)
        elif k == "HEALTHCHECK":
            first = ins.rest.split(None, 1)
            stage.healthcheck = first[0].upper() if first else None
        elif k == "EXPOSE":
            stage.exposes += words(ins.rest, escape)
        elif k in ("COPY", "ADD"):
            source_stage = ins.flag("from")
            if source_stage is not None:
                copied = _stage_ref(source_stage, stages[:-1])
                if copied is not None:
                    stages[copied].used = True
                elif k == "COPY":
                    check_image(source_stage, ins.line, f"COPY --from in {stage.label}")
            if k == "ADD":
                sources = list(ins.exec_form or words(ins.rest, escape))[:-1]
                for src in sources:
                    is_url = src.startswith(("http://", "https://", "git@"))
                    if is_url and ins.flag("checksum") is None:
                        shown = _safe_url(src) if "://" in src else "a git repository"
                        add(
                            "dockerfile/add-from-url",
                            ins.line,
                            f"ADD {shown} ({stage.label})",
                            f"ADD downloads {shown} when the image is built, "
                            "with no checksum to check it against",
                        )
        if k == "RUN":
            for mount in [f for f in ins.flags if f.startswith("--mount=")]:
                for part in mount[len("--mount=") :].split(","):
                    key, _, value = part.partition("=")
                    if key == "from":
                        mounted = _stage_ref(value, stages[:-1])
                        if mounted is not None:
                            stages[mounted].used = True
            scripts = [h[1] for h in ins.heredocs]
            if ins.exec_form is not None:
                scripts.append(" ".join(shlex.quote(a) for a in ins.exec_form))
            elif not ins.heredocs:
                scripts.append(ins.rest)
            seen: set[str] = set()
            for script in scripts:
                for how in piped_downloads(script):
                    if how in seen:
                        continue
                    seen.add(how)
                    add(
                        "dockerfile/pipe-to-shell",
                        ins.line,
                        f"RUN line {ins.line}: {how}",
                        f"RUN runs downloaded code unchecked ({how}): the build "
                        "runs whatever the server sends",
                    )

    # The images this file makes: stages no later stage builds on or copies
    # from (the last stage, and any built with --target).
    for stage in stages:
        if stage.used:
            continue
        user, healthcheck, exposes = _inherited(stage, stages)
        chain_base = _external_base(stage, stages)
        if user is not None:
            name, line = user
            if name.split(":")[0] in _ROOT_USERS:
                add(
                    "dockerfile/runs-as-root",
                    line,
                    stage.label,
                    f"{stage.label} ends with USER {name}",
                )
        elif chain_base is not None and chain_base.lower() == "scratch":
            add(
                "dockerfile/runs-as-root",
                stage.line,
                stage.label,
                f"{stage.label} has no USER, so it runs as root (scratch sets no user)",
            )
        elif chain_base is not None and not _nonroot_image(image(chain_base)):
            add(
                "dockerfile/runs-as-root",
                stage.line,
                stage.label,
                f"{stage.label} has no USER, so it runs as its base image's "
                f"user ({image(chain_base).text}): root, unless that image sets "
                "another",
            )
        if exposes and healthcheck is None:
            add(
                "dockerfile/no-healthcheck",
                stage.line,
                stage.label,
                f"{stage.label} exposes {', '.join(exposes)} but has no "
                "HEALTHCHECK, so Docker cannot tell a hung server from a "
                "working one",
            )
    return found


def _inherited(
    stage: _Stage, stages: list[_Stage]
) -> tuple[tuple[str, int] | None, str | None, list[str]]:
    """A stage's USER, HEALTHCHECK and EXPOSE, its own or from the stages
    it builds on."""
    user, healthcheck, exposes = stage.user, stage.healthcheck, list(stage.exposes)
    seen = {stage.index}
    current = stage
    while current.base_stage is not None and current.base_stage not in seen:
        current = stages[current.base_stage]
        seen.add(current.index)
        user = user or current.user
        healthcheck = healthcheck or current.healthcheck
        exposes = current.exposes + exposes
    if user is not None and "$" in user[0]:
        user = ("$", user[1])  # chosen by a variable: not judged
    return user, healthcheck, exposes


def _external_base(stage: _Stage, stages: list[_Stage]) -> str | None:
    seen = set()
    current = stage
    while current.base_stage is not None and current.base_stage not in seen:
        seen.add(current.base_stage)
        current = stages[current.base_stage]
    return None if "$" in current.base else current.base


# -- Compose -------------------------------------------------------------------------

DATABASES = frozenset(
    {
        "postgres",
        "postgis",
        "pgvector",
        "timescaledb",
        "mysql",
        "mariadb",
        "mongo",
        "mongodb-community-server",
        "redis",
        "redis-stack",
        "redis-stack-server",
        "valkey",
        "memcached",
        "elasticsearch",
        "opensearch",
        "cassandra",
        "couchdb",
        "neo4j",
        "influxdb",
        "clickhouse-server",
        "cockroach",
    }
)
_DEFAULT_PASSWORDS = frozenset(
    {
        "password",
        "passw0rd",
        "postgres",
        "root",
        "admin",
        "secret",
        "changeme",
        "change_me",
        "example",
        "test",
        "mysql",
        "mariadb",
        "redis",
        "mongo",
        "guest",
        "default",
        "pass",
        "123456",
        "12345678",
        "letmein",
        "qwerty",
        "toor",
    }
)
_NO_PASSWORD = {
    "POSTGRES_HOST_AUTH_METHOD": ("trust",),
    "MYSQL_ALLOW_EMPTY_PASSWORD": ("yes", "true", "1"),
    "MARIADB_ALLOW_EMPTY_ROOT_PASSWORD": ("yes", "true", "1"),
    "MARIADB_ALLOW_EMPTY_PASSWORD": ("yes", "true", "1"),
    "ALLOW_EMPTY_PASSWORD": ("yes", "true", "1"),
}
_TRUE = frozenset({"true", "True", "TRUE"})
_INTERPOLATION = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)"
)


def _literal(value: str) -> str | None:
    """What a Compose value is when no variable is set: its text, with
    ``${X:-default}`` as its default; None if it depends on a variable
    with no default."""
    unknown = False

    def one(m: re.Match[str]) -> str:
        nonlocal unknown
        if m.group(2) in (":-", "-"):
            return m.group(3)
        unknown = True
        return ""

    text = _INTERPOLATION.sub(one, value.replace("$$", "\0"))
    return None if unknown else text.replace("\0", "$")


def _environment(service: Node) -> list[tuple[str, str, int]]:
    env = service.get("environment")
    if env is None:
        return []
    out: list[tuple[str, str, int]] = []
    if isinstance(env.value, dict):
        for name, node in env.value.items():
            if node.text:  # an empty value passes the shell's through
                out.append((name, node.text, node.line))
    elif isinstance(env.value, list):
        for item in env.value:
            if item.text and "=" in item.text:
                name, _, value = item.text.partition("=")
                out.append((name, value, item.line))
    return out


def _is_password(name: str) -> bool:
    """A variable that holds a password (not one naming a file that holds
    it, as POSTGRES_PASSWORD_FILE does)."""
    upper = name.upper()
    if upper.endswith(("_FILE", "_PATH", "_HASH")):
        return False
    return "PASSWORD" in upper or "PASSWD" in upper or upper.endswith(("_PWD", "_PASS"))


def _all_interfaces(port: Node) -> tuple[bool, str]:
    """Whether a published port listens on every interface, and its
    container port."""
    if isinstance(port.value, dict):
        host_ip = port.get("host_ip")
        target = port.get("target")
        published = port.get("published")
        target_text = target.text if target else "?"
        if published is None or published.text in ("", None):
            return True, target_text or "?"  # a random host port, everywhere
        ip = host_ip.text if host_ip else ""
        return ip in ("", "0.0.0.0", "::", "[::]"), target_text or "?"
    text = port.text or ""
    text = text.split("/")[0]  # "/tcp"
    if text.startswith("["):  # [::1]:5432:5432
        close = text.find("]")
        ip, rest = text[1:close], text[close + 2 :]
        container = rest.split(":")[-1]
        return ip in ("", "::"), container
    parts = _split_port(text)
    container = parts[-1]
    if len(parts) == 3:
        return parts[0] in ("", "0.0.0.0"), container
    return True, container  # "8080:80" or "80": every interface


def _split_port(text: str) -> list[str]:
    """Split "ip:host:container", leaving ${VAR:-x} in one piece."""
    parts: list[str] = []
    depth = 0
    current = ""
    for c in text:
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        if c == ":" and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += c
    parts.append(current)
    return parts


def check_compose(path: str, root: Node, source: str) -> list[ConfigFinding]:
    found: list[ConfigFinding] = []

    def add(
        rule: str, line: int, subject: str, message: str, sev: str | None = None
    ) -> None:
        found.append(_finding(rule, path, line, subject, message, source, sev))

    services = root.get("services")
    if services is None or not isinstance(services.value, dict):
        return found
    shared: dict[_Weak, list[str]] = {}
    for name, service in services.value.items():
        if not isinstance(service.value, dict):
            continue
        subject = f"service {name}"

        privileged = service.get("privileged")
        if privileged and privileged.text in _TRUE:
            add(
                "compose/privileged",
                privileged.line,
                subject,
                f"{subject} runs privileged: root on the host can be reached from it",
            )
        caps = service.get("cap_add")
        if caps and isinstance(caps.value, list):
            for cap in caps.value:
                c = (cap.text or "").upper().removeprefix("CAP_")
                if c in ("ALL", "SYS_ADMIN"):
                    add(
                        "compose/privileged",
                        cap.line,
                        f"{subject}: cap_add {c}",
                        f"{subject} adds the {c} capability: close to privileged",
                    )
        for key in ("network_mode", "pid", "ipc", "userns_mode", "uts"):
            value = service.get(key)
            if value and value.text == "host":
                add(
                    "compose/host-namespace",
                    value.line,
                    f"{subject}: {key}",
                    f"{subject} shares the host's {key.replace('_mode', '')} "
                    f"({key}: host)",
                )
        volumes = service.get("volumes")
        if volumes and isinstance(volumes.value, list):
            for volume in volumes.value:
                if isinstance(volume.value, dict):
                    src = volume.get("source")
                    source_path = src.text if src else ""
                else:
                    source_path = (volume.text or "").split(":")[0]
                if (source_path or "").rstrip("/").endswith("docker.sock"):
                    add(
                        "compose/docker-socket",
                        volume.line,
                        subject,
                        f"{subject} mounts the Docker socket ({source_path}): "
                        "whoever controls the container controls Docker, and "
                        "so the host (read-only does not help: it is an API)",
                    )
        img_node = service.get("image")
        img_text = _literal(img_node.text) if img_node and img_node.text else None
        img = image(img_text) if img_text else None
        if img is not None and img.short in DATABASES:
            ports = service.get("ports")
            if ports and isinstance(ports.value, list):
                for port in ports.value:
                    everywhere, container = _all_interfaces(port)
                    if everywhere:
                        add(
                            "compose/database-port-published",
                            port.line,
                            f"{subject}: port {container}",
                            f"{subject} ({img.short}) publishes port {container} "
                            "on every network interface: anyone who can reach "
                            "this machine can try to log in (and on Linux, "
                            "Docker's published ports bypass ufw)",
                        )
        for weak in _passwords(name, service, img):
            # One password written once (in a YAML anchor, say) and used by
            # several services is one finding.
            shared.setdefault(weak, []).append(name)
    for weak, names in shared.items():
        who = _who(names)
        found.append(
            _finding(
                "compose/default-password",
                path,
                weak.line,
                f"{who}: {weak.key}",
                weak.message.format(who=who),
                source,
                weak.severity,
            )
        )
    return found


@dataclass(frozen=True)
class _Weak:
    """A weak password, before services sharing it are grouped: the line,
    the variable, the wording ("{who}" stands for the services) and the
    severity."""

    line: int
    key: str
    message: str
    severity: str | None = None


def _passwords(name: str, service: Node, img: Image | None) -> list[_Weak]:
    found: list[_Weak] = []
    env = _environment(service)
    literal = {k: _literal(v) for k, v, _ in env}
    # Values that name an account or a database, by value; a user name is
    # named over a database's (it is the closer comparison).
    accounts: dict[str, str] = {}
    for suffixes in (("_DB", "DATABASE", "DB_NAME"), ("USER", "USERNAME")):
        for k, v in literal.items():
            if v and k.upper().endswith(suffixes):
                accounts[v.lower()] = k

    def weak(value: str) -> str | None:
        """Why a password is weak, in words that do not repeat it."""
        lowered = value.lower()
        if lowered in accounts:
            return f"the same as {accounts[lowered]}"
        if lowered == name.lower():
            return "the service's own name"
        if img is not None and lowered == img.short.lower():
            return "the image's name"
        if lowered in _DEFAULT_PASSWORDS:
            return "a well-known default"
        return None

    for key, _raw, line in env:
        value = literal[key]
        if value is None:
            continue
        upper = key.upper()
        if upper in _NO_PASSWORD and value.lower() in _NO_PASSWORD[upper]:
            found.append(
                _Weak(
                    line,
                    key,
                    f"{{who}} sets {key}: logging in needs no password",
                    "high",
                )
            )
        elif _is_password(key):
            reason = weak(value)
            if reason:
                found.append(_Weak(line, key, f"{key} in {{who}} is {reason}"))
        elif "://" in value and "@" in value:
            try:
                parts = urlsplit(value)
                user, password = parts.username, parts.password
            except ValueError:
                continue
            if password:
                reason = (
                    "the same as its user name"
                    if user and password.lower() == user.lower()
                    else weak(password)
                )
                if reason:
                    found.append(
                        _Weak(line, key, f"the password in {key} ({{who}}) is {reason}")
                    )
    return found


def _who(names: list[str]) -> str:
    if len(names) == 1:
        return f"service {names[0]}"
    return f"services {', '.join(names[:-1])} and {names[-1]}"


# -- reading -------------------------------------------------------------------------


def _owner(path: str, repositories: tuple[str, ...]) -> str | None:
    best: str | None = None
    for repo in repositories:
        inside = repo == "." or path.startswith(repo + "/")
        if inside and (best is None or best == "." or len(repo) > len(best)):
            best = repo
    return best


def _read(
    target: Path, tree: Tree, path: str
) -> tuple[bytes | None, str | None, str | None]:
    """A file's bytes and where they came from ("file" or "HEAD"), or the
    reason it was not read."""
    full = target / path
    try:
        st = os.lstat(full)
    except OSError as error:
        return None, None, str(error.strerror)
    if st.st_size > MAX_BYTES:
        return None, None, f"over {MAX_BYTES // 1024} KB"
    if on_disk(st):
        try:
            return full.read_bytes(), "file", None
        except OSError as error:
            return None, None, str(error.strerror)
    repo_rel = _owner(path, tree.repositories)
    if repo_rel is None:
        return None, None, "not on this disk (iCloud), and not in a git repository"
    inner = path if repo_rel == "." else path[len(repo_rel) + 1 :]
    git_dir = (target if repo_rel == "." else target / repo_rel) / ".git"
    try:
        repo = Repository.open(git_dir)
    except (GitError, OSError) as error:
        return None, None, f"not on this disk, and its repository: {error}"
    try:
        head = repo.head()
        unknown = repo.head_unknown
        data = file_at(repo, head, inner) if head else None
    except GitError as error:
        return None, None, f"not on this disk, and not readable from git: {error}"
    finally:
        repo.close()
    if unknown:
        return None, None, "not on this disk (iCloud), and neither is its HEAD"
    if data is None:
        return None, None, "not on this disk (iCloud), and not committed"
    return data, "HEAD", None


def scan(target: Path, tree: Tree) -> ContainerScan:
    files: list[FileRead] = []
    findings: list[ConfigFinding] = []
    for path in tree.files:
        kind = classify(path)
        if kind not in (Kind.DOCKERFILE, Kind.COMPOSE):
            continue
        data, source, error = _read(target, tree, path)
        if data is None or source is None:
            files.append(FileRead(path, str(kind), None, error))
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            files.append(FileRead(path, str(kind), None, "not UTF-8"))
            continue
        try:
            if kind is Kind.DOCKERFILE:
                findings += check_dockerfile(path, parse(text), source)
            else:
                root = load(text)
                if root is not None:
                    findings += check_compose(path, root, source)
        except (DockerfileError, YamlError) as error:
            files.append(FileRead(path, str(kind), None, f"not read: {error}"))
            continue
        files.append(FileRead(path, str(kind), source, None))
    findings.sort(key=lambda f: (_RANK[f.severity], f.path, f.line, f.rule))
    return ContainerScan(tuple(files), tuple(findings))


_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


# -- acceptances ---------------------------------------------------------------------


@dataclass(frozen=True)
class AppliedConfig:
    findings: tuple[ConfigFinding, ...]
    expired: tuple[tuple[Acceptance, ConfigFinding], ...]
    unused: tuple[Acceptance, ...]


def _matches(acceptance: Acceptance, finding: ConfigFinding) -> bool:
    return acceptance.rule == finding.rule and (
        acceptance.path is None or acceptance.path == finding.path
    )


def apply(
    findings: tuple[ConfigFinding, ...], acceptances: list[Acceptance], today: date
) -> AppliedConfig:
    """Acceptances by rule (``rule = "..."``, optionally with ``path``)."""
    mine = [a for a in acceptances if a.rule is not None]
    used: set[int] = set()
    expired: list[tuple[Acceptance, ConfigFinding]] = []
    result: list[ConfigFinding] = []
    for finding in findings:
        holding = None
        for n, acceptance in enumerate(mine):
            if not _matches(acceptance, finding):
                continue
            used.add(n)
            if acceptance.expires < today:
                expired.append((acceptance, finding))
            elif holding is None:
                holding = acceptance
        result.append(replace(finding, accepted=holding) if holding else finding)
    unused = tuple(a for n, a in enumerate(mine) if n not in used)
    return AppliedConfig(tuple(result), tuple(expired), unused)


def rules() -> Iterator[Rule]:
    yield from RULES.values()
