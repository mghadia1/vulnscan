import base64
import hashlib
import http.server
import json
import threading
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import vulnscan.advisories as advisories
from vulnscan.advisories import DB_NAME, Database, lookup, read_export, update
from vulnscan.advisories.fetch import FetchError, download
from vulnscan.advisories.osv import Advisory, Verdict, parse_advisory


def advisory(
    id_: str, name: str, fixed: str, ecosystem: str = "PyPI", **extra: Any
) -> dict[str, Any]:
    return {
        "id": id_,
        "modified": "2026-01-01T00:00:00Z",
        "summary": f"{id_} summary",
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": name},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
            },
            # Advisories often cover other ecosystems too: not stored here.
            {
                "package": {"ecosystem": "Maven", "name": "org.x:y"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
        ],
        **extra,
    }


def make_zip(path: Path, entries: dict[str, str | bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return path


@pytest.fixture
def export(tmp_path: Path) -> Path:
    return make_zip(
        tmp_path / "PyPI.zip",
        {
            "PYSEC-1.json": json.dumps(advisory("PYSEC-1", "Django", "3.2.19")),
            "PYSEC-2.json": json.dumps(
                advisory("PYSEC-2", "django", "2.0", withdrawn="2026-02-01T00:00:00Z")
            ),
            "BROKEN.json": "{not json",
            "NOTES.txt": "not an advisory",
        },
    )


def test_an_export_is_indexed_and_looked_up(tmp_path: Path, export: Path) -> None:
    snapshot = update(tmp_path / "data", "PyPI", source=export)
    assert (snapshot.advisories, snapshot.withdrawn, snapshot.rejected) == (1, 1, 1)
    assert snapshot.sha256 == hashlib.sha256(export.read_bytes()).hexdigest()
    db = Database(tmp_path / "data" / DB_NAME)
    # OSV writes "Django"; an environment says "django": one package.
    [match] = lookup(db, "PyPI", "DJANGO", "3.2.18")
    assert (match.advisory.id, match.verdict) == ("PYSEC-1", Verdict.AFFECTED)
    assert lookup(db, "PyPI", "django", "3.2.19") == []
    assert list(db.lookup("Maven", "org.x:y")) == []
    db.close()
    assert export.exists()  # a --from file is never deleted


def test_read_only_opening_never_writes(tmp_path: Path, export: Path) -> None:
    data = tmp_path / "data"
    update(data, "PyPI", source=export)
    data.chmod(0o555)
    (data / DB_NAME).chmod(0o444)
    try:
        db = Database(data / DB_NAME, readonly=True)
        assert [m.advisory.id for m in lookup(db, "PyPI", "django", "1.0")] == [
            "PYSEC-1"
        ]
        db.close()
        # No journal or anything else left beside it.
        assert sorted(p.name for p in data.iterdir()) == [DB_NAME]
    finally:
        data.chmod(0o755)


def test_an_update_replaces_all_or_nothing(tmp_path: Path, export: Path) -> None:
    data = tmp_path / "data"
    update(data, "PyPI", source=export)
    db = Database(data / DB_NAME)
    before = db.snapshots()

    def failing() -> Iterator[Advisory | str]:
        parsed = parse_advisory(advisory("PYSEC-9", "flask", "9.9"))
        assert isinstance(parsed, Advisory)
        yield parsed
        raise OSError("the disk filled up")

    with pytest.raises(OSError):
        db.replace("PyPI", failing(), before[0])
    assert db.snapshots() == before
    assert [m.advisory.id for m in lookup(db, "PyPI", "django", "1.0")] == ["PYSEC-1"]
    assert lookup(db, "PyPI", "flask", "1.0") == []
    db.close()


def test_oversized_entries_are_refused_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(advisories, "MAX_ADVISORY_BYTES", 100)
    zf = make_zip(
        tmp_path / "x.zip", {"BIG.json": json.dumps(advisory("BIG", "x", "1" * 200))}
    )
    [result] = list(read_export(zf))
    assert result == "BIG.json: larger than 5 MB"


class Server:
    """A local HTTP server that answers with whatever a test sets."""

    def __init__(self) -> None:
        self.body = b""
        self.headers: dict[str, str] = {}
        self.status = 200
        self.cut_short = False
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(server.status)
                for name, value in server.headers.items():
                    self.send_header(name, value)
                length = len(server.body) + (100 if server.cut_short else 0)
                self.send_header("Content-Length", str(length))
                self.end_headers()
                self.wfile.write(server.body)

            def log_message(self, *args: object) -> None:
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server() -> Iterator[Server]:
    s = Server()
    yield s
    s.close()


def md5_header(body: bytes) -> str:
    return (
        "crc32c=AAAAAA==,md5=" + base64.b64encode(hashlib.md5(body).digest()).decode()
    )


def test_a_download_is_checked_against_the_published_md5(
    server: Server, tmp_path: Path
) -> None:
    server.body = b"the export"
    server.headers = {
        "x-goog-hash": md5_header(server.body),
        "Last-Modified": "Thu, 08 Oct 2026",
    }
    got = download(server.url + "/PyPI/all.zip", tmp_path / "a.zip")
    assert got.md5_checked and got.bytes == 10
    assert got.sha256 == hashlib.sha256(b"the export").hexdigest()
    assert got.last_modified == "Thu, 08 Oct 2026"
    assert (tmp_path / "a.zip").read_bytes() == b"the export"


@pytest.mark.parametrize("fault", ["wrong md5", "cut short", "404"])
def test_a_bad_download_leaves_nothing_behind(
    server: Server, tmp_path: Path, fault: str
) -> None:
    server.body = b"the export"
    server.headers = {
        "x-goog-hash": md5_header(
            b"something else" if fault == "wrong md5" else server.body
        )
    }
    server.cut_short = fault == "cut short"
    server.status = 404 if fault == "404" else 200
    with pytest.raises(FetchError):
        download(server.url + "/x.zip", tmp_path / "a.zip")
    assert list(tmp_path.iterdir()) == []


def test_update_downloads_indexes_and_deletes_the_zip(
    server: Server, tmp_path: Path, export: Path
) -> None:
    server.body = export.read_bytes()
    server.headers = {"x-goog-hash": md5_header(server.body)}
    data = tmp_path / "data"
    snapshot = update(data, "PyPI", url_template=server.url + "/{ecosystem}/all.zip")
    assert snapshot.md5_checked and snapshot.advisories == 1
    assert snapshot.source == server.url + "/PyPI/all.zip"
    assert list((data / "download").iterdir()) == []
