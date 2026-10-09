from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def no_real_advisory_data(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No test reads the advisory data in ~/.cache: each gets an empty
    data folder unless it builds or names its own."""
    monkeypatch.setenv("VULNSCAN_DATA", str(tmp_path_factory.mktemp("vulnscan-data")))
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)


OSV_DIR = Path(__file__).parent / "data" / "osv"
