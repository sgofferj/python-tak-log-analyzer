"""Live-test fixtures: real TAK server, local machine only."""

import os
from pathlib import Path

import pytest
import pytest_asyncio

from python_takserver_api import Server

REPO_ROOT = Path(__file__).resolve().parents[1]
DOTENV = REPO_ROOT / ".env"


def _load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _get(key: str, dotenv: dict[str, str]) -> str | None:
    return os.environ.get(key) or dotenv.get(key)


@pytest_asyncio.fixture
async def server() -> Server:  # type: ignore[no-any-unimported]
    dotenv = _load_dotenv(DOTENV)
    host = _get("TAK_LIVE_HOST", dotenv)
    cert = _get("TAK_LIVE_CERT", dotenv)
    key = _get("TAK_LIVE_KEY", dotenv)
    if not host or not cert or not key or not Path(cert).exists() or not Path(key).exists():
        pytest.skip("live server not configured: set TAK_LIVE_HOST/TAK_LIVE_CERT/TAK_LIVE_KEY in .env")
    srv = Server(host, cert, key)  # type: ignore[arg-type]
    yield srv  # type: ignore[misc]
    await srv.close()


@pytest.fixture
def live_host() -> str:
    dotenv = _load_dotenv(DOTENV)
    host = _get("TAK_LIVE_HOST", dotenv)
    if not host:
        pytest.skip("live server not configured")
    return host
