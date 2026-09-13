"""Tests for .env fallback."""

from pathlib import Path

from tak_log_analyzer.cli import _load_dotenv, _resolve_config


def test_load_dotenv(tmp_path: Path) -> None:
    p = tmp_path / ".env"
    p.write_text('TAK_LIVE_HOST=host.example.com\n# comment\nTAK_LIVE_CERT="cert.pem"\n')
    vals = _load_dotenv(p)
    assert vals["TAK_LIVE_HOST"] == "host.example.com"
    assert vals["TAK_LIVE_CERT"] == "cert.pem"
    assert _load_dotenv(tmp_path / ".missing") == {}


def test_resolve_config_from_env(monkeypatch, tmp_path: Path) -> None:
    # ensure clean env
    monkeypatch.delenv("TAK_LIVE_HOST", raising=False)
    monkeypatch.delenv("TAK_LIVE_CERT", raising=False)
    monkeypatch.delenv("TAK_LIVE_KEY", raising=False)
    # create .env in tmp and chdir
    env = tmp_path / ".env"
    env.write_text("TAK_LIVE_HOST=h\nTAK_LIVE_CERT=c\nTAK_LIVE_KEY=k\n")
    monkeypatch.chdir(tmp_path)
    host, cert, key, ca = _resolve_config(None, None, None, None)
    assert host == "h"
    assert cert == "c"
    assert key == "k"
    assert ca is None


def test_resolve_config_explicit_wins(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TAK_LIVE_HOST", "envhost")
    host, cert, key, ca = _resolve_config("explicit", "c", "k", None)
    assert host == "explicit"
