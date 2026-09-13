"""Version smoke test."""

from tak_log_analyzer import __version__

def test_version() -> None:
    assert __version__ == "0.1.0"
