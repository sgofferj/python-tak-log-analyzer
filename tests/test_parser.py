"""Tests for ACRA parser."""

from pathlib import Path

from tak_log_analyzer.parser import parse_bytes, parse_file


DATA = Path(__file__).parent / "data" / "example_crash.json"


def test_parse_file_example() -> None:
    log = parse_file(DATA)
    assert log.uid == "ANDROID-EXAMPLE-UID-001"
    assert log.callsign == "EXAMPLE-CALLSIGN"
    # platform is only in LogManager listing meta, not in ACRA JSON itself
    assert log.platform is None
    assert log.device_model == "Tab8"
    assert log.device_manufacturer == "Blackview"
    assert log.android_release == "10"
    assert log.tak_version == "5.6.0.15 (3d3d96d1)[playstore]"
    assert log.tak_error is not None
    assert "NullPointerException" in log.tak_error
    assert log.stack_hash == "6d8a2026"
    assert log.exception_type == "java.lang.NullPointerException"
    assert log.top_frame == "com.atakmap.android.update.g.a"
    assert len(log.plugin_names) == 2
    assert "plugin.version.loaded.VNS" in log.plugin_names
    assert log.logcat is not None
    assert "FATAL EXCEPTION" in log.logcat

    # with listing meta, platform is injected
    log2 = parse_bytes(DATA.read_bytes(), meta={"platform": "ATAK", "callsign": "EXAMPLE-CALLSIGN"})
    assert log2.platform == "ATAK"


def test_parse_bytes_with_meta() -> None:
    data = DATA.read_bytes()
    meta = {"id": 42, "time": "2026-03-25T18:37:44.889", "uid": "OVERRIDE-UID", "filename": "test.json"}
    log = parse_bytes(data, meta=meta)
    assert log.id == 42
    assert log.uid == "OVERRIDE-UID"
    assert log.filename == "test.json"


def test_parse_invalid_json_fallback() -> None:
    log = parse_bytes(b"not json at all")
    assert log.raw == {"raw": "not json at all", "LOGCAT": "not json at all"}
    assert log.uid == "" or log.filename is None
