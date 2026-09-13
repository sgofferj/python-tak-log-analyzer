"""Tests for analytics."""

from pathlib import Path

from tak_log_analyzer.analyzer import analyze, to_dict
from tak_log_analyzer.parser import parse_file

DATA = Path(__file__).parent / "data" / "example_crash.json"


def test_analyze_single() -> None:
    log = parse_file(DATA)
    report = analyze([log])
    assert report.summary.total == 1
    assert report.summary.unique_devices == 1
    assert report.summary.unique_stack_hashes == 1
    assert len(report.devices) == 1
    assert report.devices[0].crash_count == 1
    assert report.devices[0].uid == log.uid
    assert len(report.errors) == 1
    assert report.errors[0].count == 1
    assert report.errors[0].stack_hash == "6d8a2026"
    assert len(report.plugins) == 2
    d = to_dict(report)
    assert d["summary"]["total"] == 1


def test_analyze_multiple_grouping() -> None:
    log1 = parse_file(DATA)
    # second log same stack hash but different uid
    log2 = parse_file(DATA)
    log2.uid = "ANDROID-other"
    log2.callsign = "Other"
    log3 = parse_file(DATA)
    log3.stack_hash = "deadbeef"
    log3.tak_stack_hash = "deadbeef"
    log3.tak_error = "java.lang.IllegalStateException: other"
    log3.exception_type = "java.lang.IllegalStateException"

    report = analyze([log1, log2, log3])
    assert report.summary.total == 3
    assert report.summary.unique_devices == 2  # ANDROID-... and ANDROID-other (log3 shares uid with log1)
    # actually log1 and log3 share uid, log2 different -> 2 unique
    assert len(report.errors) == 2
    # most frequent is 6d8a2026 with 2
    assert report.errors[0].count == 2
    assert report.errors[0].stack_hash == "6d8a2026"
    assert len(report.errors[0].affected_devices) == 2


def test_analyze_empty() -> None:
    report = analyze([])
    assert report.summary.total == 0
    assert report.devices == []
    assert report.errors == []
