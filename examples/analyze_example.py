"""Example: analyze local crash logs and print report."""

from pathlib import Path
from tak_log_analyzer.parser import parse_file
from tak_log_analyzer.analyzer import analyze

# assumes tak-logs/ contains downloaded *.json
log_dir = Path("tests/data")
logs = [parse_file(p) for p in log_dir.glob("*.json")]
report = analyze(logs)
print(f"Total {report.summary.total} logs")
for dev in report.devices[:5]:
    print(f"{dev.uid} {dev.callsign} {dev.model} count={dev.crash_count}")
for err in report.errors[:5]:
    print(f"{err.stack_hash} {err.exception} x{err.count} heuristic={err.heuristic}")
