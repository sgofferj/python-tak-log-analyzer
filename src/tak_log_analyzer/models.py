"""Data models for parsed logs and analytics report."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParsedLog:
    """Normalized crash log from TAK Server ErrorLog.

    Combines listing metadata (LogManager.jsp table) with ACRA JSON fields.
    Missing optional fields are ``None`` - parsers are tolerant to partial
    / future log formats.
    """

    # listing metadata (from LogManager.jsp or filename)
    id: int | str | None = None
    time: str | None = None
    uid: str = ""
    callsign: str | None = None
    platform: str | None = None
    major_version: str | None = None
    minor_version: str | None = None
    filename: str | None = None

    # header / report extracted
    timestamp: str | None = None
    device_model: str | None = None
    device_manufacturer: str | None = None
    os_version: str | None = None
    android_release: str | None = None
    android_sdk: str | None = None
    tak_brand: str | None = None
    tak_version: str | None = None
    tak_revision: str | None = None
    tak_error: str | None = None
    tak_stack_hash: str | None = None

    # stack
    stack_trace: str | None = None
    stack_hash: str | None = None
    exception_type: str | None = None
    exception_message: str | None = None
    top_frame: str | None = None

    # plugins
    plugins: list[dict[str, str]] = field(default_factory=list)
    plugin_names: list[str] = field(default_factory=list)

    # logcat
    logcat: str | None = None
    logcat_lines: list[str] = field(default_factory=list)

    # optional metric flag
    is_metric: bool = False

    # raw envelope for escape-hatch
    raw: dict[str, object] = field(default_factory=dict)


@dataclass
class DeviceStats:
    """Per-device aggregate."""

    uid: str
    callsign: str | None
    platform: str | None
    model: str | None
    manufacturer: str | None
    android_release: str | None
    crash_count: int
    first_seen: str | None
    last_seen: str | None
    filenames: list[str] = field(default_factory=list)
    dominant_error: str | None = None
    dominant_stack_hash: str | None = None
    tak_versions: list[str] = field(default_factory=list)
    plugins: list[str] = field(default_factory=list)


@dataclass
class ErrorGroup:
    """Grouped by stack hash / exception."""

    stack_hash: str | None
    exception: str | None
    exception_message: str | None
    top_frame: str | None
    count: int
    affected_devices: list[str] = field(default_factory=list)
    affected_callsigns: list[str] = field(default_factory=list)
    tak_versions: list[str] = field(default_factory=list)
    device_models: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    example_log_id: int | str | None = None
    heuristic: str | None = None
    sample_filenames: list[str] = field(default_factory=list)


@dataclass
class PluginStats:
    """Per-plugin aggregate."""

    name: str
    count: int
    versions: list[str] = field(default_factory=list)
    stack_hashes: list[str] = field(default_factory=list)
    device_uids: list[str] = field(default_factory=list)


@dataclass
class Summary:
    """Overall summary."""

    total: int
    unique_devices: int
    unique_callsigns: int
    unique_stack_hashes: int
    unique_tak_versions: int
    unique_device_models: int
    date_range: tuple[str | None, str | None] = (None, None)
    metric_logs: int = 0
    error_logs: int = 0


@dataclass
class Report:
    """Full analytics report returned by ``analyze()``."""

    summary: Summary
    devices: list[DeviceStats] = field(default_factory=list)
    errors: list[ErrorGroup] = field(default_factory=list)
    plugins: list[PluginStats] = field(default_factory=list)
    per_day: dict[str, int] = field(default_factory=dict)
    per_hour: dict[str, int] = field(default_factory=dict)
