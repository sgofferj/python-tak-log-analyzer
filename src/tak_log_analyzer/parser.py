"""Parse TAK ACRA crash JSONs (and fallback) into ``ParsedLog``."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import ParsedLog

_STACK_FRAME_RE = re.compile(r"at\s+([^\s\(]+)")
_EXCEPTION_RE = re.compile(r"^([\w.$]+)(?::\s*(.*))?")


def _first_line(text: str | None) -> str | None:
    if not text:
        return None
    return text.splitlines()[0].strip() or None


def _exception_parts(error: str | None) -> tuple[str | None, str | None]:
    if not error:
        return None, None
    m = _EXCEPTION_RE.match(error.strip())
    if not m:
        return error.strip(), None
    return m.group(1), m.group(2)


def _top_frame(stack: str | None) -> str | None:
    if not stack:
        return None
    for line in stack.splitlines():
        m = _STACK_FRAME_RE.search(line)
        if m:
            return m.group(1)
    return None


def _extract_logcat_lines(logcat: str | None, limit: int = 20) -> list[str]:
    if not logcat:
        return []
    lines = [line for line in logcat.splitlines() if line.strip()]
    # keep last N lines plus any FATAL/ E/ lines
    tail = lines[-limit:]
    # also surface the crash line if not in tail
    fatals = [line for line in lines if "FATAL EXCEPTION" in line or " E/" in line or "E/" in line]
    # dedup preserving order: tail + fatals not already in tail
    seen = set(tail)
    for fl in fatals:
        if fl not in seen:
            tail.append(fl)
    return tail[-limit:]


def parse_bytes(
    data: bytes,
    meta: dict[str, Any] | None = None,
) -> ParsedLog:
    """Parse raw ACRA JSON bytes (and optional listing meta) into ``ParsedLog``.

    ``meta`` may contain ``id, time, uid, callsign, platform,
    major_version, minor_version, filename`` from ``LogManager.jsp``.
    The JSON body itself often duplicates these via ``header``.
    """
    meta = meta or {}
    # decode
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = str(data)
    # try json, fallback to raw text as stack
    raw: dict[str, Any] = {}
    try:
        raw = json.loads(text)
        if not isinstance(raw, dict):
            raw = {"raw": text}
    except json.JSONDecodeError:
        raw = {"raw": text, "LOGCAT": text}

    header: dict[str, Any] = raw.get("header", {}) if isinstance(raw.get("header"), dict) else {}
    report: dict[str, Any] = raw.get("report", {}) if isinstance(raw.get("report"), dict) else {}
    gpu: dict[str, Any] = raw.get("gpu", {}) if isinstance(raw.get("gpu"), dict) else {}

    # uid precedence: meta uid > header TAK.uid > report fallback
    uid = str(meta.get("uid") or header.get("TAK.uid") or report.get("uid") or "")

    # callsign - also in report SHARED_PREFERENCES.default.locationCallsign
    callsign = (
        meta.get("callsign")
        or header.get("TAK.callsign")
        or report.get("callsign")
        or (
            report.get("SHARED_PREFERENCES", {}).get("default", {}).get("locationCallsign")
            if isinstance(report.get("SHARED_PREFERENCES"), dict)
            else None
        )
    )
    # fallback: search for bestDeviceUID related? not needed
    if isinstance(callsign, str):
        callsign = callsign.strip() or None

    # platform
    platform = meta.get("platform") or header.get("TAK.platform") or header.get("platform")

    # versions
    major_version = meta.get("major_version") or header.get("TAK.version") or header.get("majorVersion")
    minor_version = meta.get("minor_version") or header.get("TAK.revision") or header.get("minorVersion")

    # filename
    filename = meta.get("filename") or header.get("TAK.filename") or raw.get("filename")

    # is_metric heuristic
    is_metric = bool(filename and str(filename).lower().startswith("metric"))

    # device
    device_model = header.get("device.model") or report.get("PHONE_MODEL") or gpu.get("device_model")
    device_manufacturer = header.get("device.manufacturer") or report.get("BRAND") or report.get("MANUFACTURER")

    # timestamps: header timestamp > USER_CRASH_DATE > meta time
    timestamp = header.get("timestamp") or report.get("USER_CRASH_DATE") or report.get("timestamp") or meta.get("time")

    # TAK fields
    tak_error = (
        header.get("TAK.error") or report.get("STACK_TRACE", "").splitlines()[0]
        if report.get("STACK_TRACE")
        else header.get("TAK.error")
    )
    tak_stack_hash = header.get("TAK.stackHash") or report.get("STACK_TRACE_HASH") or report.get("STACK_TRACE_HASH")
    tak_version = header.get("TAK.version") or report.get("APP_VERSION_NAME")
    tak_brand = header.get("TAK.brand")
    tak_revision = header.get("TAK.revision")
    os_version = header.get("os.version")
    android_release = header.get("android.release") or str(report.get("ANDROID_VERSION", "")) or None
    android_sdk = header.get("android.sdk")

    # plugins
    plugins: list[dict[str, str]] = []
    raw_plugins = header.get("plugins") or []
    if isinstance(raw_plugins, list):
        for p in raw_plugins:
            if isinstance(p, dict) and "plugin" in p:
                plugins.append({"name": str(p.get("plugin", "")), "version": str(p.get("version", ""))})
    plugin_names = [p["name"] for p in plugins]

    # stack
    stack_trace: str | None = report.get("STACK_TRACE") if isinstance(report.get("STACK_TRACE"), str) else None
    if not stack_trace:
        stack_trace = tak_error
    stack_hash: str | None = report.get("STACK_TRACE_HASH") or tak_stack_hash
    if isinstance(stack_hash, str):
        stack_hash = stack_hash.strip() or None

    # exception parts from tak_error or first line of stack
    exc_source = tak_error or _first_line(stack_trace)
    exc_type, exc_msg = _exception_parts(exc_source)

    top_frame = _top_frame(stack_trace)

    # logcat
    logcat: str | None = report.get("LOGCAT") if isinstance(report.get("LOGCAT"), str) else None
    if logcat is None and "LOGCAT" in raw and isinstance(raw["LOGCAT"], str):
        logcat = raw["LOGCAT"]
    logcat_lines = _extract_logcat_lines(logcat)

    # normalize uid fallback to filename hash when missing
    if not uid and filename:
        uid = str(filename)

    return ParsedLog(
        id=meta.get("id"),
        time=meta.get("time") or timestamp,
        uid=uid,
        callsign=str(callsign) if callsign else None,
        platform=str(platform) if platform else None,
        major_version=str(major_version) if major_version else None,
        minor_version=str(minor_version) if minor_version else None,
        filename=str(filename) if filename else None,
        timestamp=str(timestamp) if timestamp else None,
        device_model=str(device_model) if device_model else None,
        device_manufacturer=str(device_manufacturer) if device_manufacturer else None,
        os_version=str(os_version) if os_version else None,
        android_release=str(android_release) if android_release else None,
        android_sdk=str(android_sdk) if android_sdk else None,
        tak_brand=str(tak_brand) if tak_brand else None,
        tak_version=str(tak_version) if tak_version else None,
        tak_revision=str(tak_revision) if tak_revision else None,
        tak_error=str(tak_error) if tak_error else None,
        tak_stack_hash=str(tak_stack_hash) if tak_stack_hash else None,
        stack_trace=stack_trace,
        stack_hash=stack_hash,
        exception_type=exc_type,
        exception_message=exc_msg,
        top_frame=top_frame,
        plugins=plugins,
        plugin_names=plugin_names,
        logcat=logcat,
        logcat_lines=logcat_lines,
        is_metric=is_metric,
        raw=raw,
    )


def parse_file(path: Path | str, meta: dict[str, Any] | None = None) -> ParsedLog:
    """Parse a crash file on disk."""
    p = Path(path)
    data = p.read_bytes()
    # inject filename if not in meta
    m = dict(meta or {})
    if "filename" not in m:
        m["filename"] = p.name
    return parse_bytes(data, meta=m)


def parse_many(paths: list[Path | str], metas: list[dict[str, Any]] | None = None) -> list[ParsedLog]:
    """Parse many files; ``metas`` parallel to ``paths`` for listing meta."""
    out: list[ParsedLog] = []
    for i, p in enumerate(paths):
        meta = metas[i] if metas and i < len(metas) else None
        out.append(parse_file(p, meta=meta))
    return out
