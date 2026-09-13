"""Analytics over parsed TAK crash logs."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from .models import DeviceStats, ErrorGroup, ParsedLog, PluginStats, Report, Summary

_DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")
_TIME_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2})")


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    # try isoformat with Z
    try:
        v = value.strip().replace("Z", "+00:00")
        # strip millis variant like 2026-03-25T18:37:44.889 -> handled by fromisoformat
        return datetime.fromisoformat(v)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    # try date only
    try:
        return datetime.strptime(value.strip()[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def _heuristic_for_error(group: ErrorGroup, total: int, logs: list[ParsedLog]) -> str | None:
    """Simple why-heuristic: plugin/version/device correlation."""
    if group.count == 0:
        return None
    # if single device dominates
    if len(group.affected_devices) == 1:
        return "single-device: likely device-specific or local data; check device storage, plugins, OS"
    # plugin correlation: if >80% of group have same plugin
    plugin_counter: Counter[str] = Counter()
    for log in logs:
        if (log.stack_hash or log.tak_stack_hash) == group.stack_hash or log.tak_error == group.exception:
            for pn in log.plugin_names:
                plugin_counter[pn] += 1
    if plugin_counter:
        top_plugin, cnt = plugin_counter.most_common(1)[0]
        if cnt / group.count >= 0.8:
            return f"plugin-correlated ({top_plugin} in {cnt}/{group.count}); check plugin compatibility"
    # version correlation
    version_counter: Counter[str] = Counter()
    for log in logs:
        if (log.stack_hash or log.tak_stack_hash) == group.stack_hash:
            if log.tak_version:
                version_counter[log.tak_version] += 1
    if version_counter:
        top_ver, cnt = version_counter.most_common(1)[0]
        if cnt / group.count >= 0.9:
            return f"version-correlated ({top_ver} {cnt}/{group.count}); likely TAK bug fixed in other versions"
    # device model
    model_counter: Counter[str] = Counter()
    for log in logs:
        if (log.stack_hash or log.tak_stack_hash) == group.stack_hash and log.device_model:
            model_counter[log.device_model] += 1
    if model_counter:
        top_model, cnt = model_counter.most_common(1)[0]
        if cnt / group.count >= 0.8:
            return f"device-correlated ({top_model} {cnt}/{group.count}); check driver / GPU"
    # generic
    if group.count / max(total, 1) >= 0.5:
        return "fleet-wide: dominant crash, prioritize server or TAK core"
    return "mixed: no single strong correlation - inspect logcat/stack"


def analyze(logs: list[ParsedLog]) -> Report:
    """Build admin overview report from parsed logs."""
    # filter none?
    logs = [log for log in logs if log]

    total = len(logs)
    metric_logs = sum(1 for log in logs if log.is_metric)
    error_logs = total - metric_logs

    # summary helpers
    uids = {log.uid for log in logs if log.uid}
    callsigns = {log.callsign for log in logs if log.callsign}
    stack_hashes = {log.stack_hash or log.tak_stack_hash for log in logs if log.stack_hash or log.tak_stack_hash}
    # normalize None
    stack_hashes.discard(None)
    tak_versions = {log.tak_version for log in logs if log.tak_version}
    device_models = {log.device_model for log in logs if log.device_model}

    times_all = [_parse_time(log.timestamp or log.time) for log in logs]
    times: list[datetime] = [t for t in times_all if t is not None]
    times_sorted = sorted(times)
    date_range: tuple[str | None, str | None] = (None, None)
    if times_sorted:
        date_range = (times_sorted[0].isoformat(), times_sorted[-1].isoformat())

    summary = Summary(
        total=total,
        unique_devices=len(uids),
        unique_callsigns=len(callsigns),
        unique_stack_hashes=len(stack_hashes),
        unique_tak_versions=len(tak_versions),
        unique_device_models=len(device_models),
        date_range=date_range,
        metric_logs=metric_logs,
        error_logs=error_logs,
    )

    # per-device
    by_uid: dict[str, list[ParsedLog]] = defaultdict(list)
    for log in logs:
        by_uid[log.uid or "unknown"].append(log)
    devices: list[DeviceStats] = []
    for uid, lst in by_uid.items():
        lst_sorted = sorted(lst, key=lambda l: l.timestamp or l.time or "")
        first = lst_sorted[0]
        last = lst_sorted[-1]
        # dominant error for device
        err_counter: Counter[str | None] = Counter(log.stack_hash or log.tak_stack_hash for log in lst)
        dominant_hash, _ = err_counter.most_common(1)[0] if err_counter else (None, 0)
        dominant_error = None
        for log in lst:
            if (log.stack_hash or log.tak_stack_hash) == dominant_hash:
                dominant_error = log.tak_error or log.exception_type
                break
        tak_vers = sorted({log.tak_version for log in lst if log.tak_version})
        dev_plugins = sorted({pn for log in lst for pn in log.plugin_names})
        filenames = [log.filename for log in lst if log.filename]
        model = next((log.device_model for log in lst if log.device_model), None)
        manufacturer = next((log.device_manufacturer for log in lst if log.device_manufacturer), None)
        android_release = next((log.android_release for log in lst if log.android_release), None)
        callsign = next((log.callsign for log in lst if log.callsign), None)
        platform = next((log.platform for log in lst if log.platform), None)
        devices.append(
            DeviceStats(
                uid=uid,
                callsign=callsign,
                platform=platform,
                model=model,
                manufacturer=manufacturer,
                android_release=android_release,
                crash_count=len(lst),
                first_seen=first.timestamp or first.time,
                last_seen=last.timestamp or last.time,
                filenames=[f for f in filenames if f is not None],
                dominant_error=dominant_error,
                dominant_stack_hash=str(dominant_hash) if dominant_hash else None,
                tak_versions=tak_vers,
                plugins=dev_plugins,
            )
        )
    devices.sort(key=lambda d: d.crash_count, reverse=True)

    # per-error (stack hash)
    by_hash: dict[str | None, list[ParsedLog]] = defaultdict(list)
    for log in logs:
        key = log.stack_hash or log.tak_stack_hash or log.exception_type or "unknown"
        by_hash[key].append(log)
    errors: list[ErrorGroup] = []
    for h, lst in by_hash.items():
        lst_sorted = sorted(lst, key=lambda l: l.timestamp or l.time or "")
        first = lst_sorted[0]
        last = lst_sorted[-1]
        # representative log for exception/top_frame
        rep = lst_sorted[0]
        affected_devices = sorted({log.uid for log in lst if log.uid})
        affected_callsigns = sorted({log.callsign for log in lst if log.callsign})
        tak_vers = sorted({log.tak_version for log in lst if log.tak_version})
        models = sorted({log.device_model for log in lst if log.device_model})
        filenames = [log.filename for log in lst if log.filename][:5]
        # stack hash is key if key looks like hash, else exception group
        stack_hash = h if h and len(str(h)) <= 16 and re.match(r"^[a-f0-9]+$", str(h), re.I) else None
        # if key was exception, use rep's hash
        if not stack_hash:
            stack_hash = rep.stack_hash or rep.tak_stack_hash
        error_group = ErrorGroup(
            stack_hash=str(h) if h else None,
            exception=rep.exception_type or rep.tak_error,
            exception_message=rep.exception_message,
            top_frame=rep.top_frame,
            count=len(lst),
            affected_devices=affected_devices,
            affected_callsigns=affected_callsigns,
            tak_versions=tak_vers,
            device_models=models,
            first_seen=first.timestamp or first.time,
            last_seen=last.timestamp or last.time,
            example_log_id=rep.id,
            sample_filenames=filenames,
        )
        # heuristic after creation needs logs
        errors.append(error_group)
    # heuristics need total logs
    for eg in errors:
        eg.heuristic = _heuristic_for_error(eg, total, logs)
    errors.sort(key=lambda e: e.count, reverse=True)

    # per-plugin
    plugin_map: dict[str, list[ParsedLog]] = defaultdict(list)
    for log in logs:
        for pn in log.plugin_names:
            plugin_map[pn].append(log)
    plugin_stats: list[PluginStats] = []
    for name, lst in plugin_map.items():
        versions = sorted({p.get("version", "") for log in lst for p in log.plugins if p.get("name") == name})
        raw_hashes: set[str | None] = {log.stack_hash or log.tak_stack_hash for log in lst}
        hashes = sorted({h for h in raw_hashes if h})
        uids_p = sorted({log.uid for log in lst if log.uid})
        plugin_stats.append(
            PluginStats(name=name, count=len(lst), versions=versions, stack_hashes=hashes, device_uids=uids_p)
        )
    plugin_stats.sort(key=lambda p: p.count, reverse=True)

    # per_day / per_hour
    per_day: Counter[str] = Counter()
    per_hour: Counter[str] = Counter()
    for log in logs:
        dt = _parse_time(log.timestamp or log.time)
        if not dt:
            continue
        per_day[dt.date().isoformat()] += 1
        per_hour[dt.strftime("%Y-%m-%d %H:00")] += 1

    return Report(
        summary=summary,
        devices=devices,
        errors=errors,
        plugins=plugin_stats,
        per_day=dict(sorted(per_day.items())),
        per_hour=dict(sorted(per_hour.items())),
    )


def to_dict(report: Report) -> dict[str, Any]:
    """Serialize report to plain dict for JSON export."""
    return {
        "summary": {
            "total": report.summary.total,
            "unique_devices": report.summary.unique_devices,
            "unique_callsigns": report.summary.unique_callsigns,
            "unique_stack_hashes": report.summary.unique_stack_hashes,
            "unique_tak_versions": report.summary.unique_tak_versions,
            "unique_device_models": report.summary.unique_device_models,
            "date_range": report.summary.date_range,
            "metric_logs": report.summary.metric_logs,
            "error_logs": report.summary.error_logs,
        },
        "devices": [
            {
                "uid": d.uid,
                "callsign": d.callsign,
                "platform": d.platform,
                "model": d.model,
                "manufacturer": d.manufacturer,
                "android_release": d.android_release,
                "crash_count": d.crash_count,
                "first_seen": d.first_seen,
                "last_seen": d.last_seen,
                "dominant_error": d.dominant_error,
                "dominant_stack_hash": d.dominant_stack_hash,
                "tak_versions": d.tak_versions,
                "plugins": d.plugins,
            }
            for d in report.devices
        ],
        "errors": [
            {
                "stack_hash": e.stack_hash,
                "exception": e.exception,
                "exception_message": e.exception_message,
                "top_frame": e.top_frame,
                "count": e.count,
                "affected_devices": e.affected_devices,
                "affected_callsigns": e.affected_callsigns,
                "tak_versions": e.tak_versions,
                "device_models": e.device_models,
                "first_seen": e.first_seen,
                "last_seen": e.last_seen,
                "heuristic": e.heuristic,
            }
            for e in report.errors
        ],
        "plugins": [
            {"name": p.name, "count": p.count, "versions": p.versions, "stack_hashes": p.stack_hashes}
            for p in report.plugins
        ],
        "per_day": report.per_day,
        "per_hour": report.per_hour,
    }
