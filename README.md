# python-tak-log-analyzer

GPL-3.0-or-later — Analyze TAK Server device logs (crashlogs / logcats) for admin overview.

Downloads (all or filtered) device error/metrics logs from a TAK Server via `python-takserver-api` (`Marti/ErrorLog` + `LogManager.jsp`) and runs basic analytics to answer:

* **Which devices are problematic?** — ranking by crash count, recency, device model, OS, TAK version, plugins.
* **Which problems occur and how often?** — grouping by exception / stack hash / top frames, affected devices/versions.
* **Why (if possible)?** — heuristic correlation with plugins, versions, device models, and pre-crash logcat.

> Status: initial implementation covering ACRA crash JSONs (the proprietary TAK/ATAK crash report) plus generic logcat extraction. Metric logs (`filename LIKE 'metric%'`) are listed separately.

## Why this output belongs to python-tak-log-analyzer, not python-takserver-api

`python-takserver-api` is a *transport* wrapper: it faithfully exposes the TAK Server HTTP API (including the new `device_logs` accessor). `python-tak-log-analyzer` is an *application* on top: it fetches those proprietary crash blobs, parses the ACRA envelope, normalizes the logcat, and builds admin-facing aggregates/recommendations. Keeping them separate preserves the API wrapper's single-responsibility and lets the analyzer evolve its heuristics, reporting formats, and UX without polluting the wrapper.

## Example live server

Tested on **5.7-RELEASE-43-HEAD** (`tak.example.com:8443`). The proprietary ACRA payload is:

```json
{
  "header": {
    "TAK.uid": "ANDROID-EXAMPLE-UID-001",
    "TAK.error": "java.lang.NullPointerException: Attempt to invoke ... on a null object reference",
    "TAK.stackHash": "6d8a2026",
    "TAK.version": "5.6.0.15 (3d3d96d1)[playstore]",
    "device.model": "Tab8", "device.manufacturer": "Blackview",
    "android.release": "10", "android.sdk": "29",
    "plugins": [{"plugin": "plugin.version.loaded.VNS", "version": "3.11 ..."}]
  },
  "report": {
    "STACK_TRACE": "java.lang.NullPointerException: ...\\n\\tat com.atakmap.android.update.g.a(SourceFile:26)...",
    "STACK_TRACE_HASH": "6d8a2026",
    "LOGCAT": "03-25 20:28:28.449 D/ProductProviderManager: Sync complete...\\n03-25 20:28:28.463 E/AndroidRuntime: FATAL EXCEPTION: main ...",
    "LOGCAT": "...",
    "BUILD": {...}, "PHONE_MODEL": "Tab8", "ANDROID_VERSION": 10,
    "PACKAGE_NAME": "com.atakmap.app.civ", "APP_VERSION_NAME": "5.6.0.15 ..."
  },
  "gpu": {...}
}
```

A sanitized example is shipped under `tests/data/example_crash.json`.

## Suggested Analytics (implemented + roadmap)

**Implemented in `tak_log_analyzer.analyzer`:**

* **Summary:** total logs, date range, unique devices / callsigns / stack hashes / TAK versions.
* **Devices ranking:** per UID (`uid`, `callsign`, `platform`, `device.model`, `android.release`, crashes, last seen, dominant error). Sorted by count. Flags “single-device repeated crash” vs “fleet-wide”.
* **Errors ranking:** group by `STACK_TRACE_HASH` / `TAK.stackHash` or exception first line. For each: count, exception, top frame, affected devices, versions, time span.
* **Plugin correlation:** plugin name -> crashes where loaded, dominant version, co-occurrence with stack hashes.
* **Time series:** crashes per day (and per hour) to spot regressions after an update.
* **Logcat triage:** last 20 `E/` / `FATAL EXCEPTION` lines plus the stack trace, surfaced in the per-error detail to hint “why” without manual opening.
* **Heuristic “why”:** if a stack hash is 100 % associated with one plugin or one TAK version or one device model, annotate as “likely plugin/version/device-specific”. Example live: `NullPointerException at com.atakmap.android.update.g.a(SourceFile:26)` + `ProductProviderManager` + `IncompatiblePluginWizard` in logcat → suggests stale plugin set (Data Sync 3.7.4) during repo sync.

**Roadmap / suggestions:**

* Source-file de-obfuscation (mapping `SourceFile:26` via `tak` `VERSION` + build mapping).
* Clustering logcat lines (e.g., `RepoSyncTask`, `ProductRepository`, `IncompatiblePluginWizard`) to separate “plugin update” crashes from “comms” crashes.
* Metric logs (`metric_*`) — currently downloadable but not aggregated (CPU/memory, DB metrics).
* Trend alerting (spike after `TIMESTAMP` or new `APP_VERSION_CODE`).
* Export to CSV/JSON/HTML with rich tables + collapsible stack traces.
* On-device symbolication for native crashes (if NDK logs appear).

## Installation

```bash
# from sibling checkout (dev, uses path dependency on python-takserver-api)
poetry install
# or pip
pip install -e .

# production (once analyzer + API are published)
pip install python-tak-log-analyzer
```

Requires Python 3.11+, `aiohttp`, `click`, `rich`, `python-takserver-api` (with `server.device_logs` accessor).

## Quickstart — Download

```bash
# download all error logs (admin cert required)
tak-log-analyzer download \
  --host tak.example.com \
  --cert sgofferj.pem --key sgofferj_np.key \
  --out ./tak-logs

# filtered download (server-side LIKE)
tak-log-analyzer download --host tak.example.com --cert s.pem --key k.pem \
  --query EXAMPLE-CALLSIGN --out ./tak-logs

# per-UID filtered download (exact match helper)
tak-log-analyzer download --host tak.example.com --cert s.pem --key k.pem \
  --uid ANDROID-EXAMPLE-UID-001 --out ./tak-logs
```

Downloads raw files (single id -> `*.json`, multi/`ALL` -> ZIP unpacked). Listing is via `LogManager.jsp` scrape, so `query` is the same `LIKE %query%` as the Admin UI search box.

## Quickstart — Analyze

```python
from tak_log_analyzer.parser import parse_file
from tak_log_analyzer.analyzer import analyze

logs = [parse_file(p) for p in Path("./tak-logs").glob("*.json")]
report = analyze(logs)

print(f"Total {report.summary.total} crashes, {len(report.devices)} devices, {len(report.errors)} error groups")
for dev in report.devices[:5]:
    print(dev.uid, dev.callsign, dev.model, dev.crash_count, dev.dominant_error)

for err in report.errors[:5]:
    print(err.stack_hash, err.exception, err.count, f"devices={len(err.affected_devices)}")
    print(err.top_frame, "why:", err.heuristic)
```

CLI:

```bash
# analyze local dir, pretty tables
tak-log-analyzer analyze --input ./tak-logs

# json report for downstream
tak-log-analyzer analyze --input ./tak-logs --format json --out report.json
```

Example output (rich tables):

```
Summary: 3 crashes, 1 device, 1 error, range 2026-03-25T18:28:33Z..2026-03-25T18:37:44
Devices (problematic first):
┏━━━━┳━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ UID ┃ Callsign ┃ Model    ┃ Count ┃ Last seen         ┃ OS  ┃ Dominant error                    ┃
┡━━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ ANDROID-EXAMPLE-UID-001 │ EXAMPLE-CALLSIGN │ Tab8 │ 3 │ 2026-03-25T18:37:44 │ 10 │ NPE at g.a(SourceFile:26) (6d8a2026) │
└────┴─────────┴──────────┴───────┴─────────────────┴───────┴──────────────────────────────┘
Errors (by frequency):
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Hash ┃ Exception            ┃ Count ┃ Devices ┃ Top frame          ┃ Heuristic              ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 6d8a2026 │ NullPointerException │ 3 │ 1 │ g.a(SourceFile:26) │ likely plugin sync bug │
└──────┴──────────────────────┴───────┴────────┴────────────────────┴────────────────────────┘
```

## Direct fetch + analyze (no intermediate files)

```bash
tak-log-analyzer fetch-analyze --host tak.example.com --cert s.pem --key k.pem
tak-log-analyzer fetch-analyze --host tak.example.com --cert s.pem --key k.pem --query "VNS"
```

## Development

```bash
poetry install
poetry run pre-commit install
poetry run pytest          # 65 % coverage gate
poetry run pytest live_tests/ -m live   # needs .env with TAK_LIVE_HOST/CERT/KEY (admin)
```

`.env` example:

```
TAK_LIVE_HOST=tak.example.com
TAK_LIVE_CERT=../python-takserver-api/test-secrets/sgofferj.pem
TAK_LIVE_KEY=../python-takserver-api/test-secrets/sgofferj_np.key
```

Live tests create and clean up own `live-test-<uuid>` logs.

## License

GPL-3.0-or-later, see [LICENSE](LICENSE).
