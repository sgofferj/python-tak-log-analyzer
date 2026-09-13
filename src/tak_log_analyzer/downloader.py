"""Download device logs from TAK Server via python_takserver_api."""

from __future__ import annotations

import asyncio
import io
import zipfile
from pathlib import Path
from typing import Any

from python_takserver_api import Server


async def _download_to_dir(
    server: Server,
    out_dir: Path,
    ids: str | list[Any] | None,
    query: str | None = None,
    uid: str | None = None,
) -> list[Path]:
    """Helper to download logs to ``out_dir``; returns written file paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    # decide ids to download
    if ids is not None:
        target_ids: Any = ids
    elif uid is not None:
        status, logs = await server.device_logs.get_logs_for_uid(uid)
        if status != 200:
            raise RuntimeError(f"get_logs_for_uid failed {status} {logs}")
        if not logs:
            return []
        target_ids = [log["id"] for log in logs]
    elif query is not None:
        status, logs = await server.device_logs.search_logs(query)
        if status != 200:
            raise RuntimeError(f"search_logs failed {status} {logs}")
        target_ids = [log["id"] for log in logs]
        if not target_ids:
            return []
    else:
        target_ids = "ALL"

    # use download_logs - handles ALL / list / single
    status, data = await server.device_logs.download_logs(target_ids)
    if status != 200:
        raise RuntimeError(f"download_logs failed {status} {data}")
    if not isinstance(data, (bytes, bytearray)):
        raise RuntimeError(f"unexpected data type {type(data)}")

    # single raw file vs ZIP
    if (
        isinstance(target_ids, list)
        and len(target_ids) == 1
        or isinstance(target_ids, (str, int))
        and str(target_ids) != "ALL"
        and "," not in str(target_ids)
    ):
        # single file: data is raw JSON/text
        # try to infer filename from logs listing if available
        # fallback to id.json
        single_id = str(target_ids) if not isinstance(target_ids, list) else str(target_ids[0])
        # attempt to get filename from listing
        try:
            status, logs = await server.device_logs.list_logs()
            if status == 200:
                for log in logs:
                    if str(log["id"]) == single_id:
                        fname = log.get("filename") or f"{single_id}.json"
                        break
                else:
                    fname = f"{single_id}.json"
            else:
                fname = f"{single_id}.json"
        except Exception:
            fname = f"{single_id}.json"
        p = out_dir / fname
        p.write_bytes(bytes(data))
        written.append(p)
    else:
        # ZIP
        buf = io.BytesIO(bytes(data))
        try:
            with zipfile.ZipFile(buf) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    # sanitize filename
                    name = Path(info.filename).name or info.filename
                    p = out_dir / f"{name}"
                    # avoid overwrite: if exists, prefix with id
                    if p.exists():
                        p = out_dir / f"dup_{name}"
                    p.write_bytes(zf.read(info.filename))
                    written.append(p)
        except zipfile.BadZipFile:
            # fallback: single file but returned as bytes
            p = out_dir / "download.bin"
            p.write_bytes(bytes(data))
            written.append(p)
    return written


async def download_logs(
    host: str,
    cert: str,
    key: str,
    out_dir: str | Path,
    *,
    query: str | None = None,
    uid: str | None = None,
    ids: str | list[Any] | None = None,
    ca_cert: str | None = None,
) -> list[Path]:
    """Download logs from TAK Server to ``out_dir``.

    One of ``ids`` / ``query`` / ``uid`` may be given to filter;
    otherwise ``ALL`` is downloaded.

    Returns list of written file paths.
    """
    out_path = Path(out_dir)
    server = Server(host, cert, key, ca_cert=ca_cert)
    try:
        return await _download_to_dir(server, out_path, ids=ids, query=query, uid=uid)
    finally:
        await server.close()


async def list_logs(
    host: str,
    cert: str,
    key: str,
    *,
    query: str | None = None,
    metrics: bool = False,
    uid: str | None = None,
    ca_cert: str | None = None,
) -> tuple[int, list[dict[str, Any]]]:
    """List logs via ``LogManager.jsp`` without downloading."""
    server = Server(host, cert, key, ca_cert=ca_cert)
    try:
        if uid is not None:
            return await server.device_logs.get_logs_for_uid(uid, metrics=metrics, query=query)
        if query is not None:
            return await server.device_logs.search_logs(query, metrics=metrics)
        return await server.device_logs.list_logs(query=query, metrics=metrics)
    finally:
        await server.close()
