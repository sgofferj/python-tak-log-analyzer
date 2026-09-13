"""CLI for tak-log-analyzer."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

import click
from libadvian.logging import init_logging
from rich.console import Console
from rich.table import Table

from .analyzer import analyze, to_dict
from .downloader import download_logs as dl_download
from .downloader import list_logs as dl_list
from .parser import parse_file

console = Console()


def _load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _resolve_config(
    host: str | None, cert: str | None, key: str | None, ca_cert: str | None
) -> tuple[str, str, str, str | None]:
    # try .env in cwd and repo root
    dotenv: dict[str, str] = {}
    for p in [Path.cwd() / ".env", Path(__file__).resolve().parents[2] / ".env", Path(".env")]:
        dotenv.update(_load_dotenv(p))
    # env vars override .env
    host = host or os.environ.get("TAK_LIVE_HOST") or dotenv.get("TAK_LIVE_HOST")
    cert = cert or os.environ.get("TAK_LIVE_CERT") or dotenv.get("TAK_LIVE_CERT")
    key = key or os.environ.get("TAK_LIVE_KEY") or dotenv.get("TAK_LIVE_KEY")
    ca_cert = ca_cert or os.environ.get("TAK_LIVE_CA") or dotenv.get("TAK_LIVE_CA")
    if not host or not cert or not key:
        console.print("[red]Missing --host/--cert/--key and no .env found.[/red]")
        console.print(
            "Create .env with TAK_LIVE_HOST, TAK_LIVE_CERT, TAK_LIVE_KEY (see .env.example) or pass options explicitly."
        )
        raise SystemExit(2)
    return host, cert, key, ca_cert


@click.group()
@click.option("-l", "--loglevel", default=30, help="Python log level 10=DEBUG 20=INFO")
@click.option("-v", "--verbose", count=True, help="Shorthand -v/-vv for info/debug")
def cli(loglevel: int, verbose: int) -> None:
    """TAK device log analyzer — download and analyze TAK Server crash logs."""
    if verbose == 1:
        loglevel = 20
    elif verbose >= 2:
        loglevel = 10
    init_logging(loglevel)


@cli.command("list")
@click.option("--host", required=False, help="TAK Server hostname (without port) [env: TAK_LIVE_HOST / .env]")
@click.option("--cert", required=False, type=click.Path(exists=True), help="Client PEM [env: TAK_LIVE_CERT]")
@click.option("--key", required=False, type=click.Path(exists=True), help="Client key [env: TAK_LIVE_KEY]")
@click.option("--ca-cert", type=click.Path(exists=True), help="CA / server cert for verification [env: TAK_LIVE_CA]")
@click.option("--query", help="Server-side LIKE filter (search box)")
@click.option("--uid", help="Exact UID filter (client-side)")
@click.option("--metrics", is_flag=True, help="List metric logs instead of error logs")
def list_cmd(
    host: str | None,
    cert: str | None,
    key: str | None,
    ca_cert: str | None,
    query: str | None,
    uid: str | None,
    metrics: bool,
) -> None:
    """List device logs (without downloading)."""

    host, cert, key, ca_cert = _resolve_config(host, cert, key, ca_cert)

    async def _run() -> None:
        status, logs = await dl_list(host, cert, key, query=query, uid=uid, metrics=metrics, ca_cert=ca_cert)
        if status != 200:
            console.print(f"[red]list failed {status} {logs}[/red]")
            raise SystemExit(1)
        console.print(f"[green]Found {len(logs)} logs[/green]")
        tbl = Table(title="Device Logs")
        tbl.add_column("ID", justify="right")
        tbl.add_column("Time")
        tbl.add_column("UID")
        tbl.add_column("Callsign")
        tbl.add_column("Platform")
        tbl.add_column("TAK Version")
        tbl.add_column("Filename")
        for log in logs[:50]:
            tbl.add_row(
                str(log.get("id", "")),
                str(log.get("time", ""))[:19],
                str(log.get("uid", ""))[:24],
                str(log.get("callsign", "")),
                str(log.get("platform", "")),
                str(log.get("major_version", ""))[:28],
                str(log.get("filename", "")),
            )
        console.print(tbl)
        if len(logs) > 50:
            console.print(f"[dim]... and {len(logs)-50} more (use --query to filter)[/dim]")

    asyncio.run(_run())


@cli.command("download")
@click.option("--host", required=False, help="TAK Server hostname [env: TAK_LIVE_HOST / .env]")
@click.option("--cert", required=False, type=click.Path(exists=True), help="Client PEM [env: TAK_LIVE_CERT]")
@click.option("--key", required=False, type=click.Path(exists=True), help="Client key [env: TAK_LIVE_KEY]")
@click.option("--ca-cert", type=click.Path(exists=True), help="CA cert [env: TAK_LIVE_CA]")
@click.option("--out", "out_dir", required=True, type=click.Path(), help="Output directory")
@click.option("--query", help="Server-side LIKE filter")
@click.option("--uid", help="Exact UID filter")
@click.option("--ids", help="Comma-separated ids or ALL")
def download_cmd(
    host: str | None,
    cert: str | None,
    key: str | None,
    ca_cert: str | None,
    out_dir: str,
    query: str | None,
    uid: str | None,
    ids: str | None,
) -> None:
    """Download (all|filtered) logs to a directory."""

    host, cert, key, ca_cert = _resolve_config(host, cert, key, ca_cert)

    async def _run() -> None:
        ids_arg: Any = ids
        # click ids as string -> keep as string (download_logs handles comma)
        paths = await dl_download(host, cert, key, out_dir, query=query, uid=uid, ids=ids_arg, ca_cert=ca_cert)
        console.print(f"[green]Downloaded {len(paths)} files to {out_dir}[/green]")
        for p in paths[:20]:
            console.print(f"  {p}")
        if len(paths) > 20:
            console.print(f"  ... and {len(paths)-20} more")

    asyncio.run(_run())


@cli.command("analyze")
@click.option(
    "--input", "input_dir", required=True, type=click.Path(exists=True), help="Directory with *.json crash files"
)
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--out", type=click.Path(), help="Write JSON report to file (implies --format json if set)")
def analyze_cmd(input_dir: str, fmt: str, out: str | None) -> None:
    """Analyze local crash logs and print admin overview."""
    paths = (
        list(Path(input_dir).glob("*.json")) + list(Path(input_dir).glob("*.txt")) + list(Path(input_dir).glob("*.log"))
    )
    # also support generic
    if not paths:
        paths = [p for p in Path(input_dir).iterdir() if p.is_file()]
    logs = []
    for p in paths:
        try:
            logs.append(parse_file(p))
        except Exception as exc:  # pylint: disable=broad-exception-caught
            console.print(f"[yellow]skip {p.name}: {exc}[/yellow]")
    if not logs:
        console.print("[red]No parsable logs found[/red]")
        raise SystemExit(1)

    report = analyze(logs)

    if out:
        Path(out).write_text(json.dumps(to_dict(report), indent=2))
        console.print(f"[green]Wrote {out}[/green]")

    if fmt == "json" and not out:
        console.print_json(json.dumps(to_dict(report)))

    if fmt == "table" or not out:
        _print_report(report)


def _print_report(report: Any) -> None:
    console.print(
        f"\n[bold]Summary[/bold]: {report.summary.total} crashes, "
        f"{report.summary.unique_devices} devices, "
        f"{report.summary.unique_stack_hashes} errors, "
        f"range {report.summary.date_range[0]}..{report.summary.date_range[1]}"
    )
    # Devices
    tbl = Table(title="Devices — problematic first")
    tbl.add_column("UID", overflow="fold")
    tbl.add_column("Callsign")
    tbl.add_column("Model")
    tbl.add_column("Count", justify="right")
    tbl.add_column("Last seen")
    tbl.add_column("OS")
    tbl.add_column("Dominant error", overflow="fold")
    for d in report.devices[:15]:
        tbl.add_row(
            d.uid[:22],
            d.callsign or "",
            d.model or "",
            str(d.crash_count),
            str(d.last_seen)[:19] if d.last_seen else "",
            d.android_release or "",
            (d.dominant_error or "")[:60],
        )
    console.print(tbl)

    # Errors
    tbl2 = Table(title="Errors — by frequency")
    tbl2.add_column("Hash")
    tbl2.add_column("Exception", overflow="fold")
    tbl2.add_column("Count", justify="right")
    tbl2.add_column("Devices", justify="right")
    tbl2.add_column("Top frame", overflow="fold")
    tbl2.add_column("Heuristic", overflow="fold")
    for e in report.errors[:15]:
        tbl2.add_row(
            e.stack_hash or "",
            (e.exception or "")[:50],
            str(e.count),
            str(len(e.affected_devices)),
            e.top_frame or "",
            (e.heuristic or "")[:50],
        )
    console.print(tbl2)

    # Plugins
    if report.plugins:
        tbl3 = Table(title="Plugins — crashes where loaded")
        tbl3.add_column("Plugin")
        tbl3.add_column("Count", justify="right")
        tbl3.add_column("Versions", overflow="fold")
        for p in report.plugins[:10]:
            tbl3.add_row(p.name, str(p.count), ", ".join(p.versions[:2]))
        console.print(tbl3)

    # Per day
    if report.per_day:
        tbl4 = Table(title="Crashes per day")
        tbl4.add_column("Day")
        tbl4.add_column("Count", justify="right")
        for day, cnt in list(report.per_day.items())[-14:]:
            tbl4.add_row(day, str(cnt))
        console.print(tbl4)


@cli.command("fetch-analyze")
@click.option("--host", required=False, help="TAK Server hostname [env: TAK_LIVE_HOST / .env]")
@click.option("--cert", required=False, type=click.Path(exists=True), help="Client PEM [env: TAK_LIVE_CERT]")
@click.option("--key", required=False, type=click.Path(exists=True), help="Client key [env: TAK_LIVE_KEY]")
@click.option("--ca-cert", type=click.Path(exists=True), help="CA cert [env: TAK_LIVE_CA]")
@click.option("--query", help="LIKE filter")
@click.option("--uid", help="Exact UID")
@click.option("--ids", help="Comma ids or ALL")
@click.option("--format", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.option("--out", type=click.Path(), help="Write JSON report")
def fetch_analyze_cmd(
    host: str | None,
    cert: str | None,
    key: str | None,
    ca_cert: str | None,
    query: str | None,
    uid: str | None,
    ids: str | None,
    fmt: str,
    out: str | None,
) -> None:
    """Download and analyze in one step (no intermediate dir kept)."""
    import tempfile

    host, cert, key, ca_cert = _resolve_config(host, cert, key, ca_cert)

    async def _run() -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = await dl_download(host, cert, key, tmp, query=query, uid=uid, ids=ids, ca_cert=ca_cert)
            logs = []
            for p in paths:
                try:
                    logs.append(parse_file(p))
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    console.print(f"[yellow]skip {p.name}: {exc}[/yellow]")
            if not logs:
                console.print("[red]No parsable logs[/red]")
                raise SystemExit(1)
            report = analyze(logs)
            if out:
                Path(out).write_text(json.dumps(to_dict(report), indent=2))
                console.print(f"[green]Wrote {out}[/green]")
            if fmt == "json" and not out:
                console.print_json(json.dumps(to_dict(report)))
            else:
                _print_report(report)

    asyncio.run(_run())
