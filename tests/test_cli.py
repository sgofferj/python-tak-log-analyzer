"""CLI smoke tests."""

from pathlib import Path

from click.testing import CliRunner

from tak_log_analyzer.cli import cli

DATA_DIR = Path(__file__).parent / "data"


def test_analyze_cli_table(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "--input", str(DATA_DIR)])
    assert result.exit_code == 0
    assert "Summary" in result.output
    assert "EXAMPLE-CALLSIGN" in result.output or "Tab8" in result.output or "Devices" in result.output


def test_analyze_cli_json(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", "--input", str(DATA_DIR), "--format", "json", "--out", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert '"total"' in out.read_text()
