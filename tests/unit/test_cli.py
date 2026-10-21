"""Tests for the initial CLI bootstrap."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from infralens import __version__
from infralens.cli import main


def test_help_lists_scan_without_running_it(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as error:
        main(["--help"])

    assert error.value.code == 0
    output = capsys.readouterr().out
    assert "scan" in output
    assert "--version" in output


def test_version_exits_successfully(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as error:
        main(["--version"])

    assert error.value.code == 0
    assert capsys.readouterr().out.strip() == f"infralens {__version__}"


def test_scan_returns_three_after_persisting_partial_snapshot(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot_path = Path(__file__).parents[1] / "fixtures" / "snapshot_partial.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    from infralens.models import Snapshot

    parsed_snapshot = Snapshot.model_validate(snapshot)
    monkeypatch.setattr("infralens.scan.scan_local", lambda _scope_id: parsed_snapshot)
    output = tmp_path / "snapshot.json"

    status = main(["scan", "--local", "--output", str(output), "--fail-on-partial"])

    assert status == 3
    assert output.exists()
    assert "Findings: 1" in capsys.readouterr().out


def test_scan_rejects_stdout_as_output_without_collecting(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_scan(_scope_id: str | None) -> None:
        raise AssertionError("scan must not run for invalid output")

    monkeypatch.setattr("infralens.scan.scan_local", unexpected_scan)
    status = main(["scan", "--local", "--output", "-"])

    assert status == 2
    assert "local file path" in capsys.readouterr().err


def test_scan_interruption_returns_130_without_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupt(_scope_id: str | None) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("infralens.scan.scan_local", interrupt)
    output = tmp_path / "snapshot.json"

    status = main(["scan", "--local", "--output", str(output)])

    assert status == 130
    assert not output.exists()
    assert "interrupted" in capsys.readouterr().err


def test_existing_output_returns_two_without_overwriting(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot_path = Path(__file__).parents[1] / "fixtures" / "snapshot_partial.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    from infralens.models import Snapshot

    parsed_snapshot = Snapshot.model_validate(snapshot)
    monkeypatch.setattr("infralens.scan.scan_local", lambda _scope_id: parsed_snapshot)
    output = tmp_path / "snapshot.json"
    output.write_text("keep", encoding="utf-8")

    status = main(["scan", "--local", "--output", str(output)])

    assert status == 2
    assert output.read_text(encoding="utf-8") == "keep"
    assert "already exists" in capsys.readouterr().err


def test_write_interruption_returns_130_and_cleans_temporary_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot_path = Path(__file__).parents[1] / "fixtures" / "snapshot_partial.json"
    from infralens.models import Snapshot

    parsed_snapshot = Snapshot.model_validate_json(snapshot_path.read_text(encoding="utf-8"))
    monkeypatch.setattr("infralens.scan.scan_local", lambda _scope_id: parsed_snapshot)

    def interrupt(*_args: object, **_kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("infralens.reporting.write_snapshot", interrupt)
    output = tmp_path / "snapshot.json"

    status = main(["scan", "--local", "--output", str(output)])

    assert status == 130
    assert not output.exists()
    assert list(tmp_path.iterdir()) == []
    assert "interrupted" in capsys.readouterr().err


def test_module_entry_point_shows_help_from_installed_python() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "infralens", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "usage: infralens" in result.stdout
