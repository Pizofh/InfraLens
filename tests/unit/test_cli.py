"""Tests for the initial CLI bootstrap."""

import subprocess
import sys

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


def test_scan_reports_that_implementation_is_pending(capsys: pytest.CaptureFixture[str]) -> None:
    status = main(["scan", "--local", "--output", "snapshot.json"])

    assert status == 1
    assert "scan is not implemented yet" in capsys.readouterr().err


def test_module_entry_point_shows_help_from_installed_python() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "infralens", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "usage: infralens" in result.stdout
