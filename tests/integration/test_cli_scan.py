"""Exercise the installed entry-point path against this local Linux environment."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from infralens.models import Snapshot


@pytest.mark.integration
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux scan integration")
@pytest.mark.skipif(
    getattr(os, "geteuid", lambda: 1)() == 0,
    reason="C12 requires a non-root invocation",
)
def test_non_root_cli_scan_persists_valid_private_snapshot(tmp_path: Path) -> None:
    output = tmp_path / "snapshot.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "infralens",
            "scan",
            "--local",
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=35,
    )

    assert result.returncode == 0, result.stderr
    snapshot = Snapshot.model_validate_json(output.read_text(encoding="utf-8"))
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert {collector.id for collector in snapshot.collectors} == {
        "host",
        "processes",
        "sockets",
        "systemd",
    }
    assert "Collector counts:" in result.stdout
    assert "review before sharing" in result.stdout
