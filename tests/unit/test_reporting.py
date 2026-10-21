"""Filesystem and terminal safety tests for snapshot reporting."""

from __future__ import annotations

import json
import stat
import threading
from pathlib import Path

import pytest

from infralens import reporting
from infralens.models import Snapshot
from infralens.reporting import format_summary, write_snapshot

FIXTURE = Path(__file__).parents[1] / "fixtures" / "snapshot_partial.json"


def _snapshot() -> Snapshot:
    return Snapshot.model_validate_json(FIXTURE.read_text(encoding="utf-8"))


def test_write_snapshot_is_private_valid_json_and_refuses_existing_file(tmp_path: Path) -> None:
    destination = tmp_path / "snapshot.json"

    written = write_snapshot(_snapshot(), destination)

    assert written == destination
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert json.loads(destination.read_text(encoding="utf-8"))["schema_version"] == "1.0.0"
    with pytest.raises(FileExistsError):
        write_snapshot(_snapshot(), destination)


def test_overwrite_replaces_only_after_serialization_and_keeps_private_mode(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "snapshot.json"
    destination.write_text("previous", encoding="utf-8")
    destination.chmod(0o644)

    write_snapshot(_snapshot(), destination, overwrite=True)

    assert json.loads(destination.read_text(encoding="utf-8"))["schema_version"] == "1.0.0"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert list(tmp_path.glob("*.tmp")) == []


def test_symlink_destination_is_rejected_without_changing_target(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("keep", encoding="utf-8")
    destination = tmp_path / "snapshot.json"
    destination.symlink_to(target)

    with pytest.raises(ValueError, match="symbolic link"):
        write_snapshot(_snapshot(), destination, overwrite=True)

    assert target.read_text(encoding="utf-8") == "keep"


def test_validation_failure_does_not_create_output_or_temporary_file(tmp_path: Path) -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["host"]["os_version"] = "x" * 4_097
    snapshot = Snapshot.model_validate(payload)
    destination = tmp_path / "snapshot.json"

    with pytest.raises(ValueError, match="4,096"):
        write_snapshot(snapshot, destination)

    assert not destination.exists()
    assert list(tmp_path.iterdir()) == []


def test_failed_atomic_replace_preserves_previous_file_and_cleans_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "snapshot.json"
    destination.write_text("previous", encoding="utf-8")

    def fail_replace(source: Path, target: Path) -> None:
        raise OSError("simulated publication failure")

    monkeypatch.setattr(reporting.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated publication failure"):
        write_snapshot(_snapshot(), destination, overwrite=True)

    assert destination.read_text(encoding="utf-8") == "previous"
    assert list(tmp_path.iterdir()) == [destination]


def test_no_replace_publication_is_race_safe(tmp_path: Path) -> None:
    destination = tmp_path / "snapshot.json"
    start = threading.Barrier(2)
    outcomes: list[str] = []
    lock = threading.Lock()

    def write() -> None:
        start.wait()
        try:
            write_snapshot(_snapshot(), destination)
            outcome = "written"
        except FileExistsError:
            outcome = "exists"
        with lock:
            outcomes.append(outcome)

    writers = [threading.Thread(target=write) for _ in range(2)]
    for writer in writers:
        writer.start()
    for writer in writers:
        writer.join(timeout=5)

    assert all(not writer.is_alive() for writer in writers)
    assert sorted(outcomes) == ["exists", "written"]
    assert json.loads(destination.read_text(encoding="utf-8"))["schema_version"] == "1.0.0"
    assert list(tmp_path.glob(".*.tmp")) == []


def test_summary_removes_ansi_and_control_characters_from_findings() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["findings"][0]["message"] = "disk\x1b[31m RED\x1b[0m\nNEXT\x7f"
    summary = format_summary(Snapshot.model_validate(payload))

    assert "\x1b" not in summary
    assert "\x7f" not in summary
    assert "disk REDNEXT" in summary
    assert "Platform: ubuntu 24.04 6.8.0" in summary
    assert "Scope: 39cb65cb-a089-4208-82f7-d636cdb7bef1 (operator)" in summary
    assert "Time:" in summary
    assert "Collector counts:" in summary
    assert "evidence: e:1" in summary
    assert "Findings: 1" in summary
    assert "review before sharing" in summary
