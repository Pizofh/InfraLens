"""Deadline, memory, and IPC tests for collector workers."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from infralens.scan import (
    MAX_WORKER_RESULT_BYTES,
    WORKER_ADDRESS_SPACE_BYTES,
    CollectorTarget,
    run_collectors,
)

HELPERS = "tests.unit.worker_helpers"


def _target(function: str, collector_id: str = "host") -> CollectorTarget:
    return CollectorTarget(collector_id, HELPERS, function)


def test_spawn_worker_returns_json_and_applies_memory_limit() -> None:
    result = run_collectors([_target("return_context")], {"value": "fixture"}, worker_timeout=3)[0]
    limited = run_collectors([_target("report_address_space_limit")], {}, worker_timeout=3)[0]

    assert result.state == "ok"
    assert result.value["value"] == "fixture"
    assert result.value["pid"] != os.getpid()
    assert result.value["global_deadline"] >= result.value["worker_deadline"]
    assert result.value["global_deadline"] - result.value["worker_deadline"] > 20
    assert limited.state == "ok"
    assert limited.value["soft_limit"] == WORKER_ADDRESS_SPACE_BYTES


def test_unexpected_worker_error_is_sanitized() -> None:
    result = run_collectors([_target("raise_unexpected_error")], {}, worker_timeout=3)[0]

    assert result.state == "collection_error"
    assert result.error_code == "worker_error"
    assert result.message == "collector raised an unexpected error"
    assert "sensitive diagnostic" not in repr(result)


def test_worker_deadline_kills_worker_and_continues_to_next_collector() -> None:
    started = time.monotonic()
    results = run_collectors(
        [_target("sleep_forever"), _target("return_context", "processes")],
        {"value": "still runs"},
        global_timeout=4,
        worker_timeout=0.2,
    )

    assert time.monotonic() - started < 3
    assert results[0].state == "collection_error"
    assert results[0].error_code == "timeout"
    assert results[1].state == "ok"
    assert results[1].value["value"] == "still runs"


def test_global_deadline_marks_unstarted_collectors_skipped() -> None:
    results = run_collectors(
        [_target("sleep_forever"), _target("return_context", "processes")],
        {},
        global_timeout=0.2,
        worker_timeout=0.2,
    )

    assert results[0].error_code == "timeout"
    assert results[1].state == "skipped"
    assert results[1].error_code == "global_deadline"


def test_worker_result_is_bounded() -> None:
    result = run_collectors(
        [_target("return_large_result")],
        {"size": MAX_WORKER_RESULT_BYTES + 1},
        worker_timeout=3,
    )[0]

    assert result.state == "collection_error"
    assert result.error_code == "worker_error"
    assert result.message == "worker result exceeded the IPC size limit"


def test_timeout_kills_descendants_in_worker_process_group(tmp_path: Path) -> None:
    pid_path = tmp_path / "descendant.pid"
    result = run_collectors(
        [_target("spawn_descendant_and_sleep")],
        {"pid_path": str(pid_path)},
        worker_timeout=0.4,
    )[0]

    assert result.error_code == "timeout"
    assert pid_path.exists()
    pid = int(pid_path.read_text(encoding="ascii"))
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and _process_is_running(pid):
        time.sleep(0.02)
    assert not _process_is_running(pid)


def _process_is_running(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()[2]
    except FileNotFoundError:
        return False
    return state != "Z"


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), True, 31])
def test_timeout_bounds_are_validated(timeout: float) -> None:
    with pytest.raises(ValueError, match="global_timeout"):
        run_collectors([], {}, global_timeout=timeout)


def test_module_entrypoint_can_be_imported_without_running_cli() -> None:
    import infralens.__main__  # noqa: F401
