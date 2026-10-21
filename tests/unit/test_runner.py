"""Security and resource-boundary tests for the subprocess runner."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from infralens import runner
from infralens.runner import CommandResult, run_command


def _allow_python(monkeypatch: pytest.MonkeyPatch) -> str:
    executable = Path(sys.executable).resolve()
    command = executable.name
    monkeypatch.setattr(runner, "ALLOWED_COMMANDS", frozenset({command}))
    monkeypatch.setattr(runner, "TRUSTED_PATHS", (executable.parent,))
    return command


def _run_python(
    monkeypatch: pytest.MonkeyPatch, code: str, *args: str, seconds: float = 3.0
) -> CommandResult:
    command = _allow_python(monkeypatch)
    return run_command(
        [command, "-c", code, *args],
        deadline=time.monotonic() + seconds,
    )


def test_command_uses_minimal_environment_and_closed_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    result = _run_python(
        monkeypatch,
        "import json, os, sys; "
        "print(json.dumps(sorted(os.environ))); print(repr(sys.stdin.read()))",
    )

    assert result.succeeded
    assert result.stdout.decode().splitlines() == ['["LANG", "LC_ALL", "PATH"]', "''"]
    assert result.stderr_bytes == 0


def test_arguments_are_literal_and_never_interpreted_by_a_shell(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = tmp_path / "shell-was-used"
    argument = f"; touch {marker}"
    result = _run_python(
        monkeypatch,
        "import sys; print(sys.argv[1])",
        argument,
    )

    assert result.succeeded
    assert result.stdout.decode().strip() == argument
    assert not marker.exists()


def test_stdout_is_capped_and_stderr_content_is_discarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = run_command(
        [
            _allow_python(monkeypatch),
            "-c",
            "import os; os.write(1, b'x'*8192); os.write(2, b'API_TOKEN=not-for-output')",
        ],
        deadline=time.monotonic() + 3,
        stdout_limit=1024,
    )

    assert result.returncode == 0
    assert result.stdout == b"x" * 1024
    assert result.stdout_truncated
    assert result.stderr_bytes == len(b"API_TOKEN=not-for-output")
    assert not hasattr(result, "stderr")
    assert "not-for-output" not in repr(result)


def test_nonzero_status_is_preserved_without_raw_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _run_python(
        monkeypatch,
        "import os, sys; os.write(2, b'credential=do-not-copy'); sys.exit(7)",
    )

    assert result.returncode == 7
    assert not result.succeeded
    assert "do-not-copy" not in repr(result)


def test_deadline_kills_a_slow_command(monkeypatch: pytest.MonkeyPatch) -> None:
    started = time.monotonic()
    result = run_command(
        [_allow_python(monkeypatch), "-c", "import time; time.sleep(10)"],
        deadline=started + 0.15,
    )

    assert result.timed_out
    assert not result.succeeded
    assert time.monotonic() - started < 2


def test_expired_deadline_does_not_start_a_process(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow_python(monkeypatch)
    result = run_command([Path(sys.executable).resolve().name, "-c", "raise SystemExit(99)"], 0)

    assert result.timed_out
    assert result.returncode is None


def test_executable_lookup_never_uses_the_current_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = tmp_path / "executed"
    fake = tmp_path / "systemctl"
    fake.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    fake.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(runner, "TRUSTED_PATHS", ())

    result = run_command(["systemctl", "--version"], time.monotonic() + 2)

    assert result.error == "executable_not_found"
    assert not marker.exists()


def test_command_allowlist_and_argument_limits_are_enforced() -> None:
    with pytest.raises(ValueError, match="trusted executable allowlist"):
        run_command([sys.executable, "-V"], time.monotonic() + 1)
    with pytest.raises(ValueError, match="without NUL"):
        run_command(["systemctl", "bad\x00arg"], time.monotonic() + 1)
    with pytest.raises(ValueError, match="more than"):
        run_command(["systemctl", *(["x"] * runner.MAX_ARGUMENTS)], time.monotonic() + 1)
