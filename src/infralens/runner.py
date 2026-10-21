"""Run a small set of trusted system commands with bounded output and deadlines."""

from __future__ import annotations

import errno
import math
import os
import selectors
import signal
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

TRUSTED_PATHS = (
    Path("/usr/sbin"),
    Path("/usr/bin"),
    Path("/sbin"),
    Path("/bin"),
)
ALLOWED_COMMANDS = frozenset({"systemctl"})
MAX_ARGUMENTS = 128
MAX_ARGUMENT_BYTES = 4096
MAX_TOTAL_ARGUMENT_BYTES = 64 * 1024
MAX_STDOUT_BYTES = 1024 * 1024
MAX_COMMAND_SECONDS = 30.0
STDERR_READ_CHUNK = 64 * 1024
READ_CHUNK = 64 * 1024
CLEANUP_SECONDS = 1.0

LaunchError = Literal["executable_not_found", "permission_denied", "execution_error"]


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Bounded result of one command; stderr content is deliberately discarded."""

    returncode: int | None
    stdout: bytes
    stderr_bytes: int
    stdout_truncated: bool
    timed_out: bool
    error: LaunchError | None = None
    errno_value: int | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None and not self.timed_out and self.returncode == 0


def run_command(
    argv: Sequence[str], deadline: float, stdout_limit: int = MAX_STDOUT_BYTES
) -> CommandResult:
    """Run an allowlisted command before a monotonic deadline.

    The caller provides a complete argv and an absolute ``time.monotonic()`` deadline.
    The executable is resolved only from fixed system directories. The child gets a
    minimal locale/PATH environment, no stdin, and its own process group so timeouts
    can stop descendants that retain output pipes. stdout is capped and stderr is
    drained while only its byte count is retained.
    """
    command, arguments = _validate_argv(argv)
    if (
        not isinstance(deadline, (float, int))
        or isinstance(deadline, bool)
        or not math.isfinite(deadline)
        or deadline < 0
    ):
        raise ValueError("deadline must be a finite absolute monotonic timestamp")
    if not isinstance(stdout_limit, int) or isinstance(stdout_limit, bool):
        raise ValueError("stdout_limit must be an integer")
    if not 0 <= stdout_limit <= MAX_STDOUT_BYTES:
        raise ValueError(f"stdout_limit must be between 0 and {MAX_STDOUT_BYTES}")

    now = time.monotonic()
    allowed_deadline = min(float(deadline), now + MAX_COMMAND_SECONDS)
    if allowed_deadline <= now:
        return CommandResult(None, b"", 0, False, True)

    if allowed_deadline <= time.monotonic():
        return CommandResult(None, b"", 0, False, True)

    executable = _resolve_executable(command)
    if executable is None:
        return CommandResult(None, b"", 0, False, False, "executable_not_found")

    child_argv = [str(executable), *arguments]
    minimal_environment = {
        "PATH": os.pathsep.join(str(path) for path in TRUSTED_PATHS),
        "LANG": "C.UTF-8",
        "LC_ALL": "C",
    }
    try:
        process = subprocess.Popen(
            child_argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env=minimal_environment,
            close_fds=True,
            shell=False,
            start_new_session=True,
            bufsize=0,
        )
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            error: LaunchError = "executable_not_found"
        elif exc.errno in {errno.EACCES, errno.EPERM}:
            error = "permission_denied"
        else:
            error = "execution_error"
        return CommandResult(None, b"", 0, False, False, error, exc.errno)

    assert process.stdout is not None
    assert process.stderr is not None
    output = bytearray()
    stderr_bytes = 0
    stdout_truncated = False
    timed_out = False
    selector = selectors.DefaultSelector()
    os.set_blocking(process.stdout.fileno(), False)
    os.set_blocking(process.stderr.fileno(), False)
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    cleanup_deadline: float | None = None

    try:
        while selector.get_map():
            current = time.monotonic()
            if current >= allowed_deadline and not timed_out:
                timed_out = True
                cleanup_deadline = current + CLEANUP_SECONDS
                _terminate_process_group(process.pid)

            if timed_out and cleanup_deadline is not None and current >= cleanup_deadline:
                for key in list(selector.get_map().values()):
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                break

            remaining = max(0.0, allowed_deadline - current)
            wait_for = min(0.05, remaining) if not timed_out else 0.05
            try:
                events = selector.select(wait_for)
            except OSError:
                events = []
            for key, _ in events:
                try:
                    chunk = os.read(key.fd, READ_CHUNK)
                except BlockingIOError:
                    continue
                except InterruptedError:
                    continue
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        chunk = b""
                    else:
                        continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if key.data == "stdout":
                    remaining_output = stdout_limit - len(output)
                    if remaining_output > 0:
                        output.extend(chunk[:remaining_output])
                    if len(chunk) > max(remaining_output, 0):
                        stdout_truncated = True
                else:
                    stderr_bytes += len(chunk)
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()

    if timed_out:
        _terminate_process_group(process.pid)
    try:
        returncode = process.wait(timeout=CLEANUP_SECONDS)
    except subprocess.TimeoutExpired:
        _terminate_process_group(process.pid)
        try:
            returncode = process.wait(timeout=CLEANUP_SECONDS)
        except subprocess.TimeoutExpired:
            returncode = None
            timed_out = True

    return CommandResult(
        returncode=returncode,
        stdout=bytes(output),
        stderr_bytes=stderr_bytes,
        stdout_truncated=stdout_truncated,
        timed_out=timed_out,
    )


def _validate_argv(argv: Sequence[str]) -> tuple[str, list[str]]:
    if isinstance(argv, (str, bytes)) or not argv:
        raise ValueError("argv must be a non-empty sequence of arguments")
    if len(argv) > MAX_ARGUMENTS:
        raise ValueError(f"argv cannot contain more than {MAX_ARGUMENTS} arguments")
    if any(not isinstance(argument, str) or "\0" in argument for argument in argv):
        raise ValueError("argv arguments must be strings without NUL bytes")
    encoded_lengths = [len(argument.encode("utf-8")) for argument in argv]
    if any(length > MAX_ARGUMENT_BYTES for length in encoded_lengths):
        raise ValueError(f"argv arguments cannot exceed {MAX_ARGUMENT_BYTES} bytes")
    if sum(encoded_lengths) > MAX_TOTAL_ARGUMENT_BYTES:
        raise ValueError(f"argv cannot exceed {MAX_TOTAL_ARGUMENT_BYTES} encoded bytes")

    command, *arguments = argv
    if command not in ALLOWED_COMMANDS or Path(command).name != command:
        raise ValueError("command is not on the trusted executable allowlist")
    return command, arguments


def _resolve_executable(command: str) -> Path | None:
    for directory in TRUSTED_PATHS:
        candidate = directory / command
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
        except OSError:
            continue
    return None


def _terminate_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        pass
