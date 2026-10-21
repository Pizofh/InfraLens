"""Run collector functions in sequential, bounded, killable worker processes."""

from __future__ import annotations

import json
import math
import multiprocessing
import os
import re
import signal
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Literal

MAX_CONTEXT_BYTES = 64 * 1024
MAX_WORKER_RESULT_BYTES = 8 * 1024 * 1024
MAX_WORKER_SECONDS = 5.0
MAX_GLOBAL_SECONDS = 30.0
WORKER_ADDRESS_SPACE_BYTES = 256 * 1024 * 1024
CLEANUP_SECONDS = 1.0
POLL_SECONDS = 0.02

WorkerState = Literal["ok", "collection_error", "skipped"]
WorkerErrorCode = Literal["timeout", "worker_error", "global_deadline"]


@dataclass(frozen=True, slots=True)
class CollectorTarget:
    """Import path for one trusted, module-level collector function."""

    collector_id: str
    module: str
    function: str = "collect"


@dataclass(frozen=True, slots=True)
class WorkerOutcome:
    """Sanitized outcome returned by the parent-side worker supervisor."""

    collector_id: str
    state: WorkerState
    value: object | None
    error_code: WorkerErrorCode | None
    message: str | None
    started_at: float
    finished_at: float


class _ResultTooLarge(ValueError):
    pass


def run_collectors(
    targets: Sequence[CollectorTarget],
    context: Mapping[str, object],
    *,
    global_timeout: float = MAX_GLOBAL_SECONDS,
    worker_timeout: float = MAX_WORKER_SECONDS,
) -> list[WorkerOutcome]:
    """Run collectors one at a time, enforcing per-worker and global deadlines.

    Collector functions must be importable module-level functions accepting one
    JSON-compatible context mapping. They may return JSON-compatible data or a
    Pydantic-style object with ``model_dump(mode="json")``.
    """
    _validate_timeout("global_timeout", global_timeout, MAX_GLOBAL_SECONDS)
    _validate_timeout("worker_timeout", worker_timeout, MAX_WORKER_SECONDS)
    _validate_targets(targets)
    context_json = _encode_json(dict(context), MAX_CONTEXT_BYTES)
    safe_context = json.loads(context_json)

    started = time.monotonic()
    global_deadline = started + global_timeout
    outcomes: list[WorkerOutcome] = []
    for target in targets:
        now = time.monotonic()
        if now >= global_deadline:
            outcomes.append(
                WorkerOutcome(
                    target.collector_id,
                    "skipped",
                    None,
                    "global_deadline",
                    "collector was not started before the global deadline",
                    now,
                    now,
                )
            )
            continue

        deadline = min(global_deadline, now + worker_timeout)
        worker_context = dict(safe_context)
        worker_context["deadline_monotonic"] = deadline
        worker_context["global_deadline_monotonic"] = global_deadline
        outcomes.append(_run_one(target, worker_context, deadline))

    return outcomes


def _run_one(target: CollectorTarget, context: dict[str, object], deadline: float) -> WorkerOutcome:
    started = time.monotonic()
    remaining = deadline - started
    if remaining <= 0:
        return _failure(target.collector_id, "skipped", "global_deadline", started)

    mp_context = multiprocessing.get_context("spawn")
    receive_pipe, send_pipe = mp_context.Pipe(duplex=False)
    process = mp_context.Process(
        target=_worker_entry,
        args=(send_pipe, target.module, target.function, context, deadline),
        name=f"infralens-{target.collector_id}",
    )
    try:
        process.start()
    except (OSError, RuntimeError, ValueError):
        receive_pipe.close()
        send_pipe.close()
        return _failure(
            target.collector_id,
            "collection_error",
            "worker_error",
            started,
            "worker could not be started",
        )
    finally:
        if process.pid is not None:
            send_pipe.close()

    message: bytes | None = None
    too_large = False
    timed_out = False
    worker_exitcode: int | None = None
    try:
        while time.monotonic() < deadline:
            if receive_pipe.poll(min(POLL_SECONDS, max(0.0, deadline - time.monotonic()))):
                try:
                    message = receive_pipe.recv_bytes(MAX_WORKER_RESULT_BYTES)
                except OSError:
                    too_large = True
                except EOFError:
                    pass
                break
            if not process.is_alive():
                break

        if message is not None:
            process.join(timeout=max(0.0, deadline - time.monotonic()))
            if process.is_alive():
                timed_out = True
                _stop_process(process)
        elif process.is_alive():
            timed_out = True
            _stop_process(process)
        else:
            process.join(timeout=0)
    finally:
        receive_pipe.close()
        if process.is_alive():
            timed_out = True
            _stop_process(process)
        worker_exitcode = process.exitcode
        if not process.is_alive():
            process.close()

    finished = time.monotonic()
    if timed_out:
        return WorkerOutcome(
            target.collector_id,
            "collection_error",
            None,
            "timeout",
            "collector exceeded its deadline",
            started,
            finished,
        )
    if too_large:
        return WorkerOutcome(
            target.collector_id,
            "collection_error",
            None,
            "worker_error",
            "worker result exceeded the IPC size limit",
            started,
            finished,
        )
    if message is None:
        if finished >= deadline:
            return WorkerOutcome(
                target.collector_id,
                "collection_error",
                None,
                "timeout",
                "collector exceeded its deadline",
                started,
                finished,
            )
        return WorkerOutcome(
            target.collector_id,
            "collection_error",
            None,
            "worker_error",
            "worker exited without returning a result",
            started,
            finished,
        )

    try:
        envelope = json.loads(message)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return WorkerOutcome(
            target.collector_id,
            "collection_error",
            None,
            "worker_error",
            "worker returned an invalid result envelope",
            started,
            finished,
        )
    if not isinstance(envelope, dict):
        return WorkerOutcome(
            target.collector_id,
            "collection_error",
            None,
            "worker_error",
            "worker returned an invalid result envelope",
            started,
            finished,
        )
    if envelope.get("ok") is True:
        if worker_exitcode != 0:
            return WorkerOutcome(
                target.collector_id,
                "collection_error",
                None,
                "worker_error",
                "worker exited unsuccessfully after returning a result",
                started,
                finished,
            )
        return WorkerOutcome(
            target.collector_id, "ok", envelope["value"], None, None, started, finished
        )
    return WorkerOutcome(
        target.collector_id,
        "collection_error",
        None,
        "worker_error",
        envelope.get("message", "collector failed"),
        started,
        finished,
    )


def _worker_entry(
    connection: Connection,
    module_name: str,
    function_name: str,
    context: dict[str, object],
    deadline: float,
) -> None:
    try:
        os.setsid()
        _set_address_space_limit()
        if time.monotonic() >= deadline:
            _send_envelope(connection, {"ok": False, "message": "collector deadline expired"})
            return

        module = __import__(module_name, fromlist=[function_name])
        collector = getattr(module, function_name)
        value = collector(context)
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json")
        encoded_value = _encode_json(value, MAX_WORKER_RESULT_BYTES)
        envelope = b'{"ok":true,"value":' + encoded_value + b"}"
        if len(envelope) > MAX_WORKER_RESULT_BYTES:
            raise _ResultTooLarge
        connection.send_bytes(envelope)
    except _ResultTooLarge:
        _send_envelope(
            connection, {"ok": False, "message": "worker result exceeded the IPC size limit"}
        )
    except Exception:
        _send_envelope(connection, {"ok": False, "message": "collector raised an unexpected error"})
    finally:
        connection.close()


def _set_address_space_limit() -> None:
    import resource

    current_soft, current_hard = resource.getrlimit(resource.RLIMIT_AS)
    limit = WORKER_ADDRESS_SPACE_BYTES
    if current_hard != resource.RLIM_INFINITY:
        limit = min(limit, current_hard)
    if current_soft != resource.RLIM_INFINITY:
        limit = min(limit, current_soft)
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def _send_envelope(connection: Connection, envelope: dict[str, object]) -> None:
    try:
        connection.send_bytes(_encode_json(envelope, MAX_WORKER_RESULT_BYTES))
    except (BrokenPipeError, OSError, _ResultTooLarge):
        pass


def _encode_json(value: object, byte_limit: int) -> bytes:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    encoder = json.JSONEncoder(allow_nan=False, ensure_ascii=False, separators=(",", ":"))
    chunks: list[bytes] = []
    total = 0
    for part in encoder.iterencode(value):
        encoded = part.encode("utf-8")
        total += len(encoded)
        if total > byte_limit:
            raise _ResultTooLarge
        chunks.append(encoded)
    return b"".join(chunks)


def _validate_targets(targets: Sequence[CollectorTarget]) -> None:
    if isinstance(targets, (str, bytes)):
        raise ValueError("targets must be a sequence of collector targets")
    ids: set[str] = set()
    for target in targets:
        if not isinstance(target, CollectorTarget):
            raise ValueError("each target must be a CollectorTarget")
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", target.collector_id):
            raise ValueError("collector id must be a lowercase identifier")
        if target.collector_id in ids:
            raise ValueError("collector ids must be unique")
        ids.add(target.collector_id)
        if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", target.module):
            raise ValueError("collector module must be a dotted Python module name")
        if not re.fullmatch(r"[A-Za-z_]\w*", target.function):
            raise ValueError("collector function must be a Python identifier")


def _validate_timeout(name: str, value: float, maximum: float) -> None:
    if not isinstance(value, (float, int)) or isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    if not math.isfinite(value) or not 0 < value <= maximum:
        raise ValueError(f"{name} must be greater than zero and at most {maximum:g} seconds")


def _failure(
    collector_id: str,
    state: WorkerState,
    error_code: WorkerErrorCode,
    started: float,
    message: str | None = None,
) -> WorkerOutcome:
    finished = time.monotonic()
    return WorkerOutcome(
        collector_id,
        state,
        None,
        error_code,
        message or "collector was not started before its deadline",
        started,
        finished,
    )


def _stop_process(process: multiprocessing.Process) -> None:
    if process.pid is None:
        return
    try:
        if os.getpgid(process.pid) == process.pid:
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except (ProcessLookupError, PermissionError):
        process.terminate()
    process.join(timeout=CLEANUP_SECONDS)
    if process.is_alive():
        try:
            if os.getpgid(process.pid) == process.pid:
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.join(timeout=CLEANUP_SECONDS)
