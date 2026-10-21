"""Importable collector functions used to test spawn-based worker isolation."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path


def return_context(context: dict[str, object]) -> dict[str, object]:
    return {
        "value": context.get("value"),
        "pid": os.getpid(),
        "worker_deadline": context.get("deadline_monotonic"),
        "global_deadline": context.get("global_deadline_monotonic"),
    }


def raise_unexpected_error(_context: dict[str, object]) -> None:
    raise RuntimeError("sensitive diagnostic must not escape the worker")


def sleep_forever(_context: dict[str, object]) -> None:
    time.sleep(60)


def return_large_result(context: dict[str, object]) -> dict[str, str]:
    return {"payload": "x" * int(context["size"])}


def report_address_space_limit(_context: dict[str, object]) -> dict[str, int]:
    import resource

    soft, _ = resource.getrlimit(resource.RLIMIT_AS)
    return {"soft_limit": soft}


def spawn_descendant_and_sleep(context: dict[str, object]) -> None:
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    Path(str(context["pid_path"])).write_text(str(child.pid), encoding="ascii")
    time.sleep(60)
