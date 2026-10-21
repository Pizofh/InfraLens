"""Private, atomic snapshot persistence and safe terminal summaries."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import unicodedata
from pathlib import Path
from typing import Any

from infralens.models import Snapshot

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_STRING_LENGTH = 4_096
_ANSI_ESCAPE = re.compile(r"\x1b(?:\][^\x07]*(?:\x07|\x1b\\)|\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])")


def write_snapshot(snapshot: Snapshot, path: str | Path, *, overwrite: bool = False) -> Path:
    """Validate and atomically persist a private UTF-8 JSON snapshot."""
    validated = Snapshot.model_validate(snapshot.model_dump(mode="python"))
    payload = validated.model_dump(mode="json")
    _check_string_lengths(payload)
    encoded = (json.dumps(payload, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode(
        "utf-8"
    )
    if len(encoded) > MAX_JSON_BYTES:
        raise ValueError("snapshot exceeds the 16 MiB JSON limit")

    destination = Path(path)
    if not destination.name or destination.name in {".", ".."}:
        raise ValueError("output path must name a file")
    parent = destination.parent
    if not stat.S_ISDIR(os.stat(parent, follow_symlinks=False).st_mode):
        raise NotADirectoryError("output parent is not a directory")
    _validate_destination(destination, overwrite=overwrite)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=parent
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())

        if overwrite:
            os.replace(temporary_path, destination)
        else:
            # A hard link publishes the already-complete file atomically and fails
            # if another writer created the destination after our initial check.
            os.link(temporary_path, destination, follow_symlinks=False)
            temporary_path.unlink()
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return destination


def format_summary(snapshot: Snapshot) -> str:
    """Format a concise summary while removing terminal control sequences."""
    validated = Snapshot.model_validate(snapshot.model_dump(mode="python"))
    collector_lines = [
        f"  {_terminal_text(item.id)}: "
        f"{_terminal_text(item.status)}/{_terminal_text(item.coverage)}"
        for item in validated.collectors
    ]
    state_counts = {state: 0 for state in ("triggered", "not_triggered", "not_evaluable")}
    for item in validated.assessment:
        state_counts[item.state] += 1

    lines = [
        f"InfraLens scan {_terminal_text(str(validated.scan_id))}",
        "Collectors:",
        *collector_lines,
        "Assessment: " + ", ".join(f"{state}={count}" for state, count in state_counts.items()),
        f"Findings: {len(validated.findings)}",
    ]
    for finding in validated.findings:
        severity = _terminal_text(finding.severity)
        rule = _terminal_text(finding.rule_id)
        subject = _terminal_text(finding.subject_id)
        message = _terminal_text(finding.message)
        action = _terminal_text(finding.review_action)
        lines.append(f"  [{severity}] {rule} ({subject}): {message} — {action}")
    return "\n".join(lines)


def _validate_destination(destination: Path, *, overwrite: bool) -> None:
    try:
        mode = destination.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISLNK(mode):
        raise ValueError("output destination must not be a symbolic link")
    if not stat.S_ISREG(mode):
        raise ValueError("output destination must be a regular file")
    if not overwrite:
        raise FileExistsError("output file already exists")


def _check_string_lengths(value: Any) -> None:
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise ValueError("snapshot contains a string longer than 4,096 characters")
    elif isinstance(value, dict):
        for key, item in value.items():
            _check_string_lengths(key)
            _check_string_lengths(item)
    elif isinstance(value, list):
        for item in value:
            _check_string_lengths(item)


def _terminal_text(value: str) -> str:
    without_ansi = _ANSI_ESCAPE.sub("", value)
    return "".join(char for char in without_ansi if unicodedata.category(char) != "Cc")
