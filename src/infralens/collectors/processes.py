"""Collect a bounded, minimal inventory of visible local processes."""

from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Literal

import psutil
from pydantic import BaseModel, ConfigDict

from infralens.models import (
    CollectionError,
    Collector,
    Evidence,
    EvidenceSource,
    Limitation,
    ProcessAttributes,
    ProcessEntity,
)

MAX_PROCESSES = 10_000
PROCESS_SCOPE = "Processes visible to this user in the current namespace"


class ProcessCollectionResult(BaseModel):
    """Normalized process data ready for later snapshot assembly."""

    model_config = ConfigDict(extra="forbid", strict=True)

    collector: Collector
    entities: list[ProcessEntity]
    evidence: list[Evidence]
    limitations: list[Limitation]


def collect(_context: Mapping[str, object]) -> ProcessCollectionResult:
    """Read only process identity fields; never inspect argv, environment, or files."""
    started_at = datetime.now(UTC)
    errors: list[CollectionError] = []
    limitations: list[Limitation] = []
    records: dict[int, dict[str, object | None]] = {}
    field_issues: dict[int, list[str]] = {}
    truncated = False

    try:
        iterator = iter(psutil.process_iter())
    except psutil.AccessDenied:
        errors.append(_error("permission_denied"))
        iterator = iter(())
    except (OSError, psutil.Error, TypeError):
        errors.append(_error("io_error"))
        iterator = iter(())

    for index in range(MAX_PROCESSES + 1):
        try:
            process = next(iterator)
        except StopIteration:
            break
        except psutil.AccessDenied:
            _append_error_once(errors, _error("permission_denied"))
            break
        except (OSError, psutil.Error):
            _append_error_once(errors, _error("io_error"))
            break

        if index == MAX_PROCESSES:
            truncated = True
            break

        try:
            pid = process.pid
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            limitations.append(_limitation("process disappeared before its PID was read"))
            continue
        except psutil.AccessDenied:
            _append_error_once(errors, _error("permission_denied"))
            limitations.append(_limitation("process PID is unavailable"))
            continue
        except (OSError, psutil.Error, AttributeError, TypeError):
            _append_error_once(errors, _error("io_error"))
            limitations.append(_limitation("process PID is unavailable"))
            continue
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            _append_error_once(errors, _error("parse_error"))
            limitations.append(_limitation("process PID is invalid"))
            continue
        if pid in records:
            _append_error_once(errors, _error("parse_error"))
            limitations.append(_limitation("duplicate process PID was omitted"))
            continue

        record: dict[str, object | None] = {"pid": pid}
        for field_name, operation in (
            ("started_at", _read_started_at),
            ("name", _read_name),
            ("uid", _read_uid),
        ):
            value, error_code = operation(process)
            record[field_name] = value
            if error_code is not None:
                if error_code == "disappeared":
                    field_issues.setdefault(pid, []).append(field_name)
                else:
                    _append_error_once(errors, _error(error_code))
                    field_issues.setdefault(pid, []).append(field_name)
            elif value is None:
                field_issues.setdefault(pid, []).append(field_name)
        records[pid] = record

    ordered_records = [records[pid] for pid in sorted(records)]
    entities: list[ProcessEntity] = []
    evidence: list[Evidence] = []
    for index, record in enumerate(ordered_records, start=1):
        entity_id = f"process:{index}"
        pid = record["pid"]
        limitations.extend(
            _process_limitation(field_name, entity_id) for field_name in field_issues.get(pid, [])
        )
        attributes = ProcessAttributes(
            pid=pid,
            started_at=record["started_at"],
            name=record["name"],
            uid=record["uid"],
        )
        fields: dict[str, str | int] = {"pid": attributes.pid}
        if attributes.started_at is not None:
            fields["started_at"] = _format_timestamp(attributes.started_at)
        if attributes.name is not None:
            fields["name"] = attributes.name
        if attributes.uid is not None:
            fields["uid"] = attributes.uid
        item = Evidence(
            id=f"e:{index}",
            collector_id="processes",
            collected_at=datetime.now(UTC),
            source=EvidenceSource(type="api", name="psutil.process_iter"),
            subject_id=entity_id,
            claim="observed",
            fields=fields,
            limitations=[],
        )
        evidence.append(item)
        entities.append(
            ProcessEntity(
                id=entity_id,
                kind="process",
                attributes=attributes,
                evidence_ids=[item.id],
            )
        )

    if truncated:
        limitations.append(
            Limitation(
                code="process_limit_reached",
                message=f"Process collection was limited to {MAX_PROCESSES} entries.",
            )
        )
    if not entities and not errors:
        limitations.append(
            Limitation(
                code="processes_unavailable",
                message="No process records were available to establish complete coverage.",
            )
        )

    status = _collector_status(errors)
    if not entities and errors:
        coverage: Literal["complete", "partial", "none"] = "none"
    elif errors or limitations or truncated:
        coverage = "partial"
    else:
        coverage = "complete"
    finished_at = datetime.now(UTC)
    collector = Collector(
        id="processes",
        status=status,
        coverage=coverage,
        scope=PROCESS_SCOPE,
        started_at=started_at,
        finished_at=finished_at,
        entity_ids=[item.id for item in entities],
        evidence_ids=[item.id for item in evidence],
        errors=errors,
        limitations=limitations,
        truncated=truncated,
    )
    return ProcessCollectionResult(
        collector=collector,
        entities=entities,
        evidence=evidence,
        limitations=limitations,
    )


def _read_started_at(process: object) -> tuple[datetime | None, str | None]:
    try:
        value = process.create_time()
    except psutil.AccessDenied:
        return None, "permission_denied"
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None, "disappeared"
    except (OSError, psutil.Error, AttributeError, TypeError):
        return None, "io_error"
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None, "parse_error"
    try:
        return datetime.fromtimestamp(value, UTC), None
    except (OverflowError, OSError, ValueError):
        return None, "parse_error"


def _read_name(process: object) -> tuple[str | None, str | None]:
    try:
        value = process.name()
    except psutil.AccessDenied:
        return None, "permission_denied"
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None, "disappeared"
    except (OSError, psutil.Error, AttributeError, TypeError):
        return None, "io_error"
    if (
        not isinstance(value, str)
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return None, "parse_error"
    return value, None


def _read_uid(process: object) -> tuple[int | None, str | None]:
    try:
        value = process.uids().real
    except psutil.AccessDenied:
        return None, "permission_denied"
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None, "disappeared"
    except (OSError, psutil.Error, AttributeError, TypeError):
        return None, "io_error"
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None, "parse_error"
    return value, None


def _format_timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _error(code: Literal["permission_denied", "io_error", "parse_error"]) -> CollectionError:
    message = {
        "permission_denied": "Permission denied while reading process metadata.",
        "io_error": "Process metadata could not be read.",
        "parse_error": "Process metadata did not match the expected format.",
    }[code]
    return CollectionError(code=code, operation="process_iter", message=message)


def _append_error_once(errors: list[CollectionError], error: CollectionError) -> None:
    if not any(item.code == error.code and item.operation == error.operation for item in errors):
        errors.append(error)


def _limitation(message: str) -> Limitation:
    return Limitation(code="process_unavailable", message=message)


def _process_limitation(field_name: str, subject_id: str) -> Limitation:
    return Limitation(
        code="process_field_unavailable",
        message=f"Process field {field_name} is unavailable or invalid.",
        subject_id=subject_id,
    )


def _collector_status(
    errors: list[CollectionError],
) -> Literal["ok", "permission_denied", "collection_error"]:
    if any(item.code != "permission_denied" for item in errors):
        return "collection_error"
    if errors:
        return "permission_denied"
    return "ok"
