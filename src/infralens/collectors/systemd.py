"""Collect bounded loaded-service state through the allowlisted systemctl runner."""

from __future__ import annotations

import re
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import psutil
from pydantic import BaseModel, ConfigDict, ValidationError

from infralens.models import (
    CollectionError,
    Collector,
    Evidence,
    EvidenceSource,
    Limitation,
    ProcessEntity,
    Relation,
    ServiceAttributes,
    ServiceEntity,
)
from infralens.runner import CommandResult, run_command

MAX_SERVICES = 2_000
MAX_LIST_STDOUT_BYTES = 1024 * 1024
MAX_SHOW_STDOUT_BYTES = 8 * 1024
MAX_COMMAND_SECONDS = 2.0
MAX_WORKER_SECONDS = 5.0
SYSTEMD_RUNTIME = Path("/run/systemd/system")
SERVICE_SCOPE = "Loaded service units returned by the system manager"
_UNIT_CHARACTER = r"[A-Za-z0-9:_.@-]"
_UNIT_NAME = re.compile(rf"^(?:{_UNIT_CHARACTER}|\\x[0-9a-fA-F]{{2}})+\.service$")
_PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "MainPID")


class SystemdCollectionResult(BaseModel):
    """Normalized service entities, command evidence, and verified process links."""

    model_config = ConfigDict(extra="forbid", strict=True)

    collector: Collector
    entities: list[ServiceEntity]
    evidence: list[Evidence]
    relations: list[Relation]
    limitations: list[Limitation]


def collect(context: Mapping[str, object]) -> SystemdCollectionResult:
    """Read loaded service units and allowlisted state properties without mutating them."""
    started_at = datetime.now(UTC)
    deadline = _worker_deadline(context)
    errors: list[CollectionError] = []
    limitations: list[Limitation] = []

    version_result = _run(["systemctl", "--version"], deadline, 4096)
    if version_result.error == "executable_not_found":
        return _unsupported(started_at, "systemctl is not installed.")
    if not version_result.succeeded:
        return _failed_result(
            started_at,
            _command_error("systemctl_detect", version_result),
        )

    try:
        SYSTEMD_RUNTIME.stat()
    except FileNotFoundError:
        return _unsupported(started_at, "No systemd manager runtime is present.")
    except OSError:
        return _failed_result(started_at, _error("io_error", "systemctl_detect"))

    if time.monotonic() >= deadline:
        errors.append(_error("timeout", "systemctl_list_units"))
        return _result(
            started_at,
            [],
            [],
            errors,
            [
                Limitation(
                    code="deadline_reached",
                    message="Service collection exceeded its worker deadline.",
                )
            ],
            False,
        )

    list_result = _run(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--all",
            "--plain",
            "--no-legend",
            "--no-pager",
        ],
        deadline,
        MAX_LIST_STDOUT_BYTES,
    )
    if not list_result.succeeded:
        return _failed_result(
            started_at,
            _command_error("systemctl_list_units", list_result),
            truncated=list_result.stdout_truncated,
        )

    unit_names, invalid_names = _parse_unit_names(list_result.stdout)
    if invalid_names:
        errors.append(_error("parse_error", "systemctl_list_units"))
    if list_result.stdout_truncated:
        errors.append(_error("parse_error", "systemctl_list_units"))
        limitations.append(
            Limitation(
                code="systemctl_output_truncated",
                message="The service list exceeded its output limit.",
            )
        )
    truncated = len(unit_names) > MAX_SERVICES or list_result.stdout_truncated
    if len(unit_names) > MAX_SERVICES:
        limitations.append(
            Limitation(
                code="service_limit_reached",
                message=f"Service collection was limited to {MAX_SERVICES} units.",
            )
        )
        unit_names = unit_names[:MAX_SERVICES]

    process_entities, invalid_process_context = _process_entities(context.get("processes"))
    if invalid_process_context:
        limitations.append(
            Limitation(
                code="process_context_unavailable",
                message="Process observations were unavailable for MainPID ownership checks.",
            )
        )

    records: list[tuple[ServiceAttributes, list[Evidence]]] = []
    relations: list[Relation] = []
    evidence_number = 1
    for unit_name in unit_names:
        if time.monotonic() >= deadline:
            _append_error_once(errors, _error("timeout", "systemctl_show"))
            limitations.append(
                Limitation(
                    code="deadline_reached",
                    message="Remaining service units were not read before the worker deadline.",
                )
            )
            truncated = True
            break
        show_result = _show(unit_name, deadline)
        if not show_result.succeeded:
            _append_error_once(errors, _command_error("systemctl_show", show_result))
            continue
        if show_result.stdout_truncated:
            _append_error_once(errors, _error("parse_error", "systemctl_show"))
            continue
        parsed, parse_error = _parse_show(show_result.stdout)
        if parsed is None:
            if parse_error:
                _append_error_once(errors, _error("parse_error", "systemctl_show"))
            continue
        if parse_error:
            _append_error_once(errors, _error("parse_error", "systemctl_show"))
        attributes, unit_id = parsed
        if unit_id != unit_name:
            _append_error_once(errors, _error("parse_error", "systemctl_show"))
            continue

        entity_id = f"service:{len(records) + 1}"
        list_evidence = _evidence(
            evidence_number,
            "systemctl.list-units",
            entity_id,
            {"name": attributes.name},
        )
        evidence_number += 1
        show_fields: dict[str, str | int | None] = {
            "name": attributes.name,
            "load_state": attributes.load_state,
            "active_state": attributes.active_state,
            "sub_state": attributes.sub_state,
            "main_pid": attributes.main_pid,
        }
        show_evidence = _evidence(
            evidence_number,
            "systemctl.show",
            entity_id,
            show_fields,
        )
        evidence_number += 1
        if parse_error:
            limitations.append(
                Limitation(
                    code="service_field_unavailable",
                    message="Service field main_pid is unavailable or invalid.",
                    subject_id=entity_id,
                )
            )
        records.append((attributes, [list_evidence, show_evidence]))

        if attributes.main_pid is None:
            continue
        process = process_entities.get(attributes.main_pid)
        if process is None or process.attributes.started_at is None:
            limitations.append(
                Limitation(
                    code="service_main_process_unverified",
                    message="Service MainPID could not be verified against process observations.",
                    subject_id=entity_id,
                )
            )
            continue
        verified, verify_error = _revalidate_service_main_pid(
            unit_name,
            attributes,
            process,
            deadline,
        )
        if verify_error is not None:
            _append_error_once(errors, verify_error)
        if verified:
            relations.append(
                Relation(
                    id=f"r:{len(relations) + 1}",
                    type="main_process",
                    from_id=entity_id,
                    to_id=process.id,
                    claim="observed",
                    evidence_ids=[show_evidence.id],
                    rationale_code="main_pid_revalidated",
                )
            )
        else:
            limitations.append(
                Limitation(
                    code="service_main_process_unverified",
                    message="Service MainPID or process start time changed during verification.",
                    subject_id=entity_id,
                )
            )

    errors = _deduplicate_errors(errors)
    return _result(started_at, records, relations, errors, limitations, truncated)


def _run(argv: list[str], deadline: float, stdout_limit: int) -> CommandResult:
    return run_command(argv, min(deadline, time.monotonic() + MAX_COMMAND_SECONDS), stdout_limit)


def _show(unit_name: str, deadline: float) -> CommandResult:
    return _run(
        [
            "systemctl",
            "show",
            f"--property={','.join(_PROPERTIES)}",
            "--",
            unit_name,
        ],
        deadline,
        MAX_SHOW_STDOUT_BYTES,
    )


def _parse_unit_names(output: bytes) -> tuple[list[str], bool]:
    names: set[str] = set()
    invalid = False
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError:
        return [], True
    for line in text.splitlines():
        tokens = line.split(maxsplit=1)
        if not tokens:
            continue
        name = tokens[0]
        if not name.endswith(".service"):
            continue
        if len(name) > 256 or not _UNIT_NAME.fullmatch(name):
            invalid = True
            continue
        names.add(name)
    return sorted(names), invalid


def _parse_show(output: bytes) -> tuple[tuple[ServiceAttributes, str] | None, bool]:
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError:
        return None, True
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in _PROPERTIES:
            if key in values:
                return None, True
            values[key] = value
    unit_id = values.get("Id")
    load_state = values.get("LoadState")
    active_state = values.get("ActiveState")
    sub_state = values.get("SubState")
    if (
        not unit_id
        or len(unit_id) > 256
        or not _UNIT_NAME.fullmatch(unit_id)
        or not load_state
        or not active_state
        or not sub_state
    ):
        return None, True
    main_pid_text = values.get("MainPID")
    if main_pid_text is None:
        main_pid = None
        parse_error = True
    elif not main_pid_text.isdecimal() or len(main_pid_text) > 10:
        main_pid = None
        parse_error = True
    else:
        pid_value = int(main_pid_text)
        if pid_value > 2_147_483_647:
            main_pid = None
            parse_error = True
        else:
            main_pid = pid_value or None
            parse_error = False
    try:
        attributes = ServiceAttributes(
            name=unit_id,
            load_state=load_state,
            active_state=active_state,
            sub_state=sub_state,
            main_pid=main_pid,
        )
    except (ValidationError, ValueError):
        return None, True
    return (attributes, unit_id), parse_error


def _revalidate_service_main_pid(
    unit_name: str,
    expected: ServiceAttributes,
    process: ProcessEntity,
    deadline: float,
) -> tuple[bool, CollectionError | None]:
    refreshed = _show(unit_name, deadline)
    if not refreshed.succeeded:
        return False, _command_error("systemctl_show", refreshed)
    if refreshed.stdout_truncated:
        return False, _error("parse_error", "systemctl_show")
    parsed, parse_error = _parse_show(refreshed.stdout)
    if parse_error or parsed is None:
        return False, _error("parse_error", "systemctl_show")
    current, _ = parsed
    if (
        current.name != expected.name
        or current.load_state != expected.load_state
        or current.main_pid != expected.main_pid
        or current.active_state != expected.active_state
        or current.sub_state != expected.sub_state
    ):
        return False, None
    try:
        current_start = datetime.fromtimestamp(
            psutil.Process(process.attributes.pid).create_time(), UTC
        )
    except psutil.AccessDenied:
        return False, _error("permission_denied", "systemctl_show")
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return False, None
    except (OSError, psutil.Error, OverflowError, ValueError, TypeError):
        return False, _error("io_error", "systemctl_show")
    return current_start == process.attributes.started_at, None


def _process_entities(value: object) -> tuple[dict[int, ProcessEntity], bool]:
    if value is None:
        return {}, False
    if isinstance(value, Mapping):
        value = value.get("entities")
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return {}, True
    entities: dict[int, ProcessEntity] = {}
    invalid = False
    for item in value:
        try:
            entity = ProcessEntity.model_validate(item)
        except (ValidationError, TypeError):
            invalid = True
            continue
        if entity.attributes.pid in entities:
            invalid = True
            continue
        entities[entity.attributes.pid] = entity
    return entities, invalid


def _worker_deadline(context: Mapping[str, object]) -> float:
    value = context.get("deadline_monotonic")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return time.monotonic() + MAX_WORKER_SECONDS


def _unsupported(started_at: datetime, message: str) -> SystemdCollectionResult:
    limitation = Limitation(code="runtime_absent", message=message)
    return _result(started_at, [], [], [], [limitation], False, status_override="unsupported")


def _failed_result(
    started_at: datetime,
    error: CollectionError,
    *,
    truncated: bool = False,
) -> SystemdCollectionResult:
    return _result(started_at, [], [], [error], [], truncated)


def _result(
    started_at: datetime,
    records: list[tuple[ServiceAttributes, list[Evidence]]],
    relations: list[Relation],
    errors: list[CollectionError],
    limitations: list[Limitation],
    truncated: bool,
    *,
    status_override: Literal["unsupported"] | None = None,
) -> SystemdCollectionResult:
    entities: list[ServiceEntity] = []
    evidence: list[Evidence] = []
    for index, (attributes, entity_evidence) in enumerate(records, start=1):
        entity_id = f"service:{index}"
        evidence.extend(entity_evidence)
        entities.append(
            ServiceEntity(
                id=entity_id,
                kind="service",
                attributes=attributes,
                evidence_ids=[item.id for item in entity_evidence],
            )
        )

    normalized_relations = [
        relation
        for relation in relations
        if int(relation.from_id.split(":", maxsplit=1)[1]) <= len(entities)
    ]
    status = status_override or _collector_status(errors)
    if status == "unsupported":
        coverage: Literal["complete", "partial", "none"] = "none"
    elif errors and not entities:
        coverage = "none"
    elif errors or limitations or truncated:
        coverage = "partial"
    else:
        coverage = "complete"
    finished_at = datetime.now(UTC)
    collector = Collector(
        id="systemd",
        status=status,
        coverage=coverage,
        scope=SERVICE_SCOPE,
        started_at=started_at,
        finished_at=finished_at,
        entity_ids=[item.id for item in entities],
        evidence_ids=[item.id for item in evidence],
        errors=errors,
        limitations=limitations,
        truncated=truncated,
    )
    return SystemdCollectionResult(
        collector=collector,
        entities=entities,
        evidence=evidence,
        relations=normalized_relations,
        limitations=limitations,
    )


def _evidence(
    evidence_number: int,
    source_name: Literal["systemctl.list-units", "systemctl.show"],
    subject_id: str,
    fields: dict[str, str | int | None],
) -> Evidence:
    return Evidence(
        id=f"e:{evidence_number}",
        collector_id="systemd",
        collected_at=datetime.now(UTC),
        source=EvidenceSource(type="command", name=source_name),
        subject_id=subject_id,
        claim="observed",
        fields=fields,
        limitations=[],
    )


def _command_error(operation: str, result: CommandResult) -> CollectionError:
    if result.timed_out:
        code: Literal["permission_denied", "timeout", "command_failed", "io_error"] = "timeout"
    elif result.error == "permission_denied":
        code = "permission_denied"
    elif result.error is not None:
        code = "io_error"
    else:
        code = "command_failed"
    return CollectionError(
        code=code,
        operation=operation,
        message="systemctl could not return the requested service metadata.",
        errno=result.errno_value,
        exit_code=result.returncode,
    )


def _error(
    code: Literal["permission_denied", "timeout", "command_failed", "parse_error", "io_error"],
    operation: Literal["systemctl_detect", "systemctl_list_units", "systemctl_show"],
) -> CollectionError:
    message = {
        "permission_denied": "Permission denied while reading systemd metadata.",
        "timeout": "systemctl exceeded its command deadline.",
        "command_failed": "systemctl could not return the requested metadata.",
        "parse_error": "systemctl output did not match the expected format.",
        "io_error": "systemd metadata could not be read.",
    }[code]
    return CollectionError(code=code, operation=operation, message=message)


def _append_error_once(errors: list[CollectionError], error: CollectionError) -> None:
    if not any(item.code == error.code and item.operation == error.operation for item in errors):
        errors.append(error)


def _deduplicate_errors(errors: list[CollectionError]) -> list[CollectionError]:
    result: list[CollectionError] = []
    for error in errors:
        _append_error_once(result, error)
    return result


def _collector_status(
    errors: list[CollectionError],
) -> Literal["ok", "permission_denied", "collection_error"]:
    if any(item.code != "permission_denied" for item in errors):
        return "collection_error"
    if errors:
        return "permission_denied"
    return "ok"
