"""Collect local TCP listeners and bound UDP sockets with cautious PID links."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Literal

import psutil
from pydantic import BaseModel, ConfigDict, ValidationError

from infralens.models import (
    CollectionError,
    Collector,
    Evidence,
    EvidenceSource,
    Limitation,
    Relation,
    SocketAttributes,
    SocketEntity,
)
from infralens.process_refs import ProcessReference

MAX_SOCKETS = 20_000
MAX_SOCKET_RESULT_BYTES = 7 * 1024 * 1024
SOCKET_SCOPE = "TCP LISTEN and UDP bound sockets visible in the current network namespace"


class SocketCollectionResult(BaseModel):
    """Normalized socket records, evidence, limitations, and verified relations."""

    model_config = ConfigDict(extra="forbid", strict=True)

    collector: Collector
    entities: list[SocketEntity]
    evidence: list[Evidence]
    relations: list[Relation]
    limitations: list[Limitation]


def collect(context: Mapping[str, object]) -> SocketCollectionResult:
    """Collect listeners without querying connection payloads or remote endpoints."""
    started_at = datetime.now(UTC)
    errors: list[CollectionError] = []
    limitations: list[Limitation] = []
    try:
        raw_connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        errors.append(_error("permission_denied"))
        raw_connections = []
    except (OSError, psutil.Error, ValueError):
        errors.append(_error("io_error"))
        raw_connections = []

    connections, truncated, parse_failures = _normalize_connections(raw_connections)
    if parse_failures:
        errors.append(_error("parse_error"))
    if truncated:
        limitations.append(
            Limitation(
                code="socket_limit_reached",
                message=f"Socket collection was limited to {MAX_SOCKETS} entries.",
            )
        )

    process_entities, process_context_invalid = _process_entities(context.get("processes"))
    if process_context_invalid:
        limitations.append(
            Limitation(
                code="process_context_unavailable",
                message="Process observations were unavailable for socket ownership checks.",
            )
        )

    if not _is_root():
        limitations.append(
            Limitation(
                code="visibility_not_guaranteed",
                message="Socket visibility may be limited without elevated privileges.",
            )
        )

    entities: list[SocketEntity] = []
    evidence: list[Evidence] = []
    relations: list[Relation] = []
    for index, record in enumerate(connections, start=1):
        entity_id = f"socket:{index}"
        attributes = SocketAttributes(**record)
        item = Evidence(
            id=f"e:{index}",
            collector_id="sockets",
            collected_at=datetime.now(UTC),
            source=EvidenceSource(type="api", name="psutil.net_connections"),
            subject_id=entity_id,
            claim="observed",
            fields={
                "protocol": attributes.protocol,
                "family": attributes.family,
                "local_address": attributes.local_address,
                "local_port": attributes.local_port,
                "state": attributes.state,
                "pid": attributes.pid,
                "scope_id": attributes.scope_id,
            },
            limitations=[],
        )
        entity = SocketEntity(
            id=entity_id,
            kind="socket",
            attributes=attributes,
            evidence_ids=[item.id],
        )
        entities.append(entity)
        evidence.append(item)

        if (
            attributes.family == "ipv6"
            and ipaddress.IPv6Address(attributes.local_address).is_link_local
            and attributes.scope_id is None
        ):
            limitations.append(
                Limitation(
                    code="socket_scope_unknown",
                    message="IPv6 link-local socket scope could not be identified.",
                    subject_id=entity_id,
                )
            )

        if attributes.pid is None:
            limitations.append(
                Limitation(
                    code="socket_pid_unavailable",
                    message="Socket owner PID was not observable.",
                    subject_id=entity_id,
                )
            )
            continue
        process = process_entities.get(attributes.pid)
        if process is None:
            limitations.append(
                Limitation(
                    code="socket_owner_unverified",
                    message=(
                        "Socket process ownership could not be verified against process "
                        "observations."
                    ),
                    subject_id=entity_id,
                )
            )
            continue
        validation, code = _revalidate_process(attributes.pid, process.started_at)
        if code is not None:
            if code == "permission_denied":
                _append_error_once(errors, _error(code))
            elif code == "io_error":
                _append_error_once(errors, _error(code))
            limitations.append(
                Limitation(
                    code="socket_owner_unverified",
                    message="Socket process ownership changed or could not be revalidated.",
                    subject_id=entity_id,
                )
            )
            continue
        if validation:
            relations.append(
                Relation(
                    id=f"r:{len(relations) + 1}",
                    type="owned_by",
                    from_id=entity_id,
                    to_id=process.id,
                    claim="observed",
                    evidence_ids=[item.id],
                    rationale_code="pid_create_time_match",
                )
            )

    return _bounded_result(
        started_at,
        entities,
        evidence,
        relations,
        errors,
        limitations,
        truncated,
    )


def _bounded_result(
    started_at: datetime,
    entities: list[SocketEntity],
    evidence: list[Evidence],
    relations: list[Relation],
    errors: list[CollectionError],
    limitations: list[Limitation],
    truncated: bool,
) -> SocketCollectionResult:
    base_truncated = truncated
    low = 0
    high = len(entities)
    best: SocketCollectionResult | None = None
    while low <= high:
        keep = (low + high) // 2
        omitted = keep < len(entities)
        kept_entities = entities[:keep]
        kept_ids = {entity.id for entity in kept_entities}
        kept_evidence = evidence[:keep]
        kept_relations = [relation for relation in relations if relation.from_id in kept_ids]
        kept_limitations = [
            limitation
            for limitation in limitations
            if limitation.subject_id is None or limitation.subject_id in kept_ids
        ]
        if omitted:
            kept_limitations.append(
                Limitation(
                    code="socket_result_size_limit",
                    message=f"Socket output was limited to fit {MAX_SOCKET_RESULT_BYTES} bytes.",
                )
            )
        is_truncated = base_truncated or omitted
        status = _collector_status(errors)
        if errors and not kept_entities:
            coverage: Literal["complete", "partial", "none"] = "none"
        elif errors or kept_limitations or is_truncated:
            coverage = "partial"
        else:
            coverage = "complete"
        finished_at = datetime.now(UTC)
        collector = Collector(
            id="sockets",
            status=status,
            coverage=coverage,
            scope=SOCKET_SCOPE,
            started_at=started_at,
            finished_at=finished_at,
            entity_ids=[entity.id for entity in kept_entities],
            evidence_ids=[item.id for item in kept_evidence],
            errors=errors,
            limitations=kept_limitations,
            truncated=is_truncated,
        )
        candidate = SocketCollectionResult(
            collector=collector,
            entities=kept_entities,
            evidence=kept_evidence,
            relations=kept_relations,
            limitations=kept_limitations,
        )
        encoded = json.dumps(
            candidate.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) <= MAX_SOCKET_RESULT_BYTES:
            best = candidate
            low = keep + 1
        else:
            high = keep - 1
    if best is None:
        raise RuntimeError("socket result metadata exceeds its serialization budget")
    return best


def _normalize_connections(
    raw_connections: object,
) -> tuple[list[dict[str, object]], bool, bool]:
    if not isinstance(raw_connections, Sequence) or isinstance(raw_connections, (str, bytes)):
        return [], False, True
    truncated = len(raw_connections) > MAX_SOCKETS
    candidates = raw_connections[:MAX_SOCKETS]
    normalized: dict[tuple[object, ...], dict[str, object]] = {}
    parse_failures = False
    for connection in candidates:
        record, invalid = _normalize_connection(connection)
        parse_failures |= invalid
        if record is None:
            continue
        key = tuple(
            record[field]
            for field in (
                "protocol",
                "family",
                "local_address",
                "local_port",
                "state",
                "pid",
                "scope_id",
            )
        )
        normalized.setdefault(key, record)
    records = sorted(
        normalized.values(),
        key=lambda item: (
            str(item["protocol"]),
            str(item["family"]),
            str(item["local_address"]),
            int(item["local_port"]),
            -1 if item["pid"] is None else int(item["pid"]),
            -1 if item["scope_id"] is None else int(item["scope_id"]),
        ),
    )
    return records, truncated, parse_failures


def _normalize_connection(
    connection: object,
) -> tuple[dict[str, object] | None, bool]:
    family_value = getattr(connection, "family", None)
    socket_type = getattr(connection, "type", None)
    protocol: str
    state: str
    if socket_type == socket.SOCK_STREAM:
        protocol, state = "tcp", "listen"
        if getattr(connection, "status", None) != psutil.CONN_LISTEN:
            return None, False
    elif socket_type == socket.SOCK_DGRAM:
        protocol, state = "udp", "bound"
        if getattr(connection, "status", None) not in (psutil.CONN_NONE, ""):
            return None, False
    else:
        return None, False

    if family_value == socket.AF_INET:
        family = "ipv4"
        version = 4
    elif family_value == socket.AF_INET6:
        family = "ipv6"
        version = 6
    else:
        return None, False

    local = getattr(connection, "laddr", None)
    try:
        raw_address = local.ip if hasattr(local, "ip") else local[0]
        raw_port = local.port if hasattr(local, "port") else local[1]
    except (IndexError, TypeError, AttributeError):
        return None, True
    if (
        not isinstance(raw_address, str)
        or isinstance(raw_port, bool)
        or not isinstance(raw_port, int)
    ):
        return None, True
    if not 1 <= raw_port <= 65535:
        return None, True

    address_text, separator, zone = raw_address.partition("%")
    try:
        parsed = ipaddress.ip_address(address_text)
    except ValueError:
        return None, True
    if parsed.version != version:
        return None, True
    if version == 4 and separator:
        return None, True

    invalid = False
    scope_id = None
    if version == 6:
        if separator:
            if zone.isdecimal():
                scope_id = int(zone)
            else:
                try:
                    scope_id = socket.if_nametoindex(zone)
                except (OSError, ValueError):
                    scope_id = None
        else:
            try:
                raw_scope_id = (
                    local.scope_id
                    if hasattr(local, "scope_id")
                    else local[3]
                    if len(local) > 3
                    else None
                )
            except (TypeError, IndexError):
                raw_scope_id = None
            if raw_scope_id is not None:
                if (
                    isinstance(raw_scope_id, int)
                    and not isinstance(raw_scope_id, bool)
                    and raw_scope_id >= 0
                ):
                    scope_id = raw_scope_id
                else:
                    invalid = True

    raw_pid = getattr(connection, "pid", None)
    if raw_pid is None:
        pid = None
    elif isinstance(raw_pid, bool) or not isinstance(raw_pid, int) or raw_pid <= 0:
        pid = None
        invalid = True
    else:
        pid = raw_pid
    return (
        {
            "protocol": protocol,
            "family": family,
            "local_address": str(parsed),
            "local_port": raw_port,
            "state": state,
            "pid": pid,
            "scope_id": scope_id,
        },
        invalid,
    )


def _process_entities(value: object) -> tuple[dict[int, ProcessReference], bool]:
    if value is None:
        return {}, False
    if isinstance(value, Mapping):
        value = value.get("entities")
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return {}, True
    entities: dict[int, ProcessReference] = {}
    invalid = False
    for item in value:
        try:
            if isinstance(item, Mapping) and item.get("kind") == "process":
                attributes = item.get("attributes")
                if not isinstance(attributes, Mapping):
                    raise TypeError
                item = {
                    "id": item.get("id"),
                    "pid": attributes.get("pid"),
                    "started_at": attributes.get("started_at"),
                }
            entity = ProcessReference.model_validate(item)
        except (ValidationError, TypeError):
            invalid = True
            continue
        if entity.pid in entities:
            invalid = True
            continue
        entities[entity.pid] = entity
    return entities, invalid


def _revalidate_process(pid: int, expected_start: datetime) -> tuple[bool, str | None]:
    try:
        actual_start = datetime.fromtimestamp(psutil.Process(pid).create_time(), UTC)
    except psutil.AccessDenied:
        return False, "permission_denied"
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return False, "disappeared"
    except (OSError, psutil.Error, OverflowError, ValueError, TypeError):
        return False, "io_error"
    return actual_start == expected_start, None if actual_start == expected_start else "reused_pid"


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def _error(code: Literal["permission_denied", "io_error", "parse_error"]) -> CollectionError:
    message = {
        "permission_denied": "Permission denied while reading socket metadata.",
        "io_error": "Socket metadata could not be read.",
        "parse_error": "Socket metadata did not match the expected format.",
    }[code]
    return CollectionError(code=code, operation="net_connections", message=message)


def _append_error_once(errors: list[CollectionError], error: CollectionError) -> None:
    if not any(item.code == error.code and item.operation == error.operation for item in errors):
        errors.append(error)


def _collector_status(
    errors: list[CollectionError],
) -> Literal["ok", "permission_denied", "collection_error"]:
    if any(item.code != "permission_denied" for item in errors):
        return "collection_error"
    if errors:
        return "permission_denied"
    return "ok"
