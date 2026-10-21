"""Collect Linux OS identity, basic resources, and process context."""

from __future__ import annotations

import os
import platform
import re
import shlex
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from itertools import count
from pathlib import Path
from typing import Literal
from uuid import UUID

import psutil
from pydantic import BaseModel, ConfigDict

from infralens.models import (
    CollectionError,
    Collector,
    Context,
    Entity,
    Evidence,
    EvidenceSource,
    FilesystemAttributes,
    FilesystemEntity,
    Host,
    HostResourcesAttributes,
    HostResourcesEntity,
    Limitation,
    Namespaces,
)

MAX_OS_RELEASE_BYTES = 64 * 1024
MAX_FILESYSTEMS = 256
OS_RELEASE_PATHS = (Path("/etc/os-release"), Path("/usr/lib/os-release"))
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
HOST_SCOPE = (
    "OS identity, kernel, CPU/memory, UID/EUID, pid/net/mnt namespaces, and up to 256 "
    "filesystems returned by psutil.disk_partitions(all=False)"
)
_OS_RELEASE_KEY = re.compile(r"[A-Z][A-Z0-9_]*\Z")
_BOOT_ID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)


class HostCollectionResult(BaseModel):
    """Normalized host data ready for later snapshot assembly."""

    model_config = ConfigDict(extra="forbid", strict=True)

    host: Host
    context: Context
    collector: Collector
    entities: list[Entity]
    evidence: list[Evidence]
    limitations: list[Limitation]


def collect(_context: Mapping[str, object]) -> HostCollectionResult:
    """Collect a bounded, non-mutating subset of local Linux host metadata."""
    started_at = datetime.now(UTC)
    errors: list[CollectionError] = []
    limitations: list[Limitation] = []
    evidence: list[Evidence] = []
    evidence_ids = count(1)

    os_values, os_path, os_errors, os_notes = _load_os_release()
    errors.extend(os_errors)
    limitations.extend(os_notes)
    os_id = _nonempty_string(os_values.get("ID"))
    os_version = _nonempty_string(os_values.get("VERSION_ID"))
    if os_id is not None:
        os_id = os_id.lower()
        evidence.append(
            _host_evidence(
                "os-release",
                "file",
                str(os_path),
                {"os_id": os_id},
                next(evidence_ids),
            )
        )
    if os_version is not None:
        evidence.append(
            _host_evidence(
                "os-release",
                "file",
                str(os_path),
                {"os_version": os_version},
                next(evidence_ids),
            )
        )

    kernel = _read_platform_value(platform.release, "kernel", limitations)
    if kernel is not None:
        evidence.append(
            _host_evidence("platform.release", "api", None, {"kernel": kernel}, next(evidence_ids))
        )

    hostname = _read_platform_value(platform.node, "hostname", limitations)
    if hostname is not None:
        evidence.append(
            _host_evidence("platform.node", "api", None, {"hostname": hostname}, next(evidence_ids))
        )

    boot_id = _read_boot_id(limitations)
    if boot_id is not None:
        evidence.append(
            _host_evidence(
                "proc.boot_id", "file", str(BOOT_ID_PATH), {"boot_id": boot_id}, next(evidence_ids)
            )
        )

    for field_name, value in (
        ("os_id", os_id),
        ("os_version", os_version),
        ("kernel", kernel),
        ("hostname", hostname),
        ("boot_id", boot_id),
    ):
        if value is None and not any(field_name in item.message for item in limitations):
            limitations.append(_host_limitation(field_name))

    host = Host(
        os_id=os_id,
        os_version=os_version,
        kernel=kernel,
        hostname=hostname,
        boot_id=boot_id,
    )
    context, context_limitations = _collect_context()

    cpu_logical, cpu_error = _read_cpu_count()
    memory_total, memory_available, memory_error = _read_memory()
    if cpu_error is not None:
        errors.append(cpu_error)
    if memory_error is not None:
        errors.append(memory_error)

    resource_entity_id = "host_resources:1"
    resource_attributes = HostResourcesAttributes(
        cpu_logical=cpu_logical,
        memory_total_bytes=memory_total,
        memory_available_bytes=memory_available,
    )
    resource_evidence: list[Evidence] = []
    if cpu_logical is not None:
        resource_evidence.append(
            _resource_evidence(
                "psutil.cpu_count",
                {"cpu_logical": cpu_logical},
                resource_entity_id,
                next(evidence_ids),
            )
        )
    memory_fields = {
        key: value
        for key, value in (
            ("memory_total_bytes", memory_total),
            ("memory_available_bytes", memory_available),
        )
        if value is not None
    }
    if memory_fields:
        resource_evidence.append(
            _resource_evidence(
                "psutil.virtual_memory", memory_fields, resource_entity_id, next(evidence_ids)
            )
        )

    entities: list[Entity] = []
    if resource_evidence:
        resource_evidence_ids = [item.id for item in resource_evidence]
        entities.append(
            HostResourcesEntity(
                id=resource_entity_id,
                kind="host_resources",
                attributes=resource_attributes,
                evidence_ids=resource_evidence_ids,
            )
        )
        for field_name, value in (
            ("cpu_logical", cpu_logical),
            ("memory_total_bytes", memory_total),
            ("memory_available_bytes", memory_available),
        ):
            if value is None:
                limitations.append(_resource_limitation(field_name, resource_entity_id))
    else:
        for field_name in ("cpu_logical", "memory_total_bytes", "memory_available_bytes"):
            limitations.append(_resource_limitation(field_name, None))

    evidence.extend(resource_evidence)
    (
        filesystem_entities,
        filesystem_evidence,
        filesystem_errors,
        filesystem_limitations,
        truncated,
    ) = _collect_filesystems(evidence_ids)
    entities.extend(filesystem_entities)
    evidence.extend(filesystem_evidence)
    errors.extend(filesystem_errors)
    limitations.extend(filesystem_limitations)
    all_limitations = [*limitations, *context_limitations]
    if not evidence and not errors:
        errors.append(_error("io_error", "read_host_resources"))
    status = _collector_status(errors)
    has_observations = bool(evidence or entities)
    coverage: Literal["complete", "partial", "none"]
    if not has_observations:
        coverage = "none"
    elif (
        errors
        or any(item.code != "os_release_fallback" for item in limitations)
        or context_limitations
        or truncated
    ):
        coverage = "partial"
    else:
        coverage = "complete"
    finished_at = datetime.now(UTC)
    collector = Collector(
        id="host",
        status=status,
        coverage=coverage,
        scope=HOST_SCOPE,
        started_at=started_at,
        finished_at=finished_at,
        entity_ids=[entity.id for entity in entities],
        evidence_ids=[item.id for item in evidence],
        errors=errors,
        limitations=limitations,
        truncated=truncated,
    )
    return HostCollectionResult(
        host=host,
        context=context,
        collector=collector,
        entities=entities,
        evidence=evidence,
        limitations=all_limitations,
    )


def parse_os_release(content: str) -> tuple[dict[str, str], list[str]]:
    """Parse os-release assignments without evaluating shell syntax."""
    values: dict[str, str] = {}
    errors: list[str] = []
    if "\x00" in content:
        return values, ["NUL byte in os-release content"]

    for line_number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, separator, raw_value = stripped.partition("=")
        if not separator or not _OS_RELEASE_KEY.fullmatch(key):
            errors.append(f"invalid assignment on line {line_number}")
            continue
        try:
            parsed = shlex.split(raw_value, comments=True, posix=True)
        except ValueError:
            errors.append(f"invalid quoting on line {line_number}")
            continue
        if len(parsed) > 1:
            errors.append(f"value must be one shell word on line {line_number}")
            continue
        if key in values:
            errors.append(f"duplicate key on line {line_number}")
        value = parsed[0] if parsed else ""
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            errors.append(f"control character in value on line {line_number}")
            continue
        if key in {"ID", "VERSION_ID"}:
            values[key] = value
    return values, errors


def _load_os_release() -> tuple[
    dict[str, str], Path | None, list[CollectionError], list[Limitation]
]:
    read_errors: list[CollectionError] = []
    parse_errors: list[CollectionError] = []
    notes: list[Limitation] = []
    for index, path in enumerate(OS_RELEASE_PATHS):
        try:
            with path.open("rb") as stream:
                raw = stream.read(MAX_OS_RELEASE_BYTES + 1)
        except PermissionError:
            read_errors.append(_error("permission_denied", "read_os_release"))
            continue
        except OSError:
            read_errors.append(_error("io_error", "read_os_release"))
            continue
        if len(raw) > MAX_OS_RELEASE_BYTES:
            parse_errors.append(_error("parse_error", "read_os_release"))
            continue
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            parse_errors.append(_error("parse_error", "read_os_release"))
            continue
        values, issues = parse_os_release(content)
        if issues:
            parse_errors.append(_error("parse_error", "read_os_release"))
        if values.get("ID") or values.get("VERSION_ID"):
            if index > 0:
                notes.append(
                    Limitation(
                        code="os_release_fallback",
                        message="OS metadata was read from the fallback os-release path.",
                    )
                )
            return values, path, parse_errors, notes

    errors: list[CollectionError] = []
    for error in [*read_errors, *parse_errors]:
        if not any(existing.code == error.code for existing in errors):
            errors.append(error)
    if not errors:
        errors.append(_error("io_error", "read_os_release"))
    return {}, None, errors, notes


def _collect_context() -> tuple[Context, list[Limitation]]:
    limitations: list[Limitation] = []
    try:
        uid = os.getuid()
    except (AttributeError, OSError):
        uid = None
        limitations.append(_context_limitation("uid"))
    try:
        euid = os.geteuid()
    except (AttributeError, OSError):
        euid = None
        limitations.append(_context_limitation("euid"))

    namespace_values: dict[str, int | None] = {}
    for namespace in ("pid", "net", "mnt"):
        try:
            inode = _namespace_inode(namespace)
        except OSError:
            inode = None
            limitations.append(_context_limitation(f"namespace {namespace}"))
        namespace_values[namespace] = inode
    return (
        Context(
            uid=uid,
            euid=euid,
            namespaces=Namespaces(**namespace_values),
            limitations=limitations,
        ),
        limitations,
    )


def _namespace_inode(namespace: str) -> int:
    return Path(f"/proc/self/ns/{namespace}").stat().st_ino


def _read_boot_id(limitations: list[Limitation]) -> str | None:
    try:
        with BOOT_ID_PATH.open("r", encoding="ascii") as stream:
            raw = stream.read(129).strip()
    except (OSError, UnicodeDecodeError):
        limitations.append(_host_limitation("boot_id"))
        return None
    if not _BOOT_ID.fullmatch(raw):
        limitations.append(_host_limitation("boot_id"))
        return None
    try:
        return str(UUID(raw))
    except ValueError:
        limitations.append(_host_limitation("boot_id"))
        return None


def _read_platform_value(
    provider: Callable[[], str], field_name: str, limitations: list[Limitation]
) -> str | None:
    try:
        value = provider()
    except (OSError, RuntimeError):
        limitations.append(_host_limitation(field_name))
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        limitations.append(_host_limitation(field_name))
        return None
    return value


def _read_cpu_count() -> tuple[int | None, CollectionError | None]:
    try:
        value = psutil.cpu_count(logical=True)
    except PermissionError:
        return None, _error("permission_denied", "read_host_resources")
    except (OSError, psutil.Error, ValueError):
        return None, _error("io_error", "read_host_resources")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return None, None
    return value, None


def _read_memory() -> tuple[int | None, int | None, CollectionError | None]:
    try:
        memory = psutil.virtual_memory()
        total = memory.total
        available = memory.available
    except PermissionError:
        return None, None, _error("permission_denied", "read_host_resources")
    except (OSError, psutil.Error, ValueError, AttributeError):
        return None, None, _error("io_error", "read_host_resources")
    if (
        isinstance(total, bool)
        or not isinstance(total, int)
        or total < 0
        or isinstance(available, bool)
        or not isinstance(available, int)
        or available < 0
        or available > total
    ):
        return None, None, None
    return total, available, None


def _collect_filesystems(
    evidence_ids,
) -> tuple[list[FilesystemEntity], list[Evidence], list[CollectionError], list[Limitation], bool]:
    errors: list[CollectionError] = []
    limitations: list[Limitation] = []
    valid_partitions: list[tuple[str, str, str]] = []
    try:
        partitions = psutil.disk_partitions(all=False)
    except (psutil.AccessDenied, PermissionError):
        return (
            [],
            [],
            [_filesystem_error("permission_denied", "disk_partitions")],
            [_filesystem_limitation("filesystem partition list", None)],
            False,
        )
    except (OSError, psutil.Error, ValueError):
        return (
            [],
            [],
            [_filesystem_error("io_error", "disk_partitions")],
            [_filesystem_limitation("filesystem partition list", None)],
            False,
        )

    try:
        partition_rows = list(partitions)
    except (OSError, psutil.Error, ValueError, TypeError):
        return (
            [],
            [],
            [_filesystem_error("io_error", "disk_partitions")],
            [_filesystem_limitation("filesystem partition list", None)],
            False,
        )

    for partition in partition_rows:
        values = tuple(
            _bounded_fs_string(getattr(partition, name, None))
            for name in ("device", "mountpoint", "fstype")
        )
        if any(value is None for value in values):
            errors.append(_filesystem_error("parse_error", "disk_partitions"))
            limitations.append(_filesystem_limitation("filesystem identity", None))
            continue
        device, mountpoint, fs_type = values
        valid_partitions.append((device, mountpoint, fs_type))  # type: ignore[arg-type]

    valid_partitions.sort(key=lambda item: (item[1], item[0], item[2]))
    truncated = len(valid_partitions) > MAX_FILESYSTEMS
    if truncated:
        valid_partitions = valid_partitions[:MAX_FILESYSTEMS]
        limitations.append(
            Limitation(
                code="filesystem_limit_reached",
                message=f"Filesystem collection was limited to {MAX_FILESYSTEMS} mounts.",
            )
        )

    entities: list[FilesystemEntity] = []
    evidence: list[Evidence] = []
    for index, (device, mountpoint, fs_type) in enumerate(valid_partitions, start=1):
        entity_id = f"filesystem:{index}"
        try:
            usage = psutil.disk_usage(mountpoint)
            total = usage.total
            used = usage.used
            free = usage.free
            if not _valid_filesystem_usage(total, used, free):
                raise ValueError
        except (psutil.AccessDenied, PermissionError):
            total = used = free = None
            errors.append(_filesystem_error("permission_denied", "disk_usage"))
            limitations.extend(
                _filesystem_limitation(field, entity_id)
                for field in ("total_bytes", "used_bytes", "free_bytes")
            )
        except (OSError, psutil.Error):
            total = used = free = None
            errors.append(_filesystem_error("io_error", "disk_usage"))
            limitations.extend(
                _filesystem_limitation(field, entity_id)
                for field in ("total_bytes", "used_bytes", "free_bytes")
            )
        except (ValueError, AttributeError, TypeError):
            total = used = free = None
            errors.append(_filesystem_error("parse_error", "disk_usage"))
            limitations.extend(
                _filesystem_limitation(field, entity_id)
                for field in ("total_bytes", "used_bytes", "free_bytes")
            )

        attributes = FilesystemAttributes(
            device=device,
            mountpoint=mountpoint,
            fs_type=fs_type,
            total_bytes=total,
            used_bytes=used,
            free_bytes=free,
        )
        partition_evidence = Evidence(
            id=f"e:{next(evidence_ids)}",
            collector_id="host",
            collected_at=datetime.now(UTC),
            source=EvidenceSource(type="api", name="psutil.disk_partitions"),
            subject_id=entity_id,
            claim="observed",
            fields={"device": device, "mountpoint": mountpoint, "fs_type": fs_type},
            limitations=[],
        )
        entity_evidence = [partition_evidence]
        evidence.append(partition_evidence)
        if total is not None and used is not None and free is not None:
            usage_evidence = Evidence(
                id=f"e:{next(evidence_ids)}",
                collector_id="host",
                collected_at=datetime.now(UTC),
                source=EvidenceSource(type="api", name="psutil.disk_usage"),
                subject_id=entity_id,
                claim="observed",
                fields={
                    "total_bytes": total,
                    "used_bytes": used,
                    "free_bytes": free,
                },
                limitations=[],
            )
            entity_evidence.append(usage_evidence)
            evidence.append(usage_evidence)
        evidence_ids_for_entity = [item.id for item in entity_evidence]
        entities.append(
            FilesystemEntity(
                id=entity_id,
                kind="filesystem",
                attributes=attributes,
                evidence_ids=evidence_ids_for_entity,
            )
        )
    return entities, evidence, errors, limitations, truncated


def _bounded_fs_string(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return None
    return value


def _valid_filesystem_usage(total: object, used: object, free: object) -> bool:
    return (
        all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in (total, used, free)
        )
        and used <= total
        and free <= total
    )


def _filesystem_error(
    code: Literal["permission_denied", "io_error", "parse_error"],
    operation: Literal["disk_partitions", "disk_usage"],
) -> CollectionError:
    message = {
        "permission_denied": "Permission denied while reading filesystem metadata.",
        "io_error": "Filesystem metadata could not be read.",
        "parse_error": "Filesystem metadata did not match the expected format.",
    }[code]
    return CollectionError(code=code, operation=operation, message=message)


def _filesystem_limitation(field_name: str, subject_id: str | None) -> Limitation:
    return Limitation(
        code="filesystem_field_unavailable",
        message=f"Filesystem field {field_name} is unavailable or invalid.",
        subject_id=subject_id,
    )


def _host_evidence(
    source_name: str,
    source_type: Literal["api", "file"],
    locator: str | None,
    fields: dict[str, str],
    evidence_number: int,
) -> Evidence:
    return Evidence(
        id=f"e:{evidence_number}",
        collector_id="host",
        collected_at=datetime.now(UTC),
        source=EvidenceSource(type=source_type, name=source_name, locator=locator),
        subject_id="host",
        claim="observed",
        fields=fields,
        limitations=[],
    )


def _resource_evidence(
    source_name: Literal["psutil.cpu_count", "psutil.virtual_memory"],
    fields: dict[str, int],
    subject_id: str,
    evidence_number: int,
) -> Evidence:
    return Evidence(
        id=f"e:{evidence_number}",
        collector_id="host",
        collected_at=datetime.now(UTC),
        source=EvidenceSource(type="api", name=source_name),
        subject_id=subject_id,
        claim="observed",
        fields=fields,
        limitations=[],
    )


def _host_limitation(field_name: str) -> Limitation:
    return Limitation(
        code="host_field_unavailable",
        message=f"Host field {field_name} is unavailable or invalid.",
    )


def _context_limitation(field_name: str) -> Limitation:
    return Limitation(
        code="context_field_unavailable",
        message=f"Execution context field {field_name} is unavailable.",
    )


def _resource_limitation(field_name: str, subject_id: str | None) -> Limitation:
    return Limitation(
        code="host_resource_unavailable",
        message=f"Host resource field {field_name} is unavailable or invalid.",
        subject_id=subject_id,
    )


def _error(
    code: str, operation: Literal["read_os_release", "read_host_resources"]
) -> CollectionError:
    message = {
        "permission_denied": "Permission denied while reading host metadata.",
        "io_error": "Host metadata could not be read.",
        "parse_error": "Host metadata did not match the expected format.",
    }[code]
    return CollectionError(code=code, operation=operation, message=message)


def _collector_status(
    errors: list[CollectionError],
) -> Literal["ok", "permission_denied", "collection_error"]:
    if any(error.code != "permission_denied" for error in errors):
        return "collection_error"
    if errors:
        return "permission_denied"
    return "ok"


def _nonempty_string(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 512:
        return None
    return value
