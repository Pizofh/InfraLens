"""Strict producer models and cross-reference validation for snapshot schema 1.0.0."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    WithJsonSchema,
    model_validator,
)

SCHEMA_VERSION = "1.0.0"
TIMESTAMP_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"


def _validate_utc_timestamp(value: object) -> datetime:
    if isinstance(value, str) and not re.fullmatch(TIMESTAMP_PATTERN, value):
        raise ValueError("timestamp must be RFC3339 UTC with a trailing Z")
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("timestamp must be timezone-aware UTC")
        return value.astimezone(UTC)
    if isinstance(value, str):
        # The pattern above fixes the timezone to Z; datetime.fromisoformat validates the date.
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    raise ValueError("timestamp must be a UTC datetime or RFC3339 string")


def _parse_uuid(value: object) -> UUID:
    if isinstance(value, UUID):
        return value
    if isinstance(value, str):
        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("value must be a valid UUID") from exc
        if str(parsed) != value.lower():
            raise ValueError("UUID must use the canonical hyphenated representation")
        return parsed
    raise ValueError("value must be a UUID")


type UuidValue = Annotated[UUID, BeforeValidator(_parse_uuid)]


type UtcTimestamp = Annotated[
    datetime,
    BeforeValidator(_validate_utc_timestamp),
    AfterValidator(_validate_utc_timestamp),
    WithJsonSchema(
        {
            "type": "string",
            "format": "date-time",
            "pattern": TIMESTAMP_PATTERN,
        }
    ),
]


class Model(BaseModel):
    """Producer-side models reject unknown fields and implicit type coercion."""

    model_config = ConfigDict(extra="forbid", strict=True)


class Limitation(Model):
    code: StrictStr = Field(min_length=1, max_length=96)
    message: StrictStr = Field(min_length=1, max_length=512)
    subject_id: StrictStr | None = None


class CollectionError(Model):
    code: Literal[
        "permission_denied",
        "timeout",
        "command_failed",
        "parse_error",
        "io_error",
        "worker_error",
        "global_deadline",
    ]
    operation: Literal[
        "read_os_release",
        "read_host_resources",
        "disk_partitions",
        "disk_usage",
        "net_if_addrs",
        "net_if_stats",
        "process_iter",
        "net_connections",
        "systemctl_detect",
        "systemctl_list_units",
        "systemctl_show",
        "serialize_snapshot",
        "start_worker",
    ]
    message: StrictStr = Field(min_length=1, max_length=512)
    errno: StrictInt | None = Field(default=None, ge=0)
    exit_code: StrictInt | None = None


class Collector(Model):
    id: Literal["host", "processes", "sockets", "systemd"]
    status: Literal["ok", "unsupported", "permission_denied", "collection_error", "skipped"]
    coverage: Literal["complete", "partial", "none"]
    scope: StrictStr = Field(min_length=1, max_length=256)
    started_at: UtcTimestamp
    finished_at: UtcTimestamp
    entity_ids: list[StrictStr]
    evidence_ids: list[StrictStr]
    errors: list[CollectionError]
    limitations: list[Limitation]
    truncated: StrictBool

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("collector finished_at precedes started_at")

        error_codes = {error.code for error in self.errors}
        if "permission_denied" in error_codes and self.status != "collection_error":
            if self.status != "permission_denied":
                raise ValueError("permission errors require permission_denied status")
        elif error_codes - {"permission_denied"} and self.status != "collection_error":
            raise ValueError("collection errors require collection_error status")
        elif self.status == "permission_denied" and "permission_denied" not in error_codes:
            raise ValueError("permission_denied status requires a permission error")
        if self.status == "collection_error" and not self.errors:
            raise ValueError("collection_error status requires at least one error")

        if self.status in {"unsupported", "skipped"}:
            if self.coverage != "none" or self.entity_ids or self.evidence_ids:
                raise ValueError("unsupported/skipped collectors must have no coverage or data")
            if not self.limitations:
                raise ValueError("unsupported/skipped collectors require a limitation")
        if self.status == "ok" and self.coverage == "none":
            raise ValueError("an ok collector cannot have no coverage")
        if self.coverage == "complete" and (self.status != "ok" or self.truncated or self.errors):
            raise ValueError("complete coverage requires an untruncated, error-free ok collector")
        if self.coverage == "none" and (self.entity_ids or self.evidence_ids):
            raise ValueError("none coverage cannot contain entities or evidence")
        if self.coverage != "none" and self.status not in {
            "ok",
            "permission_denied",
            "collection_error",
        }:
            raise ValueError("collector status is incompatible with coverage")
        return self


class Host(Model):
    os_id: StrictStr | None
    os_version: StrictStr | None
    kernel: StrictStr | None
    hostname: StrictStr | None
    boot_id: UuidValue | None


class Namespaces(Model):
    pid: StrictInt | None = Field(ge=1)
    net: StrictInt | None = Field(ge=1)
    mnt: StrictInt | None = Field(ge=1)


class Context(Model):
    uid: StrictInt | None = Field(ge=0)
    euid: StrictInt | None = Field(ge=0)
    namespaces: Namespaces
    limitations: list[Limitation]

    @model_validator(mode="after")
    def validate_unknown_context(self) -> Self:
        values = {"uid": self.uid, "euid": self.euid, **self.namespaces.model_dump()}
        for field_name, value in values.items():
            if value is None and not any(
                field_name.casefold() in limitation.message.casefold()
                for limitation in self.limitations
            ):
                raise ValueError(f"unknown context field {field_name} requires a limitation")
        return self


class Address(Model):
    family: Literal["ipv4", "ipv6"]
    address: StrictStr
    prefix_length: StrictInt | None = Field(ge=0, le=128)
    scope_id: StrictInt | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_address(self) -> Self:
        try:
            parsed = ipaddress.ip_address(self.address)
        except ValueError as exc:
            raise ValueError("address must be a canonical IP literal without a zone") from exc
        expected_version = 4 if self.family == "ipv4" else 6
        if parsed.version != expected_version or str(parsed) != self.address:
            raise ValueError("address family or canonical representation does not match")
        if self.prefix_length is not None and self.prefix_length > parsed.max_prefixlen:
            raise ValueError("prefix length is outside the address family's range")
        if self.family == "ipv4" and self.scope_id is not None:
            raise ValueError("scope_id is only valid for IPv6 addresses")
        return self


class HostResourcesAttributes(Model):
    cpu_logical: StrictInt | None = Field(ge=1)
    memory_total_bytes: StrictInt | None = Field(ge=0)
    memory_available_bytes: StrictInt | None = Field(ge=0)

    @model_validator(mode="after")
    def validate_memory(self) -> Self:
        if (
            self.memory_total_bytes is not None
            and self.memory_available_bytes is not None
            and self.memory_available_bytes > self.memory_total_bytes
        ):
            raise ValueError("available memory cannot exceed total memory")
        return self


class FilesystemAttributes(Model):
    device: StrictStr
    mountpoint: StrictStr
    fs_type: StrictStr
    total_bytes: StrictInt | None = Field(ge=0)
    used_bytes: StrictInt | None = Field(ge=0)
    free_bytes: StrictInt | None = Field(ge=0)

    @model_validator(mode="after")
    def validate_capacity(self) -> Self:
        if self.total_bytes is not None:
            for field_name in ("used_bytes", "free_bytes"):
                value = getattr(self, field_name)
                if value is not None and value > self.total_bytes:
                    raise ValueError(f"{field_name} cannot exceed total_bytes")
        return self


class InterfaceAttributes(Model):
    name: StrictStr
    is_up: StrictBool | None
    addresses: list[Address]


class ProcessAttributes(Model):
    pid: StrictInt = Field(gt=0)
    started_at: UtcTimestamp | None
    name: StrictStr | None
    uid: StrictInt | None = Field(ge=0)


class SocketAttributes(Model):
    protocol: Literal["tcp", "udp"]
    family: Literal["ipv4", "ipv6"]
    local_address: StrictStr
    local_port: StrictInt = Field(ge=1, le=65535)
    state: Literal["listen", "bound"]
    pid: StrictInt | None = Field(default=None, gt=0)
    scope_id: StrictInt | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_socket(self) -> Self:
        try:
            parsed = ipaddress.ip_address(self.local_address)
        except ValueError as exc:
            raise ValueError("local_address must be a canonical IP literal without a zone") from exc
        expected_version = 4 if self.family == "ipv4" else 6
        if parsed.version != expected_version or str(parsed) != self.local_address:
            raise ValueError("socket address family or canonical representation does not match")
        if (self.protocol, self.state) not in {("tcp", "listen"), ("udp", "bound")}:
            raise ValueError("TCP sockets must be listen and UDP sockets must be bound")
        if self.family == "ipv4" and self.scope_id is not None:
            raise ValueError("scope_id is only valid for IPv6 sockets")
        return self


class ServiceAttributes(Model):
    name: StrictStr = Field(min_length=1)
    load_state: StrictStr
    active_state: StrictStr
    sub_state: StrictStr
    main_pid: StrictInt | None = Field(default=None, gt=0)


class EntityBase(Model):
    id: StrictStr
    evidence_ids: list[StrictStr] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_id_prefix(self) -> Self:
        if not re.fullmatch(rf"{self.kind}:[1-9][0-9]*", self.id):
            raise ValueError("entity id must use its kind and a positive ordinal")
        return self


class HostResourcesEntity(EntityBase):
    kind: Literal["host_resources"]
    attributes: HostResourcesAttributes


class FilesystemEntity(EntityBase):
    kind: Literal["filesystem"]
    attributes: FilesystemAttributes


class InterfaceEntity(EntityBase):
    kind: Literal["interface"]
    attributes: InterfaceAttributes


class ProcessEntity(EntityBase):
    kind: Literal["process"]
    attributes: ProcessAttributes


class SocketEntity(EntityBase):
    kind: Literal["socket"]
    attributes: SocketAttributes


class ServiceEntity(EntityBase):
    kind: Literal["service"]
    attributes: ServiceAttributes


type Entity = Annotated[
    HostResourcesEntity
    | FilesystemEntity
    | InterfaceEntity
    | ProcessEntity
    | SocketEntity
    | ServiceEntity,
    Field(discriminator="kind"),
]


class EvidenceSource(Model):
    type: Literal["api", "file", "command"]
    name: Literal[
        "psutil.cpu_count",
        "psutil.virtual_memory",
        "psutil.disk_partitions",
        "psutil.disk_usage",
        "psutil.net_if_addrs",
        "psutil.net_if_stats",
        "psutil.process_iter",
        "psutil.net_connections",
        "os-release",
        "proc.boot_id",
        "platform.release",
        "platform.node",
        "systemctl.list-units",
        "systemctl.show",
    ]
    locator: StrictStr | None = Field(default=None, max_length=512)


type EvidenceScalar = StrictStr | StrictInt | float | StrictBool | None


class Evidence(Model):
    id: StrictStr = Field(pattern=r"^e:[1-9][0-9]*$")
    collector_id: Literal["host", "processes", "sockets", "systemd"]
    collected_at: UtcTimestamp
    source: EvidenceSource
    subject_id: StrictStr
    claim: Literal["observed"]
    fields: dict[StrictStr, EvidenceScalar] = Field(min_length=1)
    limitations: list[Limitation]

    @model_validator(mode="after")
    def validate_source_and_finite_values(self) -> Self:
        if self.source.name.startswith("systemctl.") and self.source.type != "command":
            raise ValueError("systemctl evidence source must have type command")
        if self.source.name == "os-release" and self.source.type != "file":
            raise ValueError("os-release evidence source must have type file")
        if self.source.name == "proc.boot_id" and self.source.type != "file":
            raise ValueError("proc.boot_id evidence source must have type file")
        if self.source.name.startswith(("psutil.", "platform.")) and self.source.type != "api":
            raise ValueError("psutil/platform evidence source must have type api")
        for value in self.fields.values():
            if isinstance(value, float) and not (float("-inf") < value < float("inf")):
                raise ValueError("evidence numbers must be finite")
        return self


class Relation(Model):
    id: StrictStr = Field(pattern=r"^r:[1-9][0-9]*$")
    type: Literal["owned_by", "main_process"]
    from_id: StrictStr
    to_id: StrictStr
    claim: Literal["observed"]
    evidence_ids: list[StrictStr] = Field(min_length=1)
    rationale_code: Literal["pid_create_time_match", "main_pid_revalidated"]


class Assessment(Model):
    rule_id: Literal["FS_USAGE_HIGH", "SYSTEMD_FAILED"]
    rule_version: Literal["1.0.0"]
    subject_id: StrictStr | None
    state: Literal["triggered", "not_triggered", "not_evaluable"]
    finding_id: StrictStr | None
    reason_code: StrictStr | None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.state == "triggered" and (self.finding_id is None or self.reason_code is not None):
            raise ValueError("triggered assessments require a finding and no reason_code")
        if self.state == "not_triggered" and (
            self.finding_id is not None or self.reason_code is not None
        ):
            raise ValueError("not_triggered assessments cannot reference a finding or reason")
        if self.state == "not_evaluable" and (self.finding_id is not None or not self.reason_code):
            raise ValueError("not_evaluable assessments require a reason and no finding")
        return self


class Finding(Model):
    id: StrictStr = Field(pattern=r"^f:[1-9][0-9]*$")
    rule_id: Literal["FS_USAGE_HIGH", "SYSTEMD_FAILED"]
    rule_version: Literal["1.0.0"]
    severity: Literal["warning"]
    subject_id: StrictStr
    claim: Literal["observed"]
    evidence_ids: list[StrictStr] = Field(min_length=1)
    message: StrictStr = Field(min_length=1, max_length=512)
    review_action: StrictStr = Field(min_length=1, max_length=512)


class Snapshot(Model):
    schema_version: Literal["1.0.0"]
    tool_version: StrictStr = Field(min_length=1)
    scan_id: UuidValue
    scope_id: UuidValue
    scope_origin: Literal["operator", "generated"]
    started_at: UtcTimestamp
    finished_at: UtcTimestamp
    host: Host
    context: Context
    collectors: list[Collector] = Field(min_length=4, max_length=4)
    entities: list[Entity]
    evidence: list[Evidence]
    relations: list[Relation]
    assessment: list[Assessment]
    findings: list[Finding]
    limitations: list[Limitation]

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("snapshot finished_at precedes started_at")

        collector_map = _unique_map(self.collectors, "id", "collector")
        required_collectors = {"host", "processes", "sockets", "systemd"}
        if set(collector_map) != required_collectors:
            raise ValueError("snapshot must include each of host, processes, sockets, systemd")

        entity_map = _unique_map(self.entities, "id", "entity")
        evidence_map = _unique_map(self.evidence, "id", "evidence")
        finding_map = _unique_map(self.findings, "id", "finding")
        _unique_map(self.relations, "id", "relation")
        relation_pairs = [(item.type, item.from_id, item.to_id) for item in self.relations]
        if len(set(relation_pairs)) != len(relation_pairs):
            raise ValueError("snapshot contains duplicate relations")

        for collector in self.collectors:
            if collector.started_at < self.started_at or collector.finished_at > self.finished_at:
                raise ValueError(f"collector {collector.id} timestamps fall outside the snapshot")

            if len(set(collector.entity_ids)) != len(collector.entity_ids):
                raise ValueError(f"collector {collector.id} has duplicate entity references")
            if len(set(collector.evidence_ids)) != len(collector.evidence_ids):
                raise ValueError(f"collector {collector.id} has duplicate evidence references")
            expected_entities = {
                entity.id
                for entity in self.entities
                if _entity_collector(entity.kind) == collector.id
            }
            expected_evidence = {
                item.id for item in self.evidence if item.collector_id == collector.id
            }
            if set(collector.entity_ids) != expected_entities:
                raise ValueError(
                    f"collector {collector.id} entity_ids do not match snapshot entities"
                )
            if set(collector.evidence_ids) != expected_evidence:
                raise ValueError(
                    f"collector {collector.id} evidence_ids do not match snapshot evidence"
                )

        for entity in self.entities:
            if len(set(entity.evidence_ids)) != len(entity.evidence_ids):
                raise ValueError(f"entity {entity.id} has duplicate evidence references")
            collector_id = _entity_collector(entity.kind)
            if collector_map[collector_id].coverage == "none":
                raise ValueError("entity belongs to a collector with no coverage")
            for evidence_id in entity.evidence_ids:
                evidence = evidence_map.get(evidence_id)
                if evidence is None:
                    raise ValueError(
                        f"entity {entity.id} references unknown evidence {evidence_id}"
                    )
                if evidence.subject_id != entity.id or evidence.collector_id != collector_id:
                    raise ValueError(f"evidence {evidence_id} does not match its entity")

        for evidence in self.evidence:
            collector = collector_map[evidence.collector_id]
            if not collector.started_at <= evidence.collected_at <= collector.finished_at:
                raise ValueError(f"evidence {evidence.id} timestamp falls outside its collector")
            if evidence.subject_id == "host":
                if evidence.collector_id != "host":
                    raise ValueError(
                        f"evidence {evidence.id} host subject belongs to wrong collector"
                    )
                attributes = self.host.model_dump(mode="json")
            else:
                entity = entity_map.get(evidence.subject_id)
                if entity is None:
                    raise ValueError(f"evidence {evidence.id} references unknown subject")
                if evidence.collector_id != _entity_collector(entity.kind):
                    raise ValueError(f"evidence {evidence.id} belongs to the wrong collector")
                attributes = entity.attributes.model_dump(mode="json")
            if any(
                key not in attributes or attributes[key] != value
                for key, value in evidence.fields.items()
            ):
                raise ValueError(f"evidence {evidence.id} fields do not match observed attributes")

        for relation in self.relations:
            source = entity_map.get(relation.from_id)
            target = entity_map.get(relation.to_id)
            if source is None or target is None:
                raise ValueError(f"relation {relation.id} references an unknown entity")
            expected_kinds = {
                "owned_by": ("socket", "process", "pid_create_time_match"),
                "main_process": ("service", "process", "main_pid_revalidated"),
            }[relation.type]
            if (source.kind, target.kind, relation.rationale_code) != expected_kinds:
                raise ValueError(
                    f"relation {relation.id} has incompatible type, entities, or rationale"
                )
            source_attributes = source.attributes
            target_attributes = target.attributes
            if relation.type == "owned_by":
                if source_attributes.pid is None or source_attributes.pid != target_attributes.pid:
                    raise ValueError(f"relation {relation.id} socket and process PIDs do not match")
                if target_attributes.started_at is None:
                    raise ValueError(
                        f"relation {relation.id} requires an observed process start time"
                    )
            elif (
                source_attributes.main_pid is None
                or source_attributes.main_pid != target_attributes.pid
            ):
                raise ValueError(
                    f"relation {relation.id} service MainPID does not match the process"
                )
            for evidence_id in relation.evidence_ids:
                evidence = evidence_map.get(evidence_id)
                if evidence is None or evidence.subject_id != source.id:
                    raise ValueError(
                        f"relation {relation.id} evidence must describe its source entity"
                    )

        evaluation_map: dict[tuple[str, str | None], Assessment] = {}
        for evaluation in self.assessment:
            key = (evaluation.rule_id, evaluation.subject_id)
            if key in evaluation_map:
                raise ValueError("assessment contains duplicate rule/subject pairs")
            evaluation_map[key] = evaluation
            if evaluation.subject_id is not None and evaluation.subject_id not in entity_map:
                raise ValueError(f"assessment {evaluation.rule_id} references an unknown subject")
            if evaluation.finding_id is not None and evaluation.finding_id not in finding_map:
                raise ValueError(f"assessment {evaluation.rule_id} references an unknown finding")

        for finding in self.findings:
            subject = entity_map.get(finding.subject_id)
            if subject is None:
                raise ValueError(f"finding {finding.id} references an unknown subject")
            if finding.rule_id == "FS_USAGE_HIGH" and subject.kind != "filesystem":
                raise ValueError("FS_USAGE_HIGH findings must reference a filesystem")
            if finding.rule_id == "SYSTEMD_FAILED" and subject.kind != "service":
                raise ValueError("SYSTEMD_FAILED findings must reference a service")
            for evidence_id in finding.evidence_ids:
                evidence = evidence_map.get(evidence_id)
                if evidence is None or evidence.subject_id != subject.id:
                    raise ValueError(f"finding {finding.id} evidence must describe its subject")
            evaluation = evaluation_map.get((finding.rule_id, finding.subject_id))
            if (
                evaluation is None
                or evaluation.state != "triggered"
                or evaluation.finding_id != finding.id
            ):
                raise ValueError(f"finding {finding.id} must have a matching triggered assessment")

        for evaluation in self.assessment:
            if evaluation.state == "triggered":
                finding = finding_map[evaluation.finding_id or ""]
                if (finding.rule_id, finding.subject_id) != (
                    evaluation.rule_id,
                    evaluation.subject_id,
                ):
                    raise ValueError("triggered assessment and finding do not match")
            if evaluation.subject_id is None and evaluation.state != "not_evaluable":
                raise ValueError("subject-free assessments must be not_evaluable")

        limitation_subjects = {
            limitation.subject_id
            for limitation in [*self.limitations, *self.context.limitations]
            if limitation.subject_id is not None
        }
        limitation_subjects.update(
            limitation.subject_id
            for collector in self.collectors
            for limitation in collector.limitations
            if limitation.subject_id is not None
        )
        for evidence in self.evidence:
            limitation_subjects.update(
                limitation.subject_id
                for limitation in evidence.limitations
                if limitation.subject_id is not None
            )
        if not limitation_subjects.issubset(entity_map):
            raise ValueError("a limitation references an unknown subject")

        all_limitations = [
            *self.limitations,
            *self.context.limitations,
            *(item for collector in self.collectors for item in collector.limitations),
            *(item for evidence in self.evidence for item in evidence.limitations),
        ]
        if any(value is None for value in self.host.model_dump().values()):
            for field_name, value in self.host.model_dump().items():
                if value is None and not any(
                    field_name in limitation.message for limitation in self.limitations
                ):
                    raise ValueError(f"unknown host field {field_name} requires a limitation")

        referenced_evidence = {
            evidence_id for entity in self.entities for evidence_id in entity.evidence_ids
        }
        referenced_evidence.update(
            evidence.id for evidence in self.evidence if evidence.subject_id == "host"
        )
        if referenced_evidence != set(evidence_map):
            raise ValueError("every evidence record must be referenced by its subject")

        for entity in self.entities:
            for field_name, value in entity.attributes.model_dump().items():
                not_applicable = False
                if entity.kind == "socket" and field_name == "scope_id":
                    not_applicable = (
                        entity.attributes.family == "ipv4"
                        or not ipaddress.IPv6Address(entity.attributes.local_address).is_link_local
                    )
                elif entity.kind == "service" and field_name == "main_pid":
                    # systemctl MainPID=0 is a known absence, not an unknown value.
                    not_applicable = True
                if (
                    value is None
                    and not not_applicable
                    and not any(
                        limitation.subject_id == entity.id
                        and field_name.casefold() in limitation.message.casefold()
                        for limitation in all_limitations
                    )
                ):
                    raise ValueError(
                        f"unknown field {field_name} on {entity.id} requires a scoped limitation"
                    )

        for evaluation in self.assessment:
            if evaluation.subject_id is not None:
                subject = entity_map[evaluation.subject_id]
                expected_kind = "filesystem" if evaluation.rule_id == "FS_USAGE_HIGH" else "service"
                if subject.kind != expected_kind:
                    raise ValueError(f"{evaluation.rule_id} assessment has an incompatible subject")

        expected_assessments: set[tuple[str, str | None]] = set()
        for rule_id, kind in (("FS_USAGE_HIGH", "filesystem"), ("SYSTEMD_FAILED", "service")):
            subjects = [entity.id for entity in self.entities if entity.kind == kind]
            if subjects:
                expected_assessments.update((rule_id, subject_id) for subject_id in subjects)
            else:
                expected_assessments.add((rule_id, None))
        if set(evaluation_map) != expected_assessments:
            raise ValueError(
                "assessment must contain exactly one result per applicable rule and subject"
            )
        return self


def _unique_map(items: list[BaseModel], field: str, label: str) -> dict[str, BaseModel]:
    result: dict[str, BaseModel] = {}
    for item in items:
        value = getattr(item, field)
        if value in result:
            raise ValueError(f"duplicate {label} id: {value}")
        result[value] = item
    return result


def _null_field_names(value: object) -> set[str]:
    if isinstance(value, BaseModel):
        result: set[str] = set()
        for field_name in type(value).model_fields:
            field_value = getattr(value, field_name)
            if field_value is None:
                result.add(field_name)
            else:
                result.update(_null_field_names(field_value))
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for item in value:
            result.update(_null_field_names(item))
        return result
    if isinstance(value, dict):
        result: set[str] = set()
        for item in value.values():
            result.update(_null_field_names(item))
        return result
    return set()


def _entity_collector(kind: str) -> str:
    return {
        "host_resources": "host",
        "filesystem": "host",
        "interface": "host",
        "process": "processes",
        "socket": "sockets",
        "service": "systemd",
    }[kind]


_SCHEMA_INVARIANTS = [
    "Timestamps are RFC3339 UTC values ending in Z; finish times cannot precede start times.",
    "Each snapshot contains exactly one host, processes, sockets, and systemd collector.",
    "Collector status, coverage, truncation, errors, and data references must agree.",
    (
        "Entity, evidence, relation, assessment, and finding references resolve consistently "
        "within this snapshot."
    ),
    (
        "Evidence fields equal the observed attributes of their host or entity subject; evidence "
        "is not raw command output."
    ),
    (
        "Unknown host or entity fields require a limitation; an empty collection does not imply "
        "whole-host absence."
    ),
    (
        "A null service main_pid can mean systemd reported MainPID=0; unknown values require a "
        "limitation."
    ),
    "Rules are limited to FS_USAGE_HIGH and SYSTEMD_FAILED in schema version 1.0.0.",
]


def snapshot_json_schema() -> dict[str, object]:
    """Return the versioned JSON Schema, including cross-record invariant notes."""
    schema = Snapshot.model_json_schema(mode="validation")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "urn:infralens:snapshot:1.0.0"
    schema["x-infralens-invariants"] = list(_SCHEMA_INVARIANTS)
    return schema
