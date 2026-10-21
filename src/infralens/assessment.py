"""Pure, evidence-backed assessment rules for normalized snapshots."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from infralens.models import Assessment, Entity, Evidence, Finding, Snapshot

FS_USAGE_THRESHOLD_PERCENT = 90


class AssessmentResult(BaseModel):
    """Rule evaluations and findings produced without inspecting the host."""

    model_config = ConfigDict(extra="forbid", strict=True)

    assessment: list[Assessment]
    findings: list[Finding]


def assess(snapshot: Snapshot) -> AssessmentResult:
    """Evaluate FS_USAGE_HIGH and SYSTEMD_FAILED using only snapshot observations."""
    evidence_by_id = {item.id: item for item in snapshot.evidence}
    filesystem_entities = [item for item in snapshot.entities if item.kind == "filesystem"]
    service_entities = [item for item in snapshot.entities if item.kind == "service"]
    host_collector = next(item for item in snapshot.collectors if item.id == "host")
    systemd_collector = next(item for item in snapshot.collectors if item.id == "systemd")
    assessments: list[Assessment] = []
    findings: list[Finding] = []

    if not filesystem_entities:
        assessments.append(
            _not_evaluable(
                "FS_USAGE_HIGH",
                None,
                _empty_collection_reason(host_collector.status, host_collector.coverage),
            )
        )
    for entity in filesystem_entities:
        attributes = entity.attributes
        if attributes.total_bytes is None or attributes.used_bytes is None:
            assessments.append(
                _not_evaluable("FS_USAGE_HIGH", entity.id, "filesystem_usage_unavailable")
            )
            continue
        if not _has_evidence(
            entity, evidence_by_id, "psutil.disk_usage", "total_bytes", "used_bytes"
        ):
            assessments.append(_not_evaluable("FS_USAGE_HIGH", entity.id, "evidence_unavailable"))
            continue
        if attributes.total_bytes == 0:
            assessments.append(_not_evaluable("FS_USAGE_HIGH", entity.id, "zero_total_capacity"))
            continue
        if attributes.used_bytes * 100 >= attributes.total_bytes * FS_USAGE_THRESHOLD_PERCENT:
            finding = Finding(
                id=f"f:{len(findings) + 1}",
                rule_id="FS_USAGE_HIGH",
                rule_version="1.0.0",
                severity="warning",
                subject_id=entity.id,
                claim="observed",
                evidence_ids=_evidence_ids(
                    entity,
                    evidence_by_id,
                    "psutil.disk_usage",
                    "total_bytes",
                    "used_bytes",
                ),
                message="Observed filesystem usage is at least 90% of total capacity.",
                review_action=(
                    "Review filesystem growth and capacity; do not delete data automatically."
                ),
            )
            findings.append(finding)
            assessments.append(
                Assessment(
                    rule_id="FS_USAGE_HIGH",
                    rule_version="1.0.0",
                    subject_id=entity.id,
                    state="triggered",
                    finding_id=finding.id,
                    reason_code=None,
                )
            )
        else:
            assessments.append(_not_triggered("FS_USAGE_HIGH", entity.id))

    if not service_entities:
        assessments.append(
            _not_evaluable(
                "SYSTEMD_FAILED",
                None,
                _empty_collection_reason(systemd_collector.status, systemd_collector.coverage),
            )
        )
    for entity in service_entities:
        if not _has_evidence(entity, evidence_by_id, "systemctl.show", "active_state"):
            assessments.append(_not_evaluable("SYSTEMD_FAILED", entity.id, "evidence_unavailable"))
            continue
        if entity.attributes.active_state != "failed":
            assessments.append(_not_triggered("SYSTEMD_FAILED", entity.id))
            continue
        finding = Finding(
            id=f"f:{len(findings) + 1}",
            rule_id="SYSTEMD_FAILED",
            rule_version="1.0.0",
            severity="warning",
            subject_id=entity.id,
            claim="observed",
            evidence_ids=_evidence_ids(entity, evidence_by_id, "systemctl.show", "active_state"),
            message="The loaded systemd service has ActiveState=failed.",
            review_action=(
                "Review the unit state and logs manually; this observation does not identify "
                "a cause."
            ),
        )
        findings.append(finding)
        assessments.append(
            Assessment(
                rule_id="SYSTEMD_FAILED",
                rule_version="1.0.0",
                subject_id=entity.id,
                state="triggered",
                finding_id=finding.id,
                reason_code=None,
            )
        )

    return AssessmentResult(assessment=assessments, findings=findings)


def _has_evidence(
    entity: Entity,
    evidence_by_id: dict[str, Evidence],
    source_name: str,
    *field_names: str,
) -> bool:
    return bool(_evidence_ids(entity, evidence_by_id, source_name, *field_names))


def _evidence_ids(
    entity: Entity,
    evidence_by_id: dict[str, Evidence],
    source_name: str,
    *field_names: str,
) -> list[str]:
    matching: list[str] = []
    for evidence_id in entity.evidence_ids:
        evidence = evidence_by_id.get(evidence_id)
        if evidence is None:
            continue
        if evidence.source.name != source_name:
            continue
        if all(field in evidence.fields for field in field_names):
            matching.append(evidence_id)
    return matching


def _empty_collection_reason(
    status: str,
    coverage: str,
) -> Literal["collector_unsupported", "collector_no_coverage", "no_subjects_observed"]:
    if status == "unsupported":
        return "collector_unsupported"
    if coverage == "none":
        return "collector_no_coverage"
    return "no_subjects_observed"


def _not_evaluable(
    rule_id: Literal["FS_USAGE_HIGH", "SYSTEMD_FAILED"],
    subject_id: str | None,
    reason_code: str,
) -> Assessment:
    return Assessment(
        rule_id=rule_id,
        rule_version="1.0.0",
        subject_id=subject_id,
        state="not_evaluable",
        finding_id=None,
        reason_code=reason_code,
    )


def _not_triggered(
    rule_id: Literal["FS_USAGE_HIGH", "SYSTEMD_FAILED"],
    subject_id: str,
) -> Assessment:
    return Assessment(
        rule_id=rule_id,
        rule_version="1.0.0",
        subject_id=subject_id,
        state="not_triggered",
        finding_id=None,
        reason_code=None,
    )
