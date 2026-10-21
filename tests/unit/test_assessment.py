"""Pure rule assessment tests on validated, sanitized snapshot fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from infralens.assessment import assess
from infralens.models import Snapshot

FIXTURE = Path(__file__).parents[1] / "fixtures" / "snapshot_partial.json"


def _snapshot() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _set_filesystem_usage(payload: dict[str, Any], total: int, used: int | None) -> None:
    entity = next(item for item in payload["entities"] if item["kind"] == "filesystem")
    entity["attributes"].update(
        total_bytes=total,
        used_bytes=used,
        free_bytes=0 if total == 0 else total - (used or 0),
    )
    evidence = next(item for item in payload["evidence"] if item["subject_id"] == entity["id"])
    evidence["fields"].update(
        total_bytes=total,
        used_bytes=used,
        free_bytes=0 if total == 0 else total - (used or 0),
    )
    if used is None:
        host_collector = next(item for item in payload["collectors"] if item["id"] == "host")
        host_collector["limitations"].append(
            {
                "code": "filesystem_field_unavailable",
                "message": "Filesystem field used_bytes is unavailable.",
                "subject_id": entity["id"],
            }
        )


def _add_service(payload: dict[str, Any], active_state: str) -> None:
    collector = next(item for item in payload["collectors"] if item["id"] == "systemd")
    collector.update(
        status="ok",
        coverage="complete",
        entity_ids=["service:1"],
        evidence_ids=["e:2", "e:3"],
        errors=[],
        limitations=[],
    )
    payload["entities"].append(
        {
            "id": "service:1",
            "kind": "service",
            "attributes": {
                "name": "api.service",
                "load_state": "loaded",
                "active_state": active_state,
                "sub_state": "running" if active_state == "active" else active_state,
                "main_pid": None,
            },
            "evidence_ids": ["e:2", "e:3"],
        }
    )
    payload["evidence"].extend(
        [
            {
                "id": "e:2",
                "collector_id": "systemd",
                "collected_at": payload["started_at"],
                "source": {"type": "command", "name": "systemctl.list-units"},
                "subject_id": "service:1",
                "claim": "observed",
                "fields": {"name": "api.service"},
                "limitations": [],
            },
            {
                "id": "e:3",
                "collector_id": "systemd",
                "collected_at": payload["started_at"],
                "source": {"type": "command", "name": "systemctl.show"},
                "subject_id": "service:1",
                "claim": "observed",
                "fields": {
                    "name": "api.service",
                    "load_state": "loaded",
                    "active_state": active_state,
                    "sub_state": "running" if active_state == "active" else active_state,
                    "main_pid": None,
                },
                "limitations": [],
            },
        ]
    )
    payload["assessment"] = [
        item
        for item in payload["assessment"]
        if not (item["rule_id"] == "SYSTEMD_FAILED" and item["subject_id"] is None)
    ]
    payload["assessment"].append(
        {
            "rule_id": "SYSTEMD_FAILED",
            "rule_version": "1.0.0",
            "subject_id": "service:1",
            "state": "not_triggered",
            "finding_id": None,
            "reason_code": None,
        }
    )


@pytest.mark.parametrize(
    ("used", "expected_state"),
    [(8_999, "not_triggered"), (9_000, "triggered"), (9_500, "triggered")],
)
def test_filesystem_threshold_is_exact_and_evidence_backed(used: int, expected_state: str) -> None:
    payload = _snapshot()
    _set_filesystem_usage(payload, 10_000, used)
    snapshot = Snapshot.model_validate(payload)

    result = assess(snapshot)

    evaluation = next(item for item in result.assessment if item.rule_id == "FS_USAGE_HIGH")
    assert evaluation.state == expected_state
    assert bool(result.findings) is (expected_state == "triggered")
    if result.findings:
        assert result.findings[0].evidence_ids == ["e:1"]
        assert result.findings[0].rule_id == "FS_USAGE_HIGH"


def test_zero_capacity_and_missing_usage_are_not_evaluable() -> None:
    zero_payload = _snapshot()
    _set_filesystem_usage(zero_payload, 0, 0)
    zero_result = assess(Snapshot.model_validate(zero_payload))
    zero_evaluation = next(
        item for item in zero_result.assessment if item.rule_id == "FS_USAGE_HIGH"
    )
    assert zero_evaluation.state == "not_evaluable"
    assert zero_evaluation.reason_code == "zero_total_capacity"

    no_evidence_payload = _snapshot()
    _set_filesystem_usage(no_evidence_payload, 0, 0)
    evidence = next(item for item in no_evidence_payload["evidence"] if item["id"] == "e:1")
    evidence["fields"] = {"free_bytes": 0}
    no_evidence = assess(Snapshot.model_validate(no_evidence_payload))
    evidence_evaluation = next(
        item for item in no_evidence.assessment if item.rule_id == "FS_USAGE_HIGH"
    )
    assert evidence_evaluation.state == "not_evaluable"
    assert evidence_evaluation.reason_code == "evidence_unavailable"

    missing_payload = _snapshot()
    _set_filesystem_usage(missing_payload, 100, None)
    missing_result = assess(Snapshot.model_validate(missing_payload))
    missing_evaluation = next(
        item for item in missing_result.assessment if item.rule_id == "FS_USAGE_HIGH"
    )
    assert missing_evaluation.state == "not_evaluable"
    assert missing_evaluation.reason_code == "filesystem_usage_unavailable"


@pytest.mark.parametrize(
    ("active_state", "expected_state"),
    [("failed", "triggered"), ("active", "not_triggered")],
)
def test_systemd_rule_uses_only_observed_active_state(
    active_state: str, expected_state: str
) -> None:
    payload = _snapshot()
    _add_service(payload, active_state)
    snapshot = Snapshot.model_validate(payload)

    result = assess(snapshot)

    evaluation = next(
        item
        for item in result.assessment
        if item.rule_id == "SYSTEMD_FAILED" and item.subject_id == "service:1"
    )
    assert evaluation.state == expected_state
    systemd_findings = [item for item in result.findings if item.rule_id == "SYSTEMD_FAILED"]
    assert bool(systemd_findings) is (expected_state == "triggered")
    if systemd_findings:
        assert systemd_findings[0].evidence_ids == ["e:3"]


def test_unsupported_systemd_is_explicitly_not_evaluable() -> None:
    result = assess(Snapshot.model_validate(_snapshot()))

    evaluation = next(item for item in result.assessment if item.rule_id == "SYSTEMD_FAILED")
    assert evaluation.state == "not_evaluable"
    assert evaluation.reason_code == "collector_unsupported"
