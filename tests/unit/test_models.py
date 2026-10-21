"""Contract tests for the versioned snapshot producer models."""

import copy
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from infralens.models import Snapshot, SocketAttributes, snapshot_json_schema

FIXTURE = Path(__file__).parents[1] / "fixtures" / "snapshot_partial.json"
SCHEMA = Path(__file__).parents[2] / "schemas" / "snapshot-1.0.0.schema.json"


@pytest.fixture
def partial_snapshot() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _duplicate_entity(data: dict[str, Any]) -> None:
    data["entities"].append(copy.deepcopy(data["entities"][0]))


def _dangling_entity_evidence(data: dict[str, Any]) -> None:
    data["entities"][0]["evidence_ids"] = ["e:99"]


def _invalid_unsupported_coverage(data: dict[str, Any]) -> None:
    data["collectors"][-1]["coverage"] = "partial"


def _non_z_timestamp(data: dict[str, Any]) -> None:
    data["finished_at"] = data["finished_at"].replace("Z", "+00:00")


def _unknown_host_field(data: dict[str, Any]) -> None:
    data["host"]["unreviewed"] = "value"


def _mismatched_evidence(data: dict[str, Any]) -> None:
    data["evidence"][0]["fields"]["used_bytes"] = 0


def _unreported_unknown_host_field(data: dict[str, Any]) -> None:
    data["limitations"][0]["message"] = "hostname unavailable"


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (_duplicate_entity, "duplicate entity id"),
        (_dangling_entity_evidence, "unknown evidence"),
        (_invalid_unsupported_coverage, "unsupported/skipped"),
        (_non_z_timestamp, "timestamp must be RFC3339"),
        (_unknown_host_field, "Extra inputs are not permitted"),
        (_mismatched_evidence, "fields do not match"),
        (_unreported_unknown_host_field, "unknown host field boot_id"),
    ],
)
def test_invalid_snapshots_are_rejected(
    partial_snapshot: dict[str, Any], mutate: Callable[[dict[str, Any]], None], message: str
) -> None:
    candidate = copy.deepcopy(partial_snapshot)
    mutate(candidate)

    with pytest.raises(ValidationError, match=message):
        Snapshot.model_validate(candidate)


def test_contract_fixture_validates_with_partial_coverage(
    partial_snapshot: dict[str, Any],
) -> None:
    contract_path = Path(__file__).parents[2] / "docs" / "DATA_CONTRACT.md"
    contract = contract_path.read_text(encoding="utf-8")
    example = re.search(r"```json\n(.*?)\n```", contract, re.DOTALL)
    assert example is not None
    assert json.loads(example.group(1)) == partial_snapshot
    snapshot = Snapshot.model_validate(partial_snapshot)

    assert snapshot.schema_version == "1.0.0"
    assert snapshot.collectors[0].status == "permission_denied"
    assert snapshot.collectors[-1].status == "unsupported"
    assert snapshot.findings[0].rule_id == "FS_USAGE_HIGH"
    assert snapshot.assessment[-1].state == "not_evaluable"
    assert "T14:00:00Z" in snapshot.model_dump_json()


def test_generated_schema_is_versioned_and_discriminates_entities() -> None:
    schema = snapshot_json_schema()
    checked_in = json.loads(SCHEMA.read_text(encoding="utf-8"))

    assert schema == checked_in
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "urn:infralens:snapshot:1.0.0"
    entity_union = schema["$defs"]["Entity"]
    assert entity_union["discriminator"]["propertyName"] == "kind"
    assert set(entity_union["discriminator"]["mapping"]) == {
        "host_resources",
        "filesystem",
        "interface",
        "process",
        "socket",
        "service",
    }
    assert len(schema["x-infralens-invariants"]) >= 5
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for fixture in FIXTURE.parent.glob("snapshot_*.json"):
        validator.validate(json.loads(fixture.read_text(encoding="utf-8")))


def test_snapshot_finish_must_follow_start(partial_snapshot: dict[str, Any]) -> None:
    partial_snapshot["finished_at"] = "2026-10-21T13:59:59Z"

    with pytest.raises(ValidationError, match="finished_at precedes started_at"):
        Snapshot.model_validate(partial_snapshot)


def test_udp_socket_cannot_claim_tcp_listen_state() -> None:
    with pytest.raises(ValidationError, match="TCP sockets must be listen"):
        SocketAttributes.model_validate(
            {
                "protocol": "udp",
                "family": "ipv4",
                "local_address": "127.0.0.1",
                "local_port": 5353,
                "state": "listen",
                "pid": None,
            }
        )


def test_verified_socket_process_relation_is_preserved() -> None:
    path = FIXTURE.with_name("snapshot_process_socket.json")
    snapshot = Snapshot.model_validate_json(path.read_text(encoding="utf-8"))

    assert len(snapshot.relations) == 1
    assert snapshot.relations[0].type == "owned_by"
    assert snapshot.relations[0].claim == "observed"


def test_unknown_socket_owner_has_a_limit_without_an_invented_relation() -> None:
    path = FIXTURE.with_name("snapshot_unknown_owner.json")
    snapshot = Snapshot.model_validate_json(path.read_text(encoding="utf-8"))

    socket = next(entity for entity in snapshot.entities if entity.kind == "socket")
    assert socket.attributes.pid is None
    assert snapshot.relations == []
    assert any(
        limitation.subject_id == socket.id and "PID" in limitation.message
        for evidence in snapshot.evidence
        for limitation in evidence.limitations
    )


def test_host_metadata_can_have_direct_evidence(partial_snapshot: dict[str, Any]) -> None:
    partial_snapshot["collectors"][0]["evidence_ids"].append("e:2")
    partial_snapshot["evidence"].append(
        {
            "id": "e:2",
            "collector_id": "host",
            "collected_at": "2026-10-21T14:00:00Z",
            "source": {"type": "file", "name": "os-release", "locator": "/etc/os-release"},
            "subject_id": "host",
            "claim": "observed",
            "fields": {"os_id": "ubuntu"},
            "limitations": [],
        }
    )

    snapshot = Snapshot.model_validate(partial_snapshot)

    assert snapshot.evidence[-1].subject_id == "host"


def test_host_evidence_must_match_observed_host_fields(partial_snapshot: dict[str, Any]) -> None:
    partial_snapshot["collectors"][0]["evidence_ids"].append("e:2")
    partial_snapshot["evidence"].append(
        {
            "id": "e:2",
            "collector_id": "host",
            "collected_at": "2026-10-21T14:00:00Z",
            "source": {"type": "file", "name": "os-release", "locator": "/etc/os-release"},
            "subject_id": "host",
            "claim": "observed",
            "fields": {"os_id": "rhel"},
            "limitations": [],
        }
    )

    with pytest.raises(ValidationError, match="fields do not match"):
        Snapshot.model_validate(partial_snapshot)
