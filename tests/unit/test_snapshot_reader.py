"""Compatibility and bounds for reading offline snapshot files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from infralens.snapshot_reader import MAX_SNAPSHOT_BYTES, SnapshotReadError, load_snapshot

FIXTURE = Path(__file__).parents[1] / "fixtures" / "snapshot_partial.json"


def _payload() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_reader_validates_known_fields_and_retains_additive_fields(tmp_path: Path) -> None:
    payload = _payload()
    payload["future_top_level"] = {"enabled": True}
    payload["host"]["future_host_field"] = "retained"
    payload["entities"][0]["attributes"]["future_attribute"] = 42
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    document = load_snapshot(path)

    assert document.snapshot.schema_version == "1.0.0"
    assert document.raw_data["future_top_level"] == {"enabled": True}
    assert document.raw_data["host"]["future_host_field"] == "retained"
    assert document.raw_data["entities"][0]["attributes"]["future_attribute"] == 42
    assert not hasattr(document.snapshot.host, "future_host_field")
    assert not hasattr(document.snapshot.entities[0].attributes, "future_attribute")


def test_reader_accepts_a_future_minor_version_with_known_major(tmp_path: Path) -> None:
    payload = _payload()
    payload["schema_version"] = "1.7.2"
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    document = load_snapshot(path)

    assert document.source_schema_version == "1.7.2"
    assert document.snapshot.schema_version == "1.0.0"


@pytest.mark.parametrize("version", ["2.0.0", "1.x.0", "1.0", 1])
def test_reader_rejects_unknown_or_malformed_schema_versions(
    tmp_path: Path, version: object
) -> None:
    payload = _payload()
    payload["schema_version"] = version
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SnapshotReadError, match="schema major"):
        load_snapshot(path)


def test_reader_does_not_ignore_unknown_enum_values_or_invalid_known_types(
    tmp_path: Path,
) -> None:
    payload = _payload()
    payload["collectors"][0]["status"] = "future_status"
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SnapshotReadError, match="supported 1.x contract"):
        load_snapshot(path)

    payload = _payload()
    payload["entities"][0]["attributes"]["total_bytes"] = "not-an-integer"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SnapshotReadError, match="supported 1.x contract"):
        load_snapshot(path)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('{"schema_version":"1.0.0","schema_version":"1.0.0"}', "duplicate"),
        ('{"value":NaN}', "non-finite"),
        ('{"value":1e999}', "non-finite"),
        ("[]", "root"),
    ],
)
def test_reader_rejects_ambiguous_or_non_object_json(
    tmp_path: Path, text: str, message: str
) -> None:
    path = tmp_path / "snapshot.json"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(SnapshotReadError, match=message):
        load_snapshot(path)


def test_reader_enforces_the_snapshot_size_limit(tmp_path: Path) -> None:
    path = tmp_path / "snapshot.json"
    path.write_bytes(b" " * (MAX_SNAPSHOT_BYTES + 1))

    with pytest.raises(SnapshotReadError, match="16 MiB"):
        load_snapshot(path)
