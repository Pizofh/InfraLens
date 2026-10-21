"""Preflight refuses comparisons across unknown or mismatched scopes."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from infralens.diff_preflight import (
    ComparisonIssue,
    preflight_comparison,
)
from infralens.snapshot_reader import SnapshotDocument, load_snapshot

FIXTURE = Path(__file__).parents[1] / "fixtures" / "snapshot_partial.json"
NAMESPACES = {"pid": 4026531836, "net": 4026531840, "mnt": 4026531841}


def _document(
    tmp_path: Path,
    name: str,
    *,
    scope_id: str = "39cb65cb-a089-4208-82f7-d636cdb7bef1",
    scope_origin: str = "operator",
    schema_version: str = "1.0.0",
    uid: int | None = 1000,
    euid: int | None = 1000,
    namespaces: dict[str, int | None] | None = None,
) -> SnapshotDocument:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["scope_id"] = scope_id
    payload["scope_origin"] = scope_origin
    payload["schema_version"] = schema_version
    payload["context"]["uid"] = uid
    payload["context"]["euid"] = euid
    payload["context"]["namespaces"] = dict(namespaces or NAMESPACES)
    for name_, value in (("uid", uid), ("euid", euid)):
        if value is None:
            payload["context"]["limitations"].append(
                {"code": "context_unknown", "message": f"{name_} no disponible"}
            )
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return load_snapshot(path)


def test_preflight_accepts_same_operator_scope_and_known_context(tmp_path: Path) -> None:
    before = _document(tmp_path, "before")
    after = _document(tmp_path, "after", schema_version="1.8.3")

    result = preflight_comparison(before, after)

    assert result.comparable
    assert result.issues == ()


def test_preflight_rejects_generated_scope_even_when_ids_match(tmp_path: Path) -> None:
    before = _document(tmp_path, "before", scope_origin="generated")
    after = _document(tmp_path, "after", scope_origin="generated")

    result = preflight_comparison(before, after)

    assert result.issues == (ComparisonIssue.SCOPE_NOT_OPERATOR,)


def test_preflight_rejects_scope_id_mismatch(tmp_path: Path) -> None:
    before = _document(tmp_path, "before")
    after = _document(tmp_path, "after", scope_id="ddf9f114-b783-4d2c-b394-b0f4d8be32fc")

    result = preflight_comparison(before, after)

    assert result.issues == (ComparisonIssue.SCOPE_ID_MISMATCH,)


def test_preflight_rejects_user_identity_mismatch(tmp_path: Path) -> None:
    before = _document(tmp_path, "before", uid=1000, euid=1000)
    after = _document(tmp_path, "after", uid=1001, euid=0)

    result = preflight_comparison(before, after)

    assert result.issues == (ComparisonIssue.UID_MISMATCH, ComparisonIssue.EUID_MISMATCH)


@pytest.mark.parametrize(
    ("field", "issue"),
    [("uid", ComparisonIssue.UID_UNKNOWN), ("euid", ComparisonIssue.EUID_UNKNOWN)],
)
def test_preflight_rejects_unknown_user_identity(
    tmp_path: Path, field: str, issue: ComparisonIssue
) -> None:
    before = _document(tmp_path, "before")
    after = _document(tmp_path, "after", **{field: None})

    result = preflight_comparison(before, after)

    assert issue in result.issues


@pytest.mark.parametrize(
    ("namespace", "issue"),
    [
        ("pid", ComparisonIssue.PID_NAMESPACE_MISMATCH),
        ("net", ComparisonIssue.NET_NAMESPACE_MISMATCH),
        ("mnt", ComparisonIssue.MNT_NAMESPACE_MISMATCH),
    ],
)
def test_preflight_rejects_namespace_mismatch(
    tmp_path: Path, namespace: str, issue: ComparisonIssue
) -> None:
    before = _document(tmp_path, "before")
    changed = {**NAMESPACES, namespace: 4026531900}
    after = _document(tmp_path, "after", namespaces=changed)

    result = preflight_comparison(before, after)

    assert result.issues == (issue,)


@pytest.mark.parametrize(
    ("namespace", "issue"),
    [
        ("pid", ComparisonIssue.PID_NAMESPACE_UNKNOWN),
        ("net", ComparisonIssue.NET_NAMESPACE_UNKNOWN),
        ("mnt", ComparisonIssue.MNT_NAMESPACE_UNKNOWN),
    ],
)
def test_preflight_rejects_unknown_namespaces(
    tmp_path: Path, namespace: str, issue: ComparisonIssue
) -> None:
    before = _document(tmp_path, "before")
    unknown = {**NAMESPACES, namespace: None}
    after = _document(tmp_path, "after", namespaces=unknown)

    result = preflight_comparison(before, after)

    assert issue in result.issues


def test_preflight_rejects_different_schema_majors(tmp_path: Path) -> None:
    document = _document(tmp_path, "before")
    future_major = replace(document, source_schema_version="2.0.0")

    result = preflight_comparison(document, future_major)

    assert result.issues == (ComparisonIssue.SCHEMA_MAJOR_MISMATCH,)
