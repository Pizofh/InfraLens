"""Minimal and bounded process collector tests."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import psutil

from infralens.collectors import processes


class FakeProcess:
    def __init__(
        self,
        pid: int,
        *,
        name: str = "worker",
        uid: int = 1000,
        create_time: float = 1_750_000_000.25,
    ) -> None:
        self.pid = pid
        self._name = name
        self._uid = uid
        self._create_time = create_time

    def create_time(self) -> float:
        return self._create_time

    def name(self) -> str:
        return self._name

    def uids(self) -> SimpleNamespace:
        return SimpleNamespace(real=self._uid)


def test_collect_is_minimal_sorted_and_evidence_backed(monkeypatch) -> None:
    monkeypatch.setattr(
        processes.psutil,
        "process_iter",
        lambda: [FakeProcess(8), FakeProcess(2, name="api")],
    )

    result = processes.collect({})

    assert [entity.attributes.pid for entity in result.entities] == [2, 8]
    assert result.entities[0].attributes.name == "api"
    assert result.entities[0].attributes.started_at == datetime.fromtimestamp(1_750_000_000.25, UTC)
    assert result.entities[0].attributes.uid == 1000
    evidence = {item.id: item for item in result.evidence}
    assert evidence[result.entities[0].evidence_ids[0]].fields == {
        "pid": 2,
        "started_at": "2025-06-15T15:06:40.250000Z",
        "name": "api",
        "uid": 1000,
    }
    assert result.collector.status == "ok"
    assert result.collector.coverage == "complete"


def test_disappearing_process_keeps_other_fields_and_scopes_limitations(monkeypatch) -> None:
    process = FakeProcess(17)

    def disappeared() -> str:
        raise psutil.NoSuchProcess(process.pid)

    process.name = disappeared  # type: ignore[method-assign]
    monkeypatch.setattr(processes.psutil, "process_iter", lambda: [process])

    result = processes.collect({})

    entity = result.entities[0]
    assert entity.attributes.pid == 17
    assert entity.attributes.name is None
    assert entity.attributes.started_at is not None
    assert result.collector.coverage == "partial"
    assert any(
        item.subject_id == entity.id and "name" in item.message
        for item in result.collector.limitations
    )


def test_access_denied_uid_keeps_process_record(monkeypatch) -> None:
    process = FakeProcess(23)

    def denied():
        raise psutil.AccessDenied(process.pid)

    process.uids = denied  # type: ignore[method-assign]
    monkeypatch.setattr(processes.psutil, "process_iter", lambda: [process])

    result = processes.collect({})

    assert result.entities[0].attributes.uid is None
    assert result.collector.status == "permission_denied"
    assert result.collector.coverage == "partial"
    assert result.collector.errors[0].operation == "process_iter"


def test_process_iterator_permission_denied_has_no_coverage(monkeypatch) -> None:
    def denied():
        raise psutil.AccessDenied

    monkeypatch.setattr(processes.psutil, "process_iter", denied)

    result = processes.collect({})

    assert result.entities == []
    assert result.evidence == []
    assert result.collector.status == "permission_denied"
    assert result.collector.coverage == "none"


def test_process_limit_is_deterministic_and_truncated(monkeypatch) -> None:
    monkeypatch.setattr(
        processes.psutil,
        "process_iter",
        lambda: (FakeProcess(pid) for pid in range(1, processes.MAX_PROCESSES + 2)),
    )

    result = processes.collect({})

    assert len(result.entities) == processes.MAX_PROCESSES
    assert result.entities[0].attributes.pid == 1
    assert result.entities[-1].attributes.pid == processes.MAX_PROCESSES
    assert result.collector.truncated is True
    assert result.collector.coverage == "partial"
    assert any(item.code == "process_limit_reached" for item in result.collector.limitations)


def test_collector_never_reads_sensitive_process_properties(monkeypatch) -> None:
    process = FakeProcess(31)

    def forbidden():
        raise AssertionError("sensitive process property must not be read")

    process.cmdline = forbidden  # type: ignore[attr-defined]
    process.environ = forbidden  # type: ignore[attr-defined]
    process.cwd = forbidden  # type: ignore[attr-defined]
    process.open_files = forbidden  # type: ignore[attr-defined]
    monkeypatch.setattr(processes.psutil, "process_iter", lambda: [process])

    result = processes.collect({})

    assert len(result.entities) == 1
