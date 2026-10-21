"""TCP/UDP socket normalization and conservative ownership-link tests."""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from types import SimpleNamespace

import psutil

from infralens.collectors import sockets
from infralens.models import ProcessAttributes, ProcessEntity


def _process_entity(pid: int = 23, started_at: datetime | None = None) -> ProcessEntity:
    return ProcessEntity(
        id="process:1",
        kind="process",
        attributes=ProcessAttributes(
            pid=pid,
            started_at=started_at or datetime.fromtimestamp(1_750_000_000.25, UTC),
            name="api",
            uid=1000,
        ),
        evidence_ids=["e:1"],
    )


def _connection(
    *,
    family=socket.AF_INET,
    socket_type=socket.SOCK_STREAM,
    status=psutil.CONN_LISTEN,
    address="127.0.0.1",
    port=8080,
    pid=23,
):
    return SimpleNamespace(
        family=family,
        type=socket_type,
        status=status,
        laddr=SimpleNamespace(ip=address, port=port),
        pid=pid,
    )


def test_collect_filters_normalizes_and_links_verified_process(monkeypatch) -> None:
    connections = [
        _connection(address="0.0.0.0", port=8080),
        _connection(address="0.0.0.0", port=8080),
        _connection(
            socket_type=socket.SOCK_DGRAM,
            status=psutil.CONN_NONE,
            address="::",
            family=socket.AF_INET6,
            port=5353,
            pid=None,
        ),
        _connection(status="ESTABLISHED", port=443),
    ]
    monkeypatch.setattr(sockets.psutil, "net_connections", lambda kind: connections)
    monkeypatch.setattr(sockets.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        sockets.psutil,
        "Process",
        lambda pid: SimpleNamespace(create_time=lambda: 1_750_000_000.25),
    )

    result = sockets.collect({"processes": [_process_entity().model_dump(mode="json")]})

    assert [(item.attributes.protocol, item.attributes.state) for item in result.entities] == [
        ("tcp", "listen"),
        ("udp", "bound"),
    ]
    assert result.entities[0].attributes.local_address == "0.0.0.0"
    assert len(result.relations) == 1
    assert result.relations[0].from_id == result.entities[0].id
    assert result.relations[0].to_id == "process:1"
    assert result.relations[0].evidence_ids == result.entities[0].evidence_ids
    assert result.collector.status == "ok"
    assert result.collector.coverage == "complete"


def test_reused_pid_does_not_create_ownership_relation(monkeypatch) -> None:
    monkeypatch.setattr(sockets.psutil, "net_connections", lambda kind: [_connection()])
    monkeypatch.setattr(sockets.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        sockets.psutil,
        "Process",
        lambda pid: SimpleNamespace(create_time=lambda: 1_750_000_100.0),
    )

    result = sockets.collect({"processes": [_process_entity().model_dump(mode="json")]})

    assert result.relations == []
    assert result.collector.coverage == "partial"
    assert any(item.subject_id == "socket:1" for item in result.collector.limitations)


def test_connection_permission_denial_is_reported_without_records(monkeypatch) -> None:
    def denied(kind: str):
        raise psutil.AccessDenied

    monkeypatch.setattr(sockets.psutil, "net_connections", denied)
    monkeypatch.setattr(sockets.os, "geteuid", lambda: 0)

    result = sockets.collect({})

    assert result.entities == []
    assert result.collector.status == "permission_denied"
    assert result.collector.coverage == "none"
    assert result.collector.errors[0].operation == "net_connections"


def test_non_root_socket_visibility_is_always_partial(monkeypatch) -> None:
    monkeypatch.setattr(sockets.psutil, "net_connections", lambda kind: [_connection(pid=None)])
    monkeypatch.setattr(sockets.os, "geteuid", lambda: 1000)

    result = sockets.collect({})

    assert result.collector.status == "ok"
    assert result.collector.coverage == "partial"
    assert any(item.code == "visibility_not_guaranteed" for item in result.collector.limitations)


def test_invalid_pid_becomes_unknown_and_is_reported(monkeypatch) -> None:
    monkeypatch.setattr(sockets.psutil, "net_connections", lambda kind: [_connection(pid=0)])
    monkeypatch.setattr(sockets.os, "geteuid", lambda: 0)

    result = sockets.collect({})

    assert len(result.entities) == 1
    assert result.entities[0].attributes.pid is None
    assert result.collector.status == "collection_error"
    assert any(error.code == "parse_error" for error in result.collector.errors)


def test_ipv6_link_local_scope_is_preserved_from_zone_or_sockaddr(monkeypatch) -> None:
    zone = _connection(
        family=socket.AF_INET6,
        address="fe80::1%3",
        port=8081,
        pid=None,
    )
    sockaddr = SimpleNamespace(
        family=socket.AF_INET6,
        type=socket.SOCK_STREAM,
        status=psutil.CONN_LISTEN,
        laddr=("fe80::2", 8082, 0, 4),
        pid=None,
    )
    monkeypatch.setattr(sockets.psutil, "net_connections", lambda kind: [zone, sockaddr])
    monkeypatch.setattr(sockets.os, "geteuid", lambda: 0)

    result = sockets.collect({})

    assert [entity.attributes.scope_id for entity in result.entities] == [3, 4]
    assert not any(item.code == "socket_scope_unknown" for item in result.collector.limitations)


def test_socket_limit_is_deterministic_and_truncated(monkeypatch) -> None:
    connections = [
        _connection(address="127.0.0.1", port=index, pid=None)
        for index in range(1, sockets.MAX_SOCKETS + 2)
    ]
    monkeypatch.setattr(sockets.psutil, "net_connections", lambda kind: connections)
    monkeypatch.setattr(sockets.os, "geteuid", lambda: 0)

    result = sockets.collect({})

    assert len(result.entities) < sockets.MAX_SOCKETS
    assert result.collector.truncated is True
    assert result.collector.coverage == "partial"
    assert len(result.model_dump_json().encode("utf-8")) <= sockets.MAX_SOCKET_RESULT_BYTES
    assert any(item.code == "socket_result_size_limit" for item in result.collector.limitations)
