"""Natural service-key matching ignores snapshot-local IDs and volatile state."""

from __future__ import annotations

import pytest

from infralens.diff_matching import match_services, match_sockets
from infralens.models import ServiceEntity, SocketEntity


def _service(
    ordinal: int,
    name: str,
    *,
    active_state: str = "active",
    main_pid: int | None = 42,
) -> ServiceEntity:
    return ServiceEntity.model_validate(
        {
            "id": f"service:{ordinal}",
            "kind": "service",
            "evidence_ids": [f"e:{ordinal}"],
            "attributes": {
                "name": name,
                "load_state": "loaded",
                "active_state": active_state,
                "sub_state": "running" if active_state == "active" else "dead",
                "main_pid": main_pid,
            },
        }
    )


def _socket(
    ordinal: int,
    *,
    protocol: str = "tcp",
    family: str = "ipv4",
    address: str = "127.0.0.1",
    port: int = 8080,
    state: str = "listen",
    pid: int | None = 42,
    zone_id: int | None = None,
) -> SocketEntity:
    return SocketEntity.model_validate(
        {
            "id": f"socket:{ordinal}",
            "kind": "socket",
            "evidence_ids": [f"e:{ordinal}"],
            "attributes": {
                "protocol": protocol,
                "family": family,
                "local_address": address,
                "local_port": port,
                "state": state,
                "pid": pid,
                "scope_id": zone_id,
            },
        }
    )


def test_services_match_by_name_not_local_ids_state_or_main_pid() -> None:
    before = [_service(1, "zeta.service"), _service(2, "alpha.service")]
    after = [
        _service(8, "alpha.service", active_state="inactive", main_pid=None),
        _service(9, "zeta.service", main_pid=999),
    ]

    result = match_services(before, after)

    assert [match.name for match in result.matched] == ["alpha.service", "zeta.service"]
    assert result.matched[0].before.id == "service:2"
    assert result.matched[0].after.id == "service:8"
    assert result.before_only == ()
    assert result.after_only == ()
    assert result.ambiguous_names == ()


def test_services_return_unmatched_keys_in_stable_order() -> None:
    before = [_service(1, "zeta.service"), _service(2, "beta.service")]
    after = [_service(3, "alpha.service"), _service(4, "zeta.service")]

    result = match_services(before, after)

    assert [entity.attributes.name for entity in result.before_only] == ["beta.service"]
    assert [entity.attributes.name for entity in result.after_only] == ["alpha.service"]
    assert [match.name for match in result.matched] == ["zeta.service"]


def test_duplicate_natural_keys_are_ambiguous_not_arbitrarily_paired() -> None:
    before = [_service(1, "api.service"), _service(2, "api.service")]
    after = [_service(3, "api.service")]

    result = match_services(before, after)

    assert result.matched == ()
    assert result.before_only == ()
    assert result.after_only == ()
    assert result.ambiguous_names == ("api.service",)


def test_duplicates_on_either_snapshot_side_are_never_reported_as_added_or_removed() -> None:
    before = [_service(1, "api.service")]
    after = [_service(2, "api.service"), _service(3, "api.service")]

    result = match_services(before, after)

    assert result.matched == ()
    assert result.before_only == ()
    assert result.after_only == ()
    assert result.ambiguous_names == ("api.service",)


def test_matching_does_not_consume_generators_or_mutate_entities() -> None:
    before = [_service(1, "api.service")]
    after = [_service(2, "api.service")]

    result = match_services(iter(before), iter(after))

    assert result.matched[0].before is before[0]
    assert result.matched[0].after is after[0]
    assert before[0].attributes.active_state == "active"


def test_sockets_match_by_endpoint_even_when_owner_pid_changes() -> None:
    before = [_socket(1, pid=42)]
    after = [_socket(9, pid=987)]

    result = match_sockets(before, after)

    assert len(result.matched) == 1
    assert result.matched[0].before.id == "socket:1"
    assert result.matched[0].after.id == "socket:9"
    assert result.before_only == ()
    assert result.after_only == ()


def test_sockets_match_stably_by_protocol_family_address_port_and_zone() -> None:
    before = [
        _socket(1, protocol="udp", state="bound", address="0.0.0.0", port=5353),
        _socket(2, protocol="tcp", address="127.0.0.1", port=9000),
    ]
    after = [
        _socket(4, protocol="tcp", address="127.0.0.1", port=9000),
        _socket(3, protocol="udp", state="bound", address="0.0.0.0", port=5353),
    ]

    result = match_sockets(before, after)

    assert [item.key.local_port for item in result.matched] == [9000, 5353]
    assert result.ambiguous_keys == ()


def test_sockets_with_different_ipv6_zones_are_not_matched() -> None:
    before = [_socket(1, family="ipv6", address="fe80::1", zone_id=2)]
    after = [_socket(2, family="ipv6", address="fe80::1", zone_id=3)]

    result = match_sockets(before, after)

    assert result.matched == ()
    assert result.before_only == tuple(before)
    assert result.after_only == tuple(after)


@pytest.mark.parametrize(
    "changed_socket",
    [
        {"protocol": "udp", "state": "bound"},
        {"family": "ipv6", "address": "::1"},
        {"address": "127.0.0.2"},
        {"port": 8081},
    ],
)
def test_each_endpoint_component_is_part_of_the_socket_key(
    changed_socket: dict[str, object],
) -> None:
    before = [_socket(1)]
    after = [_socket(2, **changed_socket)]

    result = match_sockets(before, after)

    assert result.matched == ()
    assert result.before_only == tuple(before)
    assert result.after_only == tuple(after)


def test_duplicate_socket_keys_are_ambiguous_not_arbitrarily_paired() -> None:
    before = [_socket(1), _socket(2)]
    after = [_socket(3)]

    result = match_sockets(before, after)

    assert result.matched == ()
    assert result.before_only == ()
    assert result.after_only == ()
    assert len(result.ambiguous_keys) == 1
