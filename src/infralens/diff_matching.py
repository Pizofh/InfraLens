"""Natural-key matching primitives for offline snapshot differences."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from infralens.models import ServiceEntity, SocketEntity


@dataclass(frozen=True, slots=True)
class ServiceMatch:
    """The same loaded unit observed in two snapshots, matched by unit name."""

    name: str
    before: ServiceEntity
    after: ServiceEntity


@dataclass(frozen=True, slots=True)
class ServiceMatching:
    """Service matches and unmatched records, with duplicate keys kept ambiguous."""

    matched: tuple[ServiceMatch, ...]
    before_only: tuple[ServiceEntity, ...]
    after_only: tuple[ServiceEntity, ...]
    ambiguous_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SocketKey:
    """Natural listener identity, excluding snapshot-local owner PID."""

    protocol: str
    family: str
    local_address: str
    local_port: int
    zone_id: int | None


@dataclass(frozen=True, slots=True)
class SocketMatch:
    """The same listening/bound endpoint observed in two snapshots."""

    key: SocketKey
    before: SocketEntity
    after: SocketEntity


@dataclass(frozen=True, slots=True)
class SocketMatching:
    """Socket matches and unmatched records; duplicate natural keys stay ambiguous."""

    matched: tuple[SocketMatch, ...]
    before_only: tuple[SocketEntity, ...]
    after_only: tuple[SocketEntity, ...]
    ambiguous_keys: tuple[SocketKey, ...]


def match_services(
    before: Iterable[ServiceEntity], after: Iterable[ServiceEntity]
) -> ServiceMatching:
    """Match services by name; never guess when a natural key is duplicated."""
    before_by_name: dict[str, list[ServiceEntity]] = defaultdict(list)
    after_by_name: dict[str, list[ServiceEntity]] = defaultdict(list)
    for entity in before:
        before_by_name[entity.attributes.name].append(entity)
    for entity in after:
        after_by_name[entity.attributes.name].append(entity)

    matches: list[ServiceMatch] = []
    before_only: list[ServiceEntity] = []
    after_only: list[ServiceEntity] = []
    ambiguous: list[str] = []
    for name in sorted(before_by_name.keys() | after_by_name.keys()):
        old_items = before_by_name.get(name, [])
        new_items = after_by_name.get(name, [])
        if len(old_items) > 1 or len(new_items) > 1:
            ambiguous.append(name)
        elif old_items and new_items:
            matches.append(ServiceMatch(name, old_items[0], new_items[0]))
        elif old_items:
            before_only.append(old_items[0])
        elif new_items:
            after_only.append(new_items[0])

    return ServiceMatching(
        matched=tuple(matches),
        before_only=tuple(before_only),
        after_only=tuple(after_only),
        ambiguous_names=tuple(ambiguous),
    )


def _socket_key(entity: SocketEntity) -> SocketKey:
    attributes = entity.attributes
    return SocketKey(
        protocol=attributes.protocol,
        family=attributes.family,
        local_address=attributes.local_address,
        local_port=attributes.local_port,
        zone_id=attributes.scope_id,
    )


def _socket_key_sort(key: SocketKey) -> tuple[str, str, str, int, int]:
    zone_order = -1 if key.zone_id is None else key.zone_id
    return (key.protocol, key.family, key.local_address, key.local_port, zone_order)


def match_sockets(before: Iterable[SocketEntity], after: Iterable[SocketEntity]) -> SocketMatching:
    """Match listeners by endpoint tuple and IPv6 zone; ignore owner PID changes."""
    before_by_key: dict[SocketKey, list[SocketEntity]] = defaultdict(list)
    after_by_key: dict[SocketKey, list[SocketEntity]] = defaultdict(list)
    for entity in before:
        before_by_key[_socket_key(entity)].append(entity)
    for entity in after:
        after_by_key[_socket_key(entity)].append(entity)

    matches: list[SocketMatch] = []
    before_only: list[SocketEntity] = []
    after_only: list[SocketEntity] = []
    ambiguous: list[SocketKey] = []
    keys = before_by_key.keys() | after_by_key.keys()
    for key in sorted(keys, key=_socket_key_sort):
        old_items = before_by_key.get(key, [])
        new_items = after_by_key.get(key, [])
        if len(old_items) > 1 or len(new_items) > 1:
            ambiguous.append(key)
        elif old_items and new_items:
            matches.append(SocketMatch(key, old_items[0], new_items[0]))
        elif old_items:
            before_only.append(old_items[0])
        elif new_items:
            after_only.append(new_items[0])

    return SocketMatching(
        matched=tuple(matches),
        before_only=tuple(before_only),
        after_only=tuple(after_only),
        ambiguous_keys=tuple(ambiguous),
    )
