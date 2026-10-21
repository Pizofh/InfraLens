"""Natural-key matching primitives for offline snapshot differences."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from infralens.models import ServiceEntity


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
