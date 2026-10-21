"""Natural service-key matching ignores snapshot-local IDs and volatile state."""

from __future__ import annotations

from infralens.diff_matching import match_services
from infralens.models import ServiceEntity


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
