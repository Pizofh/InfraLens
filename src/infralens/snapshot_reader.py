"""Read supported snapshot 1.x documents without weakening producer validation."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from types import UnionType
from typing import Annotated, Any, Union, get_args, get_origin

from pydantic import BaseModel, ValidationError

from infralens.models import Snapshot

MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
_VERSION_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class SnapshotReadError(ValueError):
    """A snapshot could not be safely parsed as a supported document."""


@dataclass(frozen=True, slots=True)
class SnapshotDocument:
    """Validated known semantics plus the original JSON, including additive fields."""

    snapshot: Snapshot
    source_schema_version: str
    raw_data: dict[str, Any]


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotReadError("snapshot contains a duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonstandard_number(value: str) -> None:
    raise SnapshotReadError("snapshot contains a non-finite JSON number")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise SnapshotReadError("snapshot contains a non-finite JSON number")
    return parsed


def _model_for_discriminated_value(annotation: Any, value: object) -> Any | None:
    if hasattr(annotation, "__value__"):
        annotation = annotation.__value__
    origin = get_origin(annotation)
    if origin is Annotated:
        annotation = get_args(annotation)[0]
        origin = get_origin(annotation)
    if origin not in (Union, UnionType) or not isinstance(value, dict):
        return None

    for candidate in get_args(annotation):
        if hasattr(candidate, "__value__"):
            candidate = candidate.__value__
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            discriminator = candidate.model_fields.get("kind")
            if discriminator is not None and value.get("kind") in get_args(
                discriminator.annotation
            ):
                return candidate
    return None


def _drop_unknown_model_fields(value: Any, annotation: Any) -> Any:
    """Drop only undeclared object properties; preserve typed maps and array order."""
    if hasattr(annotation, "__value__"):
        return _drop_unknown_model_fields(value, annotation.__value__)

    origin = get_origin(annotation)
    if origin is Annotated:
        return _drop_unknown_model_fields(value, get_args(annotation)[0])

    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        if not isinstance(value, dict):
            return value
        return {
            name: _drop_unknown_model_fields(value[name], field.annotation)
            for name, field in annotation.model_fields.items()
            if name in value
        }

    if origin is list:
        item_type = get_args(annotation)[0]
        if isinstance(value, list):
            return [_drop_unknown_model_fields(item, item_type) for item in value]
        return value

    if origin is dict:
        value_type = get_args(annotation)[1]
        if isinstance(value, dict):
            return {
                key: _drop_unknown_model_fields(item, value_type) for key, item in value.items()
            }
        return value

    model = _model_for_discriminated_value(annotation, value)
    if model is not None:
        return _drop_unknown_model_fields(value, model)
    return value


def load_snapshot(path: str | Path) -> SnapshotDocument:
    """Read a bounded JSON snapshot and validate its known 1.x contract."""
    try:
        with Path(path).open("rb") as source:
            payload = source.read(MAX_SNAPSHOT_BYTES + 1)
    except OSError as exc:
        raise SnapshotReadError(f"cannot read snapshot (errno {exc.errno})") from None

    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise SnapshotReadError("snapshot exceeds the 16 MiB read limit")
    try:
        text = payload.decode("utf-8")
        raw_data = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_nonstandard_number,
            parse_float=_parse_finite_float,
        )
    except UnicodeDecodeError:
        raise SnapshotReadError("snapshot is not valid UTF-8") from None
    except (json.JSONDecodeError, RecursionError):
        raise SnapshotReadError("snapshot is not valid JSON") from None

    if not isinstance(raw_data, dict):
        raise SnapshotReadError("snapshot root must be a JSON object")
    version = raw_data.get("schema_version")
    match = _VERSION_RE.fullmatch(version) if isinstance(version, str) else None
    if match is None or match.group(1) != "1":
        raise SnapshotReadError("snapshot schema major is unsupported; expected 1.x")

    known_data = _drop_unknown_model_fields(raw_data, Snapshot)
    # The strict producer model describes 1.0.0; semver-compatible 1.x documents
    # validate against those known semantics while raw_data retains their version.
    known_data["schema_version"] = "1.0.0"
    try:
        snapshot = Snapshot.model_validate(known_data)
    except (ValidationError, TypeError, ValueError, RecursionError):
        raise SnapshotReadError("snapshot fields do not match the supported 1.x contract") from None

    return SnapshotDocument(snapshot, version, raw_data)
