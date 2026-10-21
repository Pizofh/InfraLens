"""Regenerate the checked-in snapshot JSON Schema from the producer models."""

from __future__ import annotations

import json
from pathlib import Path

from infralens.models import snapshot_json_schema

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "snapshot-1.0.0.schema.json"


def main() -> None:
    SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCHEMA_PATH.write_text(
        json.dumps(snapshot_json_schema(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
