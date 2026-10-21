"""Compact process identities passed between bounded collector workers."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from infralens.models import UtcTimestamp


class ProcessReference(BaseModel):
    """The fields required to revalidate a process relation in another worker."""

    model_config = ConfigDict(extra="forbid", strict=True)

    id: StrictStr = Field(pattern=r"^process:[1-9][0-9]*$")
    pid: StrictInt = Field(gt=0)
    started_at: UtcTimestamp
