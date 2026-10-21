"""Conservative comparability checks for two validated snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from infralens.snapshot_reader import SnapshotDocument


class ComparisonIssue(StrEnum):
    """Stable reasons why snapshots cannot be compared globally."""

    SCHEMA_MAJOR_MISMATCH = "schema_major_mismatch"
    SCOPE_NOT_OPERATOR = "scope_not_operator"
    SCOPE_ID_MISMATCH = "scope_id_mismatch"
    UID_UNKNOWN = "uid_unknown"
    UID_MISMATCH = "uid_mismatch"
    EUID_UNKNOWN = "euid_unknown"
    EUID_MISMATCH = "euid_mismatch"
    PID_NAMESPACE_UNKNOWN = "pid_namespace_unknown"
    PID_NAMESPACE_MISMATCH = "pid_namespace_mismatch"
    NET_NAMESPACE_UNKNOWN = "net_namespace_unknown"
    NET_NAMESPACE_MISMATCH = "net_namespace_mismatch"
    MNT_NAMESPACE_UNKNOWN = "mnt_namespace_unknown"
    MNT_NAMESPACE_MISMATCH = "mnt_namespace_mismatch"


@dataclass(frozen=True, slots=True)
class ComparisonPreflight:
    """Preflight result with deterministic, non-sensitive issue codes."""

    issues: tuple[ComparisonIssue, ...]

    @property
    def comparable(self) -> bool:
        return not self.issues


def preflight_comparison(before: SnapshotDocument, after: SnapshotDocument) -> ComparisonPreflight:
    """Require explicit scope and matching, observable collection context."""
    issues: list[ComparisonIssue] = []
    before_major = before.source_schema_version.partition(".")[0]
    after_major = after.source_schema_version.partition(".")[0]
    if before_major != after_major:
        issues.append(ComparisonIssue.SCHEMA_MAJOR_MISMATCH)

    left = before.snapshot
    right = after.snapshot
    if left.scope_origin != "operator" or right.scope_origin != "operator":
        issues.append(ComparisonIssue.SCOPE_NOT_OPERATOR)
    if left.scope_id != right.scope_id:
        issues.append(ComparisonIssue.SCOPE_ID_MISMATCH)

    for field_name, unknown_issue, mismatch_issue in (
        ("uid", ComparisonIssue.UID_UNKNOWN, ComparisonIssue.UID_MISMATCH),
        ("euid", ComparisonIssue.EUID_UNKNOWN, ComparisonIssue.EUID_MISMATCH),
    ):
        left_value = getattr(left.context, field_name)
        right_value = getattr(right.context, field_name)
        if left_value is None or right_value is None:
            issues.append(unknown_issue)
        elif left_value != right_value:
            issues.append(mismatch_issue)

    for namespace_name, unknown_issue, mismatch_issue in (
        (
            "pid",
            ComparisonIssue.PID_NAMESPACE_UNKNOWN,
            ComparisonIssue.PID_NAMESPACE_MISMATCH,
        ),
        (
            "net",
            ComparisonIssue.NET_NAMESPACE_UNKNOWN,
            ComparisonIssue.NET_NAMESPACE_MISMATCH,
        ),
        (
            "mnt",
            ComparisonIssue.MNT_NAMESPACE_UNKNOWN,
            ComparisonIssue.MNT_NAMESPACE_MISMATCH,
        ),
    ):
        left_value = getattr(left.context.namespaces, namespace_name)
        right_value = getattr(right.context.namespaces, namespace_name)
        if left_value is None or right_value is None:
            issues.append(unknown_issue)
        elif left_value != right_value:
            issues.append(mismatch_issue)

    return ComparisonPreflight(tuple(issues))
