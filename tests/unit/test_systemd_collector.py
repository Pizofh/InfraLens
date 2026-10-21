"""systemctl capability, allowlist, parsing, and MainPID link tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from infralens.collectors import systemd
from infralens.models import ProcessAttributes, ProcessEntity
from infralens.runner import CommandResult


def _success(stdout: bytes = b"") -> CommandResult:
    return CommandResult(0, stdout, 0, False, False)


def _service_output(main_pid: int | str = 0, *, active: str = "active") -> bytes:
    return (
        "Id=api.service\n"
        "LoadState=loaded\n"
        f"ActiveState={active}\n"
        "SubState=running\n"
        f"MainPID={main_pid}\n"
    ).encode()


def _process_entity(pid: int = 42) -> ProcessEntity:
    return ProcessEntity(
        id="process:1",
        kind="process",
        attributes=ProcessAttributes(
            pid=pid,
            started_at=datetime.fromtimestamp(1_750_000_000.25, UTC),
            name="api",
            uid=1000,
        ),
        evidence_ids=["e:1"],
    )


def test_collects_allowlisted_properties_and_ignores_descriptions(
    monkeypatch, tmp_path: Path
) -> None:
    runtime = tmp_path / "systemd"
    runtime.mkdir()
    monkeypatch.setattr(systemd, "SYSTEMD_RUNTIME", runtime)
    commands: list[list[str]] = []

    def run(argv, deadline, stdout_limit):
        commands.append(argv)
        if argv == ["systemctl", "--version"]:
            return _success(b"systemd 255\n")
        if argv[1] == "list-units":
            return _success(b"api.service loaded active running TOP_SECRET_DESCRIPTION\n")
        return _success(_service_output(main_pid=0) + b"Description=SECOND_SECRET\n")

    monkeypatch.setattr(systemd, "run_command", run)
    result = systemd.collect({})

    assert result.collector.status == "ok"
    assert result.collector.coverage == "complete"
    assert result.entities[0].attributes.name == "api.service"
    assert result.entities[0].attributes.main_pid is None
    assert commands[-1] == [
        "systemctl",
        "show",
        "--property=Id,LoadState,ActiveState,SubState,MainPID",
        "--",
        "api.service",
    ]
    serialized = result.model_dump_json()
    assert "TOP_SECRET_DESCRIPTION" not in serialized
    assert "SECOND_SECRET" not in serialized


def test_main_pid_link_requires_matching_process_and_repeated_service_state(
    monkeypatch, tmp_path: Path
) -> None:
    runtime = tmp_path / "systemd"
    runtime.mkdir()
    monkeypatch.setattr(systemd, "SYSTEMD_RUNTIME", runtime)
    show_calls = 0

    def run(argv, deadline, stdout_limit):
        nonlocal show_calls
        if argv == ["systemctl", "--version"]:
            return _success(b"systemd 255\n")
        if argv[1] == "list-units":
            return _success(b"api.service loaded active running description\n")
        show_calls += 1
        return _success(_service_output(main_pid=42))

    monkeypatch.setattr(systemd, "run_command", run)
    monkeypatch.setattr(
        systemd.psutil,
        "Process",
        lambda pid: SimpleNamespace(create_time=lambda: 1_750_000_000.25),
    )

    result = systemd.collect({"processes": [_process_entity().model_dump(mode="json")]})

    assert show_calls == 2
    assert len(result.relations) == 1
    assert result.relations[0].from_id == "service:1"
    assert result.relations[0].to_id == "process:1"
    assert result.relations[0].rationale_code == "main_pid_revalidated"


def test_changed_main_pid_or_active_state_does_not_create_relation(
    monkeypatch, tmp_path: Path
) -> None:
    runtime = tmp_path / "systemd"
    runtime.mkdir()
    monkeypatch.setattr(systemd, "SYSTEMD_RUNTIME", runtime)
    show_calls = 0

    def run(argv, deadline, stdout_limit):
        nonlocal show_calls
        if argv == ["systemctl", "--version"]:
            return _success()
        if argv[1] == "list-units":
            return _success(b"api.service loaded active running description\n")
        show_calls += 1
        return _success(_service_output(42, active="active" if show_calls == 1 else "inactive"))

    monkeypatch.setattr(systemd, "run_command", run)
    monkeypatch.setattr(
        systemd.psutil,
        "Process",
        lambda pid: SimpleNamespace(create_time=lambda: 1_750_000_000.25),
    )

    result = systemd.collect({"processes": [_process_entity().model_dump(mode="json")]})

    assert result.relations == []
    assert any(item.subject_id == "service:1" for item in result.collector.limitations)


def test_missing_runtime_is_unsupported_but_manager_command_failure_is_error(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(systemd, "SYSTEMD_RUNTIME", tmp_path / "absent")
    monkeypatch.setattr(systemd, "run_command", lambda argv, deadline, stdout_limit: _success())

    unsupported = systemd.collect({})

    assert unsupported.collector.status == "unsupported"
    assert unsupported.collector.coverage == "none"
    assert unsupported.collector.limitations

    runtime = tmp_path / "systemd"
    runtime.mkdir()
    monkeypatch.setattr(systemd, "SYSTEMD_RUNTIME", runtime)

    def disconnected(argv, deadline, stdout_limit):
        if argv == ["systemctl", "--version"]:
            return _success()
        return CommandResult(1, b"", 0, False, False)

    monkeypatch.setattr(systemd, "run_command", disconnected)
    failed = systemd.collect({})
    assert failed.collector.status == "collection_error"
    assert failed.collector.errors[0].operation == "systemctl_list_units"
    assert failed.collector.coverage == "none"

    def denied(argv, deadline, stdout_limit):
        if argv == ["systemctl", "--version"]:
            return _success()
        return CommandResult(None, b"", 0, False, False, error="permission_denied")

    monkeypatch.setattr(systemd, "run_command", denied)
    permission = systemd.collect({})
    assert permission.collector.status == "permission_denied"
    assert permission.collector.errors[0].code == "permission_denied"


def test_bad_unit_name_and_malformed_show_are_reported_without_raw_output(
    monkeypatch, tmp_path: Path
) -> None:
    runtime = tmp_path / "systemd"
    runtime.mkdir()
    monkeypatch.setattr(systemd, "SYSTEMD_RUNTIME", runtime)

    def run(argv, deadline, stdout_limit):
        if argv == ["systemctl", "--version"]:
            return _success()
        if argv[1] == "list-units":
            return _success(
                b"bad;unit.service loaded active running SECRET\n"
                b"api.service loaded active running\n"
            )
        return _success(
            b"Id=api.service\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=badSECRET\n"
        )

    monkeypatch.setattr(systemd, "run_command", run)
    result = systemd.collect({})

    assert len(result.entities) == 1
    assert result.entities[0].attributes.main_pid is None
    assert result.collector.status == "collection_error"
    assert result.collector.coverage == "partial"
    serialized = result.model_dump_json()
    assert "SECRET" not in serialized
    assert any(item.subject_id == "service:1" for item in result.collector.limitations)


def test_service_limit_is_truncated(monkeypatch, tmp_path: Path) -> None:
    runtime = tmp_path / "systemd"
    runtime.mkdir()
    monkeypatch.setattr(systemd, "SYSTEMD_RUNTIME", runtime)
    show_count = 0

    def run(argv, deadline, stdout_limit):
        nonlocal show_count
        if argv == ["systemctl", "--version"]:
            return _success()
        if argv[1] == "list-units":
            listing = "".join(
                f"unit{index:04d}.service loaded active running description\n"
                for index in range(systemd.MAX_SERVICES + 1)
            )
            return _success(listing.encode())
        show_count += 1
        name = argv[-1]
        return _success(
            f"Id={name}\nLoadState=loaded\nActiveState=active\nSubState=running\nMainPID=0\n".encode()
        )

    monkeypatch.setattr(systemd, "run_command", run)
    result = systemd.collect({})

    assert len(result.entities) == systemd.MAX_SERVICES
    assert show_count == systemd.MAX_SERVICES
    assert result.collector.truncated is True
    assert result.collector.coverage == "partial"
    assert any(item.code == "service_limit_reached" for item in result.collector.limitations)
