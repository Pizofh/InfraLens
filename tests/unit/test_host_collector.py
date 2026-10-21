"""Host metadata and resource collection tests with synthetic providers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from infralens.collectors import host


def _configure_host(monkeypatch, tmp_path: Path, release_text: str) -> None:
    release_path = tmp_path / "os-release"
    release_path.write_text(release_text, encoding="utf-8")
    boot_path = tmp_path / "boot_id"
    boot_path.write_text("e2f4b337-85ca-4c8c-82b5-3df3cc71d691\n", encoding="ascii")
    monkeypatch.setattr(host, "OS_RELEASE_PATHS", (release_path,))
    monkeypatch.setattr(host, "BOOT_ID_PATH", boot_path)
    monkeypatch.setattr(host.platform, "release", lambda: "6.8.0-test")
    monkeypatch.setattr(host.platform, "node", lambda: "infra-test")
    monkeypatch.setattr(host.os, "getuid", lambda: 1000)
    monkeypatch.setattr(host.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        host, "_namespace_inode", lambda name: {"pid": 101, "net": 102, "mnt": 103}[name]
    )
    monkeypatch.setattr(host.psutil, "cpu_count", lambda logical=True: 4)
    monkeypatch.setattr(
        host.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(total=16_000, available=8_000),
    )
    monkeypatch.setattr(host.psutil, "disk_partitions", lambda all=False: [])
    monkeypatch.setattr(host.psutil, "net_if_addrs", lambda: {})
    monkeypatch.setattr(host.psutil, "net_if_stats", lambda: {})


def test_os_release_parser_handles_quotes_without_evaluating_shell(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist"
    values, errors = host.parse_os_release(
        f'ID=ubuntu\nVERSION_ID="24.04 LTS"\nNAME="$(touch {marker})"\n'
    )

    assert errors == []
    assert values["ID"] == "ubuntu"
    assert values["VERSION_ID"] == "24.04 LTS"
    assert "NAME" not in values
    assert not marker.exists()


def test_collect_returns_valid_host_context_resources_and_evidence(
    monkeypatch, tmp_path: Path
) -> None:
    _configure_host(monkeypatch, tmp_path, 'ID=Ubuntu\nVERSION_ID="24.04"\n')

    result = host.collect({})

    assert result.host.os_id == "ubuntu"
    assert result.host.os_version == "24.04"
    assert result.host.kernel == "6.8.0-test"
    assert result.host.hostname == "infra-test"
    assert str(result.host.boot_id) == "e2f4b337-85ca-4c8c-82b5-3df3cc71d691"
    assert result.context.uid == result.context.euid == 1000
    assert result.context.namespaces.model_dump() == {"pid": 101, "net": 102, "mnt": 103}
    resources = result.entities[0]
    assert resources.kind == "host_resources"
    assert resources.attributes.model_dump() == {
        "cpu_logical": 4,
        "memory_total_bytes": 16_000,
        "memory_available_bytes": 8_000,
    }
    assert result.collector.status == "ok"
    assert result.collector.coverage == "complete"
    assert len(result.evidence) == 7
    host_evidence = [item for item in result.evidence if item.subject_id == "host"]
    assert {item.source.name for item in host_evidence} == {
        "os-release",
        "platform.release",
        "platform.node",
        "proc.boot_id",
    }


def test_collect_normalizes_synthetic_rhel_identity(monkeypatch, tmp_path: Path) -> None:
    _configure_host(monkeypatch, tmp_path, 'ID="rhel"\nVERSION_ID="9.5"\n')

    result = host.collect({})

    assert result.host.os_id == "rhel"
    assert result.host.os_version == "9.5"


def test_os_release_uses_fallback_and_records_its_source(monkeypatch, tmp_path: Path) -> None:
    missing = tmp_path / "missing-os-release"
    fallback = tmp_path / "usr-lib-os-release"
    fallback.write_text("ID=debian\nVERSION_ID=13\n", encoding="utf-8")
    monkeypatch.setattr(host, "OS_RELEASE_PATHS", (missing, fallback))

    values, path, errors, notes = host._load_os_release()

    assert values == {"ID": "debian", "VERSION_ID": "13"}
    assert path == fallback
    assert errors == []
    assert notes[0].code == "os_release_fallback"


def test_malformed_os_release_keeps_valid_fields_and_reports_partial_coverage(
    monkeypatch, tmp_path: Path
) -> None:
    _configure_host(monkeypatch, tmp_path, 'ID="ubuntu\nVERSION_ID=24.04\n')

    result = host.collect({})

    assert result.host.os_id is None
    assert result.host.os_version == "24.04"
    assert result.collector.status == "collection_error"
    assert result.collector.coverage == "partial"
    assert any(item.code == "parse_error" for item in result.collector.errors)
    assert any("os_id" in item.message for item in result.limitations)


def test_permission_denied_resource_preserves_other_observations(
    monkeypatch, tmp_path: Path
) -> None:
    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")

    def denied():
        raise PermissionError

    monkeypatch.setattr(host.psutil, "virtual_memory", denied)
    result = host.collect({})

    assert result.collector.status == "permission_denied"
    assert result.collector.coverage == "partial"
    assert result.entities[0].attributes.memory_total_bytes is None
    assert any(item.code == "permission_denied" for item in result.collector.errors)
    assert any(
        item.subject_id == result.entities[0].id and "memory_total_bytes" in item.message
        for item in result.collector.limitations
    )


def test_unavailable_namespace_is_explicit_in_context(monkeypatch, tmp_path: Path) -> None:
    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")

    def namespace_inode(name: str) -> int:
        if name == "net":
            raise PermissionError
        return 100

    monkeypatch.setattr(host, "_namespace_inode", namespace_inode)
    result = host.collect({})

    assert result.context.namespaces.net is None
    assert any("namespace net" in item.message for item in result.context.limitations)


def test_collect_filesystems_sorts_observations_and_records_evidence(
    monkeypatch, tmp_path: Path
) -> None:
    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")
    partitions = [
        SimpleNamespace(device="/dev/z", mountpoint="/z", fstype="ext4"),
        SimpleNamespace(device="/dev/a", mountpoint="/a", fstype="xfs"),
    ]
    monkeypatch.setattr(host.psutil, "disk_partitions", lambda all=False: partitions)
    monkeypatch.setattr(
        host.psutil,
        "disk_usage",
        lambda path: SimpleNamespace(total=1000, used=400, free=600),
    )

    result = host.collect({})

    filesystems = [entity for entity in result.entities if entity.kind == "filesystem"]
    assert [item.attributes.mountpoint for item in filesystems] == ["/a", "/z"]
    assert filesystems[0].attributes.model_dump() == {
        "device": "/dev/a",
        "mountpoint": "/a",
        "fs_type": "xfs",
        "total_bytes": 1000,
        "used_bytes": 400,
        "free_bytes": 600,
    }
    evidence_by_id = {item.id: item for item in result.evidence}
    assert [evidence_by_id[item].source.name for item in filesystems[0].evidence_ids] == [
        "psutil.disk_partitions",
        "psutil.disk_usage",
    ]
    assert result.collector.coverage == "complete"


def test_filesystem_usage_error_preserves_other_mounts(monkeypatch, tmp_path: Path) -> None:
    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")
    monkeypatch.setattr(
        host.psutil,
        "disk_partitions",
        lambda all=False: [
            SimpleNamespace(device="/dev/a", mountpoint="/a", fstype="ext4"),
            SimpleNamespace(device="/dev/b", mountpoint="/b", fstype="xfs"),
        ],
    )

    def disk_usage(mountpoint: str):
        if mountpoint == "/a":
            raise PermissionError
        return SimpleNamespace(total=100, used=40, free=60)

    monkeypatch.setattr(host.psutil, "disk_usage", disk_usage)
    result = host.collect({})

    filesystems = [entity for entity in result.entities if entity.kind == "filesystem"]
    assert filesystems[0].attributes.total_bytes is None
    assert filesystems[1].attributes.total_bytes == 100
    assert result.collector.status == "permission_denied"
    assert result.collector.coverage == "partial"
    assert any(error.operation == "disk_usage" for error in result.collector.errors)
    assert any(item.subject_id == filesystems[0].id for item in result.collector.limitations)


def test_partition_enumeration_denied_is_partial(monkeypatch, tmp_path: Path) -> None:
    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")

    def denied(all=False):
        raise PermissionError

    monkeypatch.setattr(host.psutil, "disk_partitions", denied)
    result = host.collect({})

    assert not [entity for entity in result.entities if entity.kind == "filesystem"]
    assert result.collector.status == "permission_denied"
    assert result.collector.coverage == "partial"
    assert result.collector.errors[-1].operation == "disk_partitions"


def test_filesystem_cap_marks_result_truncated(monkeypatch, tmp_path: Path) -> None:
    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")
    partitions = [
        SimpleNamespace(device=f"/dev/{index:03d}", mountpoint=f"/mnt/{index:03d}", fstype="ext4")
        for index in reversed(range(host.MAX_FILESYSTEMS + 1))
    ]
    usage_calls: list[str] = []
    monkeypatch.setattr(host.psutil, "disk_partitions", lambda all=False: partitions)

    def disk_usage(mountpoint: str):
        usage_calls.append(mountpoint)
        return SimpleNamespace(total=100, used=50, free=50)

    monkeypatch.setattr(host.psutil, "disk_usage", disk_usage)
    result = host.collect({})

    filesystems = [entity for entity in result.entities if entity.kind == "filesystem"]
    assert len(filesystems) == host.MAX_FILESYSTEMS
    assert len(usage_calls) == host.MAX_FILESYSTEMS
    assert filesystems[0].attributes.mountpoint == "/mnt/000"
    assert result.collector.truncated is True
    assert result.collector.coverage == "partial"
    assert any(item.code == "filesystem_limit_reached" for item in result.collector.limitations)


def test_zero_capacity_is_valid_and_invalid_mount_is_reported(monkeypatch, tmp_path: Path) -> None:
    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")
    monkeypatch.setattr(
        host.psutil,
        "disk_partitions",
        lambda all=False: [
            SimpleNamespace(device="/dev/zero", mountpoint="/zero", fstype="tmpfs"),
            SimpleNamespace(device="", mountpoint="/invalid", fstype="tmpfs"),
        ],
    )
    monkeypatch.setattr(
        host.psutil,
        "disk_usage",
        lambda mountpoint: SimpleNamespace(total=0, used=0, free=0),
    )

    result = host.collect({})

    filesystems = [entity for entity in result.entities if entity.kind == "filesystem"]
    assert len(filesystems) == 1
    assert filesystems[0].attributes.total_bytes == 0
    assert filesystems[0].attributes.used_bytes == 0
    assert any(error.code == "parse_error" for error in result.collector.errors)


def test_interfaces_normalize_ip_prefix_and_ipv6_zone(monkeypatch, tmp_path: Path) -> None:
    import socket

    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")
    monkeypatch.setattr(
        host.psutil,
        "net_if_addrs",
        lambda: {
            "eth0": [
                SimpleNamespace(
                    family=socket.AF_INET,
                    address="192.0.2.8",
                    netmask="255.255.255.0",
                ),
                SimpleNamespace(
                    family=socket.AF_INET6,
                    address="fe80::1%7",
                    netmask="ffff:ffff:ffff:ffff::",
                ),
                SimpleNamespace(family=getattr(socket, "AF_PACKET", -1), address="aa:bb"),
            ]
        },
    )
    monkeypatch.setattr(
        host.psutil,
        "net_if_stats",
        lambda: {"eth0": SimpleNamespace(isup=True)},
    )

    result = host.collect({})

    interface = next(entity for entity in result.entities if entity.kind == "interface")
    assert interface.attributes.name == "eth0"
    assert interface.attributes.is_up is True
    assert [address.model_dump() for address in interface.attributes.addresses] == [
        {"family": "ipv4", "address": "192.0.2.8", "prefix_length": 24, "scope_id": None},
        {"family": "ipv6", "address": "fe80::1", "prefix_length": 64, "scope_id": 7},
    ]
    interface_evidence = [item for item in result.evidence if item.subject_id == interface.id]
    assert {item.source.name for item in interface_evidence} == {
        "psutil.net_if_addrs",
        "psutil.net_if_stats",
    }
    stats_evidence = next(item for item in interface_evidence if item.source.name.endswith("stats"))
    assert stats_evidence.fields == {"name": "eth0", "is_up": True}
    assert result.collector.status == "ok"


def test_interface_address_failure_preserves_link_state(monkeypatch, tmp_path: Path) -> None:
    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")

    def denied():
        raise PermissionError

    monkeypatch.setattr(host.psutil, "net_if_addrs", denied)
    monkeypatch.setattr(
        host.psutil,
        "net_if_stats",
        lambda: {"eth0": SimpleNamespace(isup=True)},
    )
    result = host.collect({})

    interface = next(entity for entity in result.entities if entity.kind == "interface")
    assert interface.attributes.is_up is True
    assert interface.attributes.addresses == []
    assert result.collector.status == "permission_denied"
    assert result.collector.coverage == "partial"
    assert any(
        item.subject_id == interface.id and "addresses" in item.message
        for item in result.collector.limitations
    )


def test_interface_stats_failure_preserves_addresses(monkeypatch, tmp_path: Path) -> None:
    import socket

    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")
    monkeypatch.setattr(
        host.psutil,
        "net_if_addrs",
        lambda: {
            "eth0": [SimpleNamespace(family=socket.AF_INET, address="192.0.2.4", netmask=None)]
        },
    )

    def denied():
        raise PermissionError

    monkeypatch.setattr(host.psutil, "net_if_stats", denied)
    result = host.collect({})

    interface = next(entity for entity in result.entities if entity.kind == "interface")
    assert interface.attributes.is_up is None
    assert interface.attributes.addresses[0].address == "192.0.2.4"
    assert result.collector.status == "permission_denied"
    assert any(
        item.subject_id == interface.id and "is_up" in item.message
        for item in result.collector.limitations
    )


def test_unresolved_ipv6_zone_keeps_address_with_scope_limitation(
    monkeypatch, tmp_path: Path
) -> None:
    import socket

    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")
    monkeypatch.setattr(
        host.psutil,
        "net_if_addrs",
        lambda: {
            "eth0": [
                SimpleNamespace(
                    family=socket.AF_INET6,
                    address="fe80::1%not-present",
                    netmask="ffff:ffff:ffff:ffff::",
                )
            ]
        },
    )

    def missing_index(_: str) -> int:
        raise OSError

    monkeypatch.setattr(socket, "if_nametoindex", missing_index)

    result = host.collect({})

    interface = next(entity for entity in result.entities if entity.kind == "interface")
    address = interface.attributes.addresses[0]
    assert address.address == "fe80::1"
    assert address.scope_id is None
    assert result.collector.status == "ok"
    assert any(
        item.subject_id == interface.id and "scope_id" in item.message
        for item in result.collector.limitations
    )


def test_invalid_interface_address_is_omitted_with_partial_coverage(
    monkeypatch, tmp_path: Path
) -> None:
    import socket

    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")
    monkeypatch.setattr(
        host.psutil,
        "net_if_addrs",
        lambda: {
            "eth0": [
                SimpleNamespace(family=socket.AF_INET, address="not-an-ip", netmask="bad-mask")
            ]
        },
    )

    result = host.collect({})

    interface = next(entity for entity in result.entities if entity.kind == "interface")
    assert interface.attributes.addresses == []
    assert result.collector.status == "collection_error"
    assert any(error.operation == "net_if_addrs" for error in result.collector.errors)
    assert any(item.subject_id == interface.id for item in result.collector.limitations)


def test_interface_cap_is_deterministic_and_truncated(monkeypatch, tmp_path: Path) -> None:
    _configure_host(monkeypatch, tmp_path, "ID=ubuntu\nVERSION_ID=24.04\n")
    names = [f"eth{index:03d}" for index in reversed(range(host.MAX_INTERFACES + 1))]
    monkeypatch.setattr(host.psutil, "net_if_addrs", lambda: {name: [] for name in names})
    monkeypatch.setattr(
        host.psutil,
        "net_if_stats",
        lambda: {name: SimpleNamespace(isup=False) for name in names},
    )

    result = host.collect({})

    interfaces = [entity for entity in result.entities if entity.kind == "interface"]
    assert len(interfaces) == host.MAX_INTERFACES
    assert interfaces[0].attributes.name == "eth000"
    assert result.collector.truncated is True
    assert result.collector.coverage == "partial"
    assert any(item.code == "interface_limit_reached" for item in result.collector.limitations)
