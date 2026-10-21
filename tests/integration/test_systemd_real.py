"""Optional C14 validation against a real system manager in an isolated lab."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from uuid import uuid4

import pytest

from infralens.scan import scan_local


@pytest.mark.integration
@pytest.mark.systemd
def test_failed_transient_unit_is_observed_and_cleaned_up() -> None:
    systemd_run = shutil.which("systemd-run")
    systemctl = shutil.which("systemctl")
    if (
        not os.path.exists("/run/systemd/system")
        or systemctl is None
        or systemd_run is None
        or getattr(os, "geteuid", lambda: 1)() != 0
    ):
        pytest.skip("C14 requires a real systemd manager and root-capable test harness")
    manager = subprocess.run(
        [systemctl, "show", "--property=Version", "--value"],
        check=False,
        capture_output=True,
        timeout=2,
    )
    if manager.returncode != 0:
        pytest.skip("C14 systemd manager is not reachable")

    unit_name = f"infralens-c14-{uuid4().hex}.service"
    false_binary = shutil.which("false")
    if false_binary is None:
        pytest.skip("C14 requires the harmless false test command")

    started = False
    try:
        started = True
        launch = subprocess.run(
            [
                systemd_run,
                f"--unit={unit_name}",
                "--service-type=oneshot",
                "--property=RemainAfterExit=yes",
                "--wait",
                false_binary,
            ],
            check=False,
            capture_output=True,
            timeout=10,
        )
        assert launch.returncode != 0

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            state = subprocess.run(
                [systemctl, "show", "--property=ActiveState", "--value", unit_name],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
            if state.returncode == 0 and state.stdout.strip() == "failed":
                break
            time.sleep(0.05)
        else:
            pytest.fail("the temporary systemd service did not reach failed state")

        snapshot = scan_local()
        service = next(
            (
                entity
                for entity in snapshot.entities
                if entity.kind == "service" and entity.attributes.name == unit_name
            ),
            None,
        )
        assert service is not None
        assert service.attributes.active_state == "failed"
        assessment = next(
            item
            for item in snapshot.assessment
            if item.rule_id == "SYSTEMD_FAILED" and item.subject_id == service.id
        )
        assert assessment.state == "triggered"
        finding = next(item for item in snapshot.findings if item.id == assessment.finding_id)
        assert finding.rule_id == "SYSTEMD_FAILED"
        assert finding.subject_id == service.id
    finally:
        if started:
            subprocess.run(
                [systemctl, "stop", unit_name],
                check=False,
                capture_output=True,
                timeout=5,
            )
            subprocess.run(
                [systemctl, "reset-failed", unit_name],
                check=False,
                capture_output=True,
                timeout=5,
            )
