"""Exercise socket visibility against a controlled local listener."""

from __future__ import annotations

import socket
import sys

import pytest

from infralens.collectors import sockets


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux psutil socket semantics")
def test_listener_is_observed_and_disappears_after_close() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        result = sockets.collect({})
        if result.collector.status == "permission_denied":
            pytest.skip("the runner cannot read socket tables")
        assert any(
            entity.attributes.local_address == "127.0.0.1"
            and entity.attributes.local_port == port
            and entity.attributes.protocol == "tcp"
            and entity.attributes.state == "listen"
            for entity in result.entities
        )
    finally:
        listener.close()

    after_close = sockets.collect({})
    assert not any(
        entity.attributes.local_address == "127.0.0.1"
        and entity.attributes.local_port == port
        and entity.attributes.protocol == "tcp"
        and entity.attributes.state == "listen"
        for entity in after_close.entities
    )
