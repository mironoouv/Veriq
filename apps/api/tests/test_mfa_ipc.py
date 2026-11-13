import os
import socket

import pytest

from veriq.mfa_ipc import MAX_REQUEST_BYTES, IpcDenied, dispatch, receive_request

pytestmark = pytest.mark.skipif(
    not hasattr(socket, "SO_PEERCRED"), reason="requires Linux peer credentials"
)


def test_peer_uid_checked_before_reading() -> None:
    client, server = socket.socketpair()
    with client, server, pytest.raises(IpcDenied, match="peer denied"):
        receive_request(server, os.getuid() + 1)


def test_only_registered_operations_are_dispatched() -> None:
    client, server = socket.socketpair()
    with client, server:
        client.sendall(b'{"operation":"health","arguments":{}}\n')
        assert dispatch(server, os.getuid(), {"health": lambda _: {"ready": True}}) == {
            "ready": True
        }

    client, server = socket.socketpair()
    with client, server:
        client.sendall(b'{"operation":"verify","arguments":{"verified":true}}\n')
        with pytest.raises(IpcDenied, match="Unknown"):
            dispatch(server, os.getuid(), {})


def test_oversize_frame_is_rejected() -> None:
    client, server = socket.socketpair()
    with client, server:
        client.sendall(b"x" * (MAX_REQUEST_BYTES + 1))
        with pytest.raises(IpcDenied, match="frame"):
            receive_request(server, os.getuid())
