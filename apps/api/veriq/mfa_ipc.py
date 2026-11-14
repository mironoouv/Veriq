"""Bounded Linux IPC transport for the trusted MFA process."""

import json
import socket
import stat
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any

MAX_REQUEST_BYTES = 8192
REQUEST_TIMEOUT_SECONDS = 3
TRUSTED_SERVICE_UID = 10002


class IpcDenied(ValueError):
    """The peer or request is outside the IPC contract."""


def peer_uid(peer: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise IpcDenied("Linux peer credentials required")
    layout = struct.Struct("iII")
    credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, layout.size)
    return int(layout.unpack(credentials)[1])


def receive_request(peer: socket.socket, allowed_uid: int) -> dict[str, Any]:
    """Authenticate the operating-system peer before reading credentials."""
    if peer_uid(peer) != allowed_uid:
        raise IpcDenied("MFA IPC peer denied")

    peer.settimeout(REQUEST_TIMEOUT_SECONDS)
    with peer.makefile("rb") as stream:
        frame = stream.readline(MAX_REQUEST_BYTES + 1)
    if len(frame) > MAX_REQUEST_BYTES or not frame.endswith(b"\n"):
        raise IpcDenied("Invalid MFA IPC frame")
    try:
        request = json.loads(frame)
    except (ValueError, RecursionError):
        raise IpcDenied("Invalid MFA IPC request") from None
    if not isinstance(request, dict):
        raise IpcDenied("Expected an MFA IPC object")
    return request


def dispatch(
    peer: socket.socket,
    allowed_uid: int,
    handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]],
) -> dict[str, Any]:
    """Route only registered operations. Handlers must authorize their subjects."""
    request = receive_request(peer, allowed_uid)
    operation = request.get("operation")
    arguments = request.get("arguments")
    if (
        set(request) != {"operation", "arguments"}
        or not isinstance(operation, str)
        or not isinstance(arguments, dict)
        or operation not in handlers
    ):
        raise IpcDenied("Unknown or invalid MFA IPC operation")
    return handlers[operation](arguments)


def disable_factor(
    endpoint: str,
    *,
    account: str,
    factor: str,
    session: str,
    organization: str | None,
    token: str,
    code: str,
    request: str,
    correlation: str,
) -> None:
    """Internal test adapter. Any transport error or rejection fails closed."""
    arguments = {
        "account": account,
        "factor": factor,
        "session": session,
        "organization": organization,
        "token": token,
        "code": code,
        "request": request,
        "correlation": correlation,
    }
    frame = json.dumps({"operation": "disable_factor", "arguments": arguments}).encode()
    if len(frame) >= MAX_REQUEST_BYTES:
        raise IpcDenied("MFA operation denied")
    try:
        directory = Path(endpoint).parent.lstat()
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != TRUSTED_SERVICE_UID
            or directory.st_mode & 0o022
        ):
            raise IpcDenied("MFA operation denied")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(REQUEST_TIMEOUT_SECONDS)
            peer.connect(endpoint)
            if peer_uid(peer) != TRUSTED_SERVICE_UID:
                raise IpcDenied("MFA operation denied")
            peer.sendall(frame + b"\n")
            with peer.makefile("rb") as stream:
                response = stream.readline(MAX_REQUEST_BYTES + 1)
        if len(response) <= MAX_REQUEST_BYTES and response.endswith(b"\n"):
            body = json.loads(response)
            if (
                isinstance(body, dict)
                and set(body) == {"disabled"}
                and body["disabled"] is True
            ):
                return
    except (OSError, ValueError, RecursionError):
        pass
    raise IpcDenied("MFA operation denied")
