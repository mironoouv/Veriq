"""Bounded Linux IPC transport for the trusted MFA process."""

import json
import socket
import struct
from collections.abc import Callable
from typing import Any

MAX_REQUEST_BYTES = 8192
REQUEST_TIMEOUT_SECONDS = 3


class IpcDenied(ValueError):
    """The peer or request is outside the IPC contract."""


def receive_request(peer: socket.socket, allowed_uid: int) -> dict[str, Any]:
    """Authenticate the operating-system peer before reading credentials."""
    if not hasattr(socket, "SO_PEERCRED"):
        raise IpcDenied("Linux peer credentials required")
    layout = struct.Struct("iII")
    credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, layout.size)
    _, uid, _ = layout.unpack(credentials)
    if uid != allowed_uid:
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
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(REQUEST_TIMEOUT_SECONDS)
            peer.connect(endpoint)
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
