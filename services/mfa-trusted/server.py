"""Standalone synthetic-factor verification service for Linux."""

import json
import os
import signal
import socket
import stat
import sys
from pathlib import Path
from time import time
from uuid import UUID

from veriq.mfa_crypto import FactorKeys, matching_counter
from veriq.mfa_ipc import IpcDenied, dispatch


def private_file(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("Unsafe secret file")
        data = stream.read(16385)
        if not data or len(data) > 16384:
            raise ValueError("Invalid secret file size")
        return data


def serve() -> None:
    if sys.platform != "linux" or os.getuid() == 0:
        raise ValueError("Requires an unprivileged Linux UID")
    peer_uid = int(os.environ["VERIQ_MFA_PEER_UID"])
    if peer_uid <= 0 or peer_uid == os.getuid():
        raise ValueError("Requires a distinct unprivileged client UID")
    password = private_file(Path(os.environ["VERIQ_TRUSTED_DB_PASSWORD_FILE"]))
    if not password.strip():
        raise ValueError("Empty database credential")
    ring = json.loads(private_file(Path(os.environ["VERIQ_TRUSTED_KEYRING"])))
    keys = FactorKeys(
        ring["active"], {k: bytes.fromhex(v) for k, v in ring["keys"].items()}
    )
    fixture = json.loads(private_file(Path(os.environ["VERIQ_MFA_SYNTHETIC_FACTOR"])))
    seed = keys.decrypt(
        UUID(fixture["user"]),
        UUID(fixture["factor"]),
        fixture["key_id"],
        bytes.fromhex(fixture["ciphertext"]),
    )
    endpoint = Path(os.environ["VERIQ_MFA_SOCKET"])
    directory = endpoint.parent.lstat()
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != os.getuid()
        or directory.st_mode & 0o027
    ):
        raise ValueError("Unsafe socket directory")
    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    def health(args):
        if args:
            raise IpcDenied("Unexpected arguments")
        return {"ready": True}

    def verify(args):
        code = args.get("code")
        if set(args) != {"code"} or not isinstance(code, str) or len(code) != 6:
            raise IpcDenied("Invalid verification request")
        return {"matches": matching_counter(seed, code, int(time())) is not None}

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    os.umask(0o177)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(endpoint))
        try:
            endpoint.chmod(0o660)
            listener.listen(8)
            listener.settimeout(0.25)
            while not stopped:
                try:
                    peer, _ = listener.accept()
                except TimeoutError:
                    continue
                with peer:
                    peer.settimeout(1)
                    try:
                        response = dispatch(
                            peer,
                            peer_uid,
                            {"health": health, "check_fixture_totp": verify},
                        )
                    except (IpcDenied, OSError):
                        response = {"error": "denied"}
                    try:
                        peer.sendall(json.dumps(response).encode("ascii") + b"\n")
                    except OSError:
                        pass
        finally:
            endpoint.unlink()


if __name__ == "__main__":
    try:
        serve()
    except Exception:  # noqa: BLE001 - never expose config or cryptographic errors
        print("Trusted MFA startup or runtime failure", file=sys.stderr)
        sys.exit(1)
