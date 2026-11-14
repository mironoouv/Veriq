"""Isolated MFA verification service for Linux."""

import json
import os
import signal
import socket
import stat
import sys
from pathlib import Path
from time import time
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from psycopg import Error, connect
from veriq.mfa_crypto import FactorKeys, matching_counter
from veriq.mfa_ipc import IpcDenied, dispatch
from veriq.sessions import SessionPolicy, SessionToken
from veriq.tenant_access import AccessDenied


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
    host = os.environ.get("VERIQ_TRUSTED_DB_HOST")
    seed = None
    if host is None:
        fixture = json.loads(
            private_file(Path(os.environ["VERIQ_MFA_SYNTHETIC_FACTOR"]))
        )
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
        if host:
            with database() as db:
                db.execute("SELECT 1")
        return {"ready": True}

    def verify(args):
        code = args.get("code")
        if set(args) != {"code"} or not isinstance(code, str) or len(code) != 6:
            raise IpcDenied("Invalid verification request")
        assert seed is not None
        return {"matches": matching_counter(seed, code, int(time())) is not None}

    def database():
        return connect(
            host=host,
            dbname=os.environ["VERIQ_TRUSTED_DB_NAME"],
            user="veriq_mfa_trusted",
            password=password.decode().strip(),
            connect_timeout=2,
            options="-c statement_timeout=2000",
        )

    def attest_disable(args, *, disable=False):
        fields = {
            "account",
            "factor",
            "session",
            "organization",
            "token",
            "code",
        }
        if disable:
            fields.update(("request", "correlation"))
        if set(args) != fields:
            raise IpcDenied("Invalid attestation arguments")
        if any(not isinstance(v, str) for k, v in args.items() if k != "organization"):
            raise IpcDenied("Invalid attestation arguments")
        if args["organization"] is not None and not isinstance(
            args["organization"], str
        ):
            raise IpcDenied("Invalid organization")
        gate = SessionToken(args["token"])._gate(SessionPolicy())
        if gate.session_id != UUID(args["session"]):
            raise IpcDenied("Session mismatch")
        scope = (
            UUID(args["account"]),
            UUID(args["factor"]),
            gate.session_id,
            gate.digest,
            UUID(args["organization"]) if args["organization"] else None,
        )
        with database() as db:
            row = db.execute(
                "SELECT * FROM public.veriq_trusted_mfa_factor(%s,%s,%s,%s,%s)", scope
            ).fetchone()
            if row is None:
                raise IpcDenied("Factor denied")
            key, encrypted, tick = row
            counter = matching_counter(
                keys.decrypt(scope[0], scope[1], key, encrypted), args["code"], tick
            )
            proof = uuid4()
            if counter is None or db.execute(
                "SELECT public.veriq_trusted_mfa_totp(%s,%s,%s,%s,%s,%s,%s,%s)",
                (proof, *scope, counter, encrypted),
            ).fetchone() != (True,):
                raise IpcDenied("Factor denied")
            if disable:
                result = db.execute(
                    "SELECT public.veriq_trusted_mfa_disable(%s,%s,%s,%s,%s,%s,%s)",
                    (
                        proof,
                        *scope[:4],
                        UUID(args["request"]),
                        UUID(args["correlation"]),
                    ),
                ).fetchone()
                if result != (True,):
                    raise IpcDenied("Factor denied")
        return {"disabled": True} if disable else {"attestation": str(proof)}

    disable_handler = {}
    if host and os.environ.get("VERIQ_TEST_TRUSTED_DISABLE") == "1":

        def disable_factor(args):
            return attest_disable(args, disable=True)

        disable_handler["disable_factor"] = disable_factor

    handlers = {
        "health": health,
        **(
            {"attest_disable": attest_disable, **disable_handler}
            if host
            else {"check_fixture_totp": verify}
        ),
    }
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
                            handlers,
                        )
                    except (
                        ValueError,
                        OSError,
                        Error,
                        InvalidTag,
                        KeyError,
                        AccessDenied,
                    ):
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
