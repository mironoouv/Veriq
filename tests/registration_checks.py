"""Registration HTTP, PostgreSQL, Redis, and local mail integration."""

import json
import os
import secrets
import socket
import sys
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, redirect_stderr
from hashlib import sha256
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier, Thread
from time import monotonic, sleep
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

import uvicorn
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import DBAPIError
from veriq.database import database_url
from veriq.main import create_app
from veriq.registration_policy import HASHER
from veriq.verification_mail import LocalMailbox, deliver_verification

INITIAL = "synthetic pre-verification passphrase"
FINAL = "synthetic mailbox owner's new passphrase"
BLOCKED = "synthetic compromised passphrase"
PREFIX = "/api/v1/auth"


@contextmanager
def server() -> Iterator[str]:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        app = create_app(enable_docs=True)
        runtime = uvicorn.Server(
            uvicorn.Config(
                app, log_level="warning", access_log=False, proxy_headers=False
            )
        )
        thread = Thread(target=runtime.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        try:
            deadline = monotonic() + 10
            while not runtime.started and thread.is_alive() and monotonic() < deadline:
                sleep(0.01)
            assert runtime.started
            yield f"http://127.0.0.1:{port}{PREFIX}"
        finally:
            runtime.should_exit = True
            thread.join(10)
            assert not thread.is_alive()


def send(url: str, route: str, **data: str) -> tuple[int, bytes, dict[str, str]]:
    request = Request(
        url + route,
        json.dumps(data).encode() if data else None,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=10) as response:
            return (
                response.status,
                response.read(),
                {name.lower(): value for name, value in response.headers.items()},
            )
    except HTTPError as error:
        with error:
            return (
                error.code,
                error.read(),
                {name.lower(): value for name, value in error.headers.items()},
            )


def assert_denial(engine: Engine, query: str) -> None:
    try:
        with engine.begin() as connection:
            connection.execute(text(query))
    except DBAPIError as error:
        assert getattr(error.orig, "sqlstate", None) == "42501"
    else:
        raise AssertionError("Expected a PostgreSQL permission denial")


def query(engine: Engine, sql: str, **params: Any) -> Any:
    with engine.begin() as connection:
        return connection.execute(text(sql), params).scalar_one()


def checks(url: str, owner: Engine, worker: Engine, cipher: Fernet, root: Path) -> None:
    email = f"slice2-{uuid4().hex}@example.invalid"
    missing = f"missing-{uuid4().hex}@example.invalid"
    barrier = Barrier(2)

    def register(address: str) -> tuple[int, bytes, dict[str, str]]:
        barrier.wait(timeout=10)
        return send(url, "/register", email=address, password=INITIAL)

    with ThreadPoolExecutor(max_workers=2) as executor:
        registrations = list(executor.map(register, (email, f" \t{email.upper()} ")))
    assert [entry[:2] for entry in registrations] == [(202, b""), (202, b"")]
    assert all("set-cookie" not in headers for _, _, headers in registrations)
    assert (
        query(
            owner,
            "SELECT count(*) FROM users WHERE email_normalized=:email",
            email=email,
        )
        == 1
    )
    assert (
        send(url, "/register", email=email, password=INITIAL)[:2]
        == registrations[0][:2]
    )
    assert send(url, "/register", email=missing, password=BLOCKED)[0] == 400
    assert send(url, "/register", email=email, password=BLOCKED)[0] == 400
    assert send(url, "/register", email=missing, password="short")[0] == 400
    result = send(url, "/register", email=missing, password=INITIAL, actor_id="forged")
    assert result[0] == 400 and INITIAL.encode() not in result[1]

    record = query(
        owner,
        "SELECT password_hash FROM users WHERE email_normalized=:email AND disabled_at IS NOT NULL",
        email=email,
    )
    assert record.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert HASHER.verify(record, INITIAL)
    assert query(owner, "SELECT count(*) FROM auth_sessions") == 0
    assert query(owner, "SELECT count(*) FROM auth_credential_proofs") == 0
    assert query(owner, "SELECT count(*) FROM email_verification_outbox") == 1

    # Failed transport retains ciphertext, and retry is throttled by PostgreSQL.
    assert not deliver_verification(worker, cipher, LocalMailbox(root / "missing"))
    assert (
        query(
            owner,
            "SELECT count(*) FROM email_verification_outbox WHERE available_at > now()",
        )
        == 1
    )
    query(owner, "UPDATE email_verification_outbox SET available_at=now() RETURNING 1")
    mailbox = LocalMailbox(root)
    ciphertext = query(owner, "SELECT envelope FROM email_verification_outbox")
    assert deliver_verification(worker, cipher, mailbox)
    assert not deliver_verification(worker, cipher, mailbox)
    first = next(root.glob("*.json"))
    message = json.loads(first.read_text(encoding="utf-8"))
    assert message["recipient"] == email
    original = message["path"].split("#")[1]
    assert original.encode() not in ciphertext and email.encode() not in ciphertext
    assert (
        query(owner, "SELECT digest FROM email_verification_proofs")
        == sha256(original.encode()).digest()
    )
    status, page, headers = send(url, "/verify-email")
    assert status == 200 and b"history.replaceState" in page
    assert headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert (
        query(
            owner,
            "SELECT count(*) FROM users WHERE email_verified_at IS NOT NULL AND email_normalized=:email",
            email=email,
        )
        == 0
    )

    assert send(url, "/resend-verification", email=missing)[:2] == (202, b"")
    assert send(url, "/resend-verification", email=email)[:2] == (202, b"")
    assert deliver_verification(worker, cipher, mailbox)
    second = next(path for path in root.glob("*.json") if path != first)
    proof = json.loads(second.read_text(encoding="utf-8"))["path"].split("#")[1]
    assert proof != original
    assert (
        send(url, "/verify-email", email=email, password=FINAL, proof=original)[0]
        == 400
    )
    wrong_email = send(url, "/verify-email", email=missing, password=FINAL, proof=proof)
    assert wrong_email[0] == 400 and proof.encode() not in wrong_email[1]
    wrong_purpose = send(
        url,
        "/verify-email",
        email=email,
        password=FINAL,
        proof=proof,
        purpose="password_reset",
    )
    assert wrong_purpose[0] == 400 and proof.encode() not in wrong_purpose[1]
    assert (
        send(url, "/verify-email", email=email, password=FINAL, proof="x" + proof)[0]
        == 400
    )

    query(owner, "UPDATE email_verification_proofs SET expires_at=now() RETURNING 1")
    assert (
        send(url, "/verify-email", email=email, password=FINAL, proof=proof)[0] == 400
    )
    assert send(url, "/resend-verification", email=email)[0] == 202
    assert deliver_verification(worker, cipher, mailbox)
    third = next(path for path in root.glob("*.json") if path not in (first, second))
    proof = json.loads(third.read_text(encoding="utf-8"))["path"].split("#")[1]

    def verify(_: int) -> int:
        barrier.wait(timeout=10)
        return send(url, "/verify-email", email=email, password=FINAL, proof=proof)[0]

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert sorted(executor.map(verify, range(2))) == [204, 400]
    assert (
        send(url, "/verify-email", email=email, password=FINAL, proof=proof)[0] == 400
    )
    confirmed = query(
        owner,
        "SELECT password_hash FROM users WHERE email_normalized=:email AND disabled_at IS NULL AND email_verified_at IS NOT NULL",
        email=email,
    )
    assert HASHER.verify(confirmed, FINAL)
    try:
        HASHER.verify(confirmed, INITIAL)
    except VerifyMismatchError:
        pass
    else:
        raise AssertionError("Pre-confirmation password was retained")
    assert send(url, "/resend-verification", email=email)[0] == 202
    limited = send(url, "/resend-verification", email=email)
    assert limited[0] == 429 and int(limited[2]["retry-after"]) > 0
    assert query(owner, "SELECT count(*) FROM email_verification_outbox") == 0
    assert query(owner, "SELECT count(*) FROM auth_sessions") == 0
    assert query(owner, "SELECT count(*) FROM auth_credential_proofs") == 0
    assert (
        query(
            owner,
            "SELECT count(*) FROM auth_audit_events WHERE event_type='registration_attempt' AND actor_id IS NULL AND target_id IS NULL",
        )
        > 0
    )


def main() -> None:
    url = database_url()
    assert url.database is not None and url.database.startswith("memberships_test_")
    api = create_engine(url, hide_parameters=True)
    owner = create_engine(
        url.set(
            username="veriq_dev", password=os.environ["VERIQ_DB_PASSWORD_FOR_TEST"]
        ),
        hide_parameters=True,
    )
    worker = create_engine(
        url.set(
            username="veriq_worker", password=os.environ["VERIQ_WORKER_DB_PASSWORD"]
        ),
        hide_parameters=True,
    )
    try:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            blocklist = root / "blocklist"
            blocklist.write_text(
                sha256(BLOCKED.encode()).hexdigest() + "\n", encoding="ascii"
            )
            key = Fernet.generate_key()
            os.environ.update(
                {
                    "VERIQ_ENV": "test",
                    "VERIQ_ENABLE_TEST_REGISTRATION": "1",
                    "VERIQ_TEST_MAIL_KEY": key.decode("ascii"),
                    "VERIQ_TEST_AUTH_HMAC_KEY": secrets.token_hex(32),
                    "VERIQ_TEST_PASSWORD_BLOCKLIST": str(blocklist),
                }
            )
            if sys.argv[1:] == ["outage"]:
                with server() as address:
                    assert (
                        send(
                            address,
                            "/register",
                            email="outage@example.invalid",
                            password=INITIAL,
                        )[0]
                        == 503
                    )
                print("Registration Redis outage fails closed.")
                return
            assert_denial(api, "SELECT digest FROM email_verification_proofs")
            assert_denial(api, "SELECT envelope FROM email_verification_outbox")
            assert_denial(worker, "SELECT envelope FROM email_verification_outbox")
            assert_denial(
                worker, "SELECT public.veriq_signup_resend(NULL, NULL, NULL, NULL)"
            )
            assert_denial(api, "SELECT * FROM public.veriq_signup_mail_next()")
            assert_denial(
                api,
                "SELECT public.veriq_auth_confirm(NULL, NULL, NULL, NULL, NULL, NULL)",
            )
            captured = StringIO()
            with redirect_stderr(captured), server() as address:
                checks(address, owner, worker, Fernet(key), root)
            secrets_in_mail = [
                json.loads(path.read_text(encoding="utf-8"))["path"].split("#")[1]
                for path in root.glob("*.json")
            ]
            assert all(
                value not in captured.getvalue()
                for value in (INITIAL, FINAL, BLOCKED, *secrets_in_mail)
            )
            os.environ["VERIQ_ENV"] = "production"
            with server() as address:
                assert (
                    send(
                        address,
                        "/register",
                        email="disabled@example.invalid",
                        password=INITIAL,
                    )[0]
                    == 404
                )
            print(
                "Registration: concurrency, Argon2id, proof binding/expiry/replay, encrypted mail retry, rate limits and production gate passed."
            )
    finally:
        api.dispose()
        owner.dispose()
        worker.dispose()


if __name__ == "__main__":
    main()
