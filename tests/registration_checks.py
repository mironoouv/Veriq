"""Registration HTTP, PostgreSQL, Redis, and local mail integration."""

import base64
import json
import os
import secrets
import socket
import ssl
import sys
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, redirect_stderr
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from io import StringIO
from ipaddress import IPv4Address
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier, Thread
from time import monotonic, sleep
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

import uvicorn
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from psycopg import Connection as PsycopgConnection
from psycopg import sql
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import DBAPIError
from veriq.auth_audit import RequestContext
from veriq.auth_credentials import CredentialVerifier
from veriq.browser_login import PasswordLogin
from veriq.database import database_url
from veriq.main import create_app
from veriq.mfa import Mfa
from veriq.mfa_crypto import FactorKeys, totp
from veriq.registration_policy import HASHER
from veriq.sessions import Sessions
from veriq.tenant_access import AccessDenied
from veriq.verification_mail import LocalMailbox, deliver_verification

INITIAL = "synthetic pre-verification passphrase"
FINAL = "synthetic mailbox owner's new passphrase"
BLOCKED = "synthetic compromised passphrase"
PREFIX = "/api/v1/auth"


@contextmanager
def server(certfile: Path | None = None, keyfile: Path | None = None) -> Iterator[str]:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        scheme = "https" if certfile is not None else "http"
        if certfile is not None:
            os.environ["VERIQ_TEST_LOGIN_ORIGIN"] = f"https://127.0.0.1:{port}"
        app = create_app(enable_docs=True)
        runtime = uvicorn.Server(
            uvicorn.Config(
                app,
                log_level="warning",
                access_log=False,
                proxy_headers=False,
                ssl_certfile=str(certfile) if certfile is not None else None,
                ssl_keyfile=str(keyfile) if keyfile is not None else None,
            )
        )
        thread = Thread(target=runtime.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        try:
            deadline = monotonic() + 10
            while not runtime.started and thread.is_alive() and monotonic() < deadline:
                sleep(0.01)
            assert runtime.started
            yield f"{scheme}://127.0.0.1:{port}{PREFIX}"
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


def checks(url: str, owner: Engine, worker: Engine, cipher: Fernet, root: Path) -> str:
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
    assert send(url, "/resend-verification", email=email.upper())[:2] == (202, b"")
    assert not deliver_verification(worker, cipher, mailbox)
    assert (
        query(owner, "SELECT digest FROM email_verification_proofs")
        == sha256(original.encode()).digest()
    )
    proof = original
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
    third = next(path for path in root.glob("*.json") if path != first)
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

    return email


def browser_checks(
    address: str, tls: ssl.SSLContext, owner: Engine, email: str
) -> None:
    origin = address.removesuffix(PREFIX)
    csrf_cookie = ""
    csrf_token = ""
    session_cookie = ""

    def request(
        path: str,
        *,
        method: str = "GET",
        data: dict[str, str | None] | None = None,
        site: str = origin,
        token: str | None = None,
    ) -> tuple[int, bytes, list[str]]:
        headers = {
            "Origin": site,
            "Cookie": "; ".join(filter(None, (csrf_cookie, session_cookie))),
            "Content-Type": "application/json",
            "X-Veriq-CSRF-Bootstrap": "1",
            "X-CSRF-Token": csrf_token if token is None else token,
        }
        call = Request(
            origin + "/api/v1" + path,
            json.dumps(data).encode() if data is not None else None,
            headers,
            method=method,
        )
        try:
            with urlopen(call, timeout=10, context=tls) as result:
                return (
                    result.status,
                    result.read(),
                    result.headers.get_all("Set-Cookie", []),
                )
        except HTTPError as error:
            with error:
                return error.code, error.read(), error.headers.get_all("Set-Cookie", [])

    def bootstrap() -> None:
        nonlocal csrf_cookie, csrf_token
        status, payload, cookies = request("/auth/csrf")
        assert status == 200
        csrf_cookie = cookies[0].split(";", 1)[0]
        csrf_token = json.loads(payload)["csrf_token"]

    def session_value(cookies: list[str]) -> str:
        cookie = next(
            value for value in cookies if value.startswith("__Host-veriq-session=")
        )
        for attribute in ("HttpOnly", "Secure", "SameSite=lax", "Path=/"):
            assert attribute in cookie
        assert "Domain=" not in cookie
        return cookie.split(";", 1)[0]

    bootstrap()
    credentials: dict[str, str | None] = {"email": email.upper(), "password": FINAL}
    assert request("/auth/login", method="POST", data=credentials, token="")[0] == 403
    assert (
        request(
            "/auth/login",
            method="POST",
            data=credentials,
            site="https://other.example.invalid",
        )[0]
        == 403
    )
    for denied in (
        {"email": email, "password": INITIAL},
        {"email": "unknown@example.invalid", "password": FINAL},
    ):
        status, payload, cookies = request(
            "/auth/login", method="POST", data={**denied}
        )
        assert (
            status == 401
            and json.loads(payload)["error"]["code"] == "INVALID_CREDENTIALS"
            and not cookies
        )
    assert (
        request("/auth/login", method="POST", data={**credentials, "mfa_level": "1"})[0]
        == 400
    )
    assert (
        request(
            "/auth/login",
            method="POST",
            data={**credentials, "organization_id": str(uuid4())},
        )[0]
        == 401
    )

    query(
        owner,
        "UPDATE users SET disabled_at=now() WHERE email_normalized=:email RETURNING 1",
        email=email,
    )
    assert request("/auth/login", method="POST", data=credentials)[0] == 401
    query(
        owner,
        "UPDATE users SET disabled_at=NULL, email_verified_at=NULL WHERE email_normalized=:email RETURNING 1",
        email=email,
    )
    assert request("/auth/login", method="POST", data=credentials)[0] == 401
    query(
        owner,
        "UPDATE users SET email_verified_at=now() WHERE email_normalized=:email RETURNING 1",
        email=email,
    )

    user_id = query(
        owner, "SELECT id FROM users WHERE email_normalized=:email", email=email
    )
    organization = query(
        owner,
        "SELECT organization_id FROM organization_roles WHERE code='org_admin' ORDER BY organization_id LIMIT 1",
    )
    membership = uuid4()
    query(
        owner,
        """
        INSERT INTO organization_memberships (id, organization_id, user_id, status)
        VALUES (:id, :org, :user, 'active') RETURNING id
        """,
        id=membership,
        org=organization,
        user=user_id,
    )
    older = PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1).hash(FINAL)
    query(
        owner,
        "UPDATE users SET password_hash=:hash WHERE id=:id RETURNING 1",
        hash=older,
        id=user_id,
    )
    status, _, cookies = request(
        "/auth/login",
        method="POST",
        data={**credentials, "organization_id": str(organization)},
    )
    assert status == 204
    upgraded = query(owner, "SELECT password_hash FROM users WHERE id=:id", id=user_id)
    assert upgraded != older and HASHER.verify(upgraded, FINAL)
    assert not HASHER.check_needs_rehash(upgraded)
    session_cookie = session_value(cookies)
    status, payload, _ = request("/me")
    assert status == 200 and json.loads(payload)["organization_id"] == str(organization)
    bootstrap()
    assert request("/auth/logout", method="POST")[0] == 204
    session_cookie = ""
    bootstrap()
    role = query(
        owner,
        "SELECT id FROM organization_roles WHERE organization_id=:org AND code='org_admin'",
        org=organization,
    )
    query(
        owner,
        """
        INSERT INTO membership_roles (organization_id, membership_id, role_id)
        VALUES (:org, :member, :role) RETURNING membership_id
        """,
        org=organization,
        member=membership,
        role=role,
    )
    assert (
        request(
            "/auth/login",
            method="POST",
            data={**credentials, "organization_id": str(organization)},
        )[0]
        == 401
    )

    status, _, cookies = request("/auth/login", method="POST", data=credentials)
    assert status == 204
    session_cookie = session_value(cookies)
    assert request("/me")[0] == 200
    assert request("/auth/logout", method="POST")[0] == 403
    bootstrap()
    assert (
        request(
            "/auth/sessions/rotate",
            method="POST",
            data={"organization_id": str(organization)},
        )[0]
        == 401
    )
    old = session_cookie
    status, _, cookies = request(
        "/auth/sessions/rotate", method="POST", data={"organization_id": None}
    )
    assert status == 204
    replacement = session_value(cookies)
    assert replacement != old
    session_cookie = old
    assert request("/me")[0] == 401
    session_cookie = replacement
    bootstrap()
    assert request("/auth/logout", method="POST")[0] == 204
    assert request("/me")[0] == 401
    assert (
        query(
            owner,
            "SELECT count(*) FROM auth_sessions WHERE user_id=:user AND mfa_level<>0",
            user=user_id,
        )
        == 0
    )
    with owner.connect() as connection:
        phases = connection.execute(
            text("""
                SELECT e.result, array_agg(a.event_type ORDER BY a.event_type) AS types
                FROM auth_audit_events AS e
                JOIN auth_audit_events AS a USING (request_id, correlation_id)
                WHERE e.target_id = :user AND e.event_type IN ('session_issued', 'login_mfa_required')
                GROUP BY e.id
                """),
            {"user": user_id},
        ).all()
    assert (
        sum(
            row.types == ["password_verified", "session_issued"]
            and row.result == "succeeded"
            for row in phases
        )
        == 2
    )
    assert (
        sum(
            row.types == ["login_mfa_required", "password_verified"]
            and row.result == "denied"
            for row in phases
        )
        == 1
    )
    assert (
        query(
            owner,
            """
        SELECT count(*) FROM auth_audit_events
        WHERE target_id=:user AND event_type='session_rotated' AND result='succeeded'
        """,
            user=user_id,
        )
        == 1
    )
    print(
        "Browser login: TLS, credential denials, tenant/MFA, CSRF, cookies, rotation and logout passed."
    )


def tls_fixture(root: Path) -> tuple[Path, Path, ssl.SSLContext]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Veriq test loopback")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(IPv4Address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = root / "tls.pem", root / "tls-key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certfile, keyfile, ssl.create_default_context(cafile=str(certfile))


def rehash_race(owner: Engine, verifier: CredentialVerifier) -> None:
    account = uuid4()
    email = f"rehash-race-{account.hex}@example.invalid"
    old = PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1).hash(FINAL)
    new = HASHER.hash("synthetic replacement credential")
    query(
        owner,
        """INSERT INTO users (id, email_normalized, email_verified_at, password_hash)
           VALUES (:id, :email, now(), :hash) RETURNING id""",
        id=account,
        email=email,
        hash=old,
    )
    passwords = PasswordLogin(verifier)
    candidate = passwords.check(email, FINAL)
    assert candidate is not None and candidate.replacement is not None
    assert HASHER.verify(candidate.replacement, FINAL)
    assert passwords.check(email, INITIAL) is None
    assert passwords.check("unknown-rehash@example.invalid", FINAL) is None

    def confirm() -> None:
        verifier.confirm_password(
            candidate.user_id,
            candidate.version,
            organization_id=None,
            expected_hash=candidate.password_hash,
            replacement=candidate.replacement,
            context=RequestContext.new(),
        )

    with ThreadPoolExecutor(max_workers=1) as executor:
        with owner.begin() as connection:
            connection.execute(
                text(
                    "SELECT pg_advisory_xact_lock(hashtextextended(CAST(:id AS text), 7007))"
                ),
                {"id": account},
            )
            connection.execute(
                text("""
                UPDATE users SET password_hash = :hash, credential_version = credential_version + 1
                WHERE id = :id
            """),
                {"id": account, "hash": new},
            )
            result = executor.submit(confirm)
            try:
                result.result(timeout=0.2)
            except TimeoutError:
                pass
            else:
                raise AssertionError("Password confirmation bypassed the account lock")
        try:
            result.result(timeout=10)
        except AccessDenied:
            pass
        else:
            raise AssertionError(
                "Stale password confirmation survived credential change"
            )

    assert (
        query(owner, "SELECT password_hash FROM users WHERE id=:id", id=account) == new
    )
    assert (
        query(owner, "SELECT credential_version FROM users WHERE id=:id", id=account)
        == candidate.version + 1
    )
    assert (
        query(
            owner,
            "SELECT count(*) FROM auth_credential_proofs WHERE user_id=:id",
            id=account,
        )
        == 0
    )
    assert passwords.check(email, FINAL) is None
    assert passwords.check(email, "synthetic replacement credential") is not None
    print(
        "Argon2id race: concurrent password change preserved the replacement credential and blocked stale proof."
    )


def provision_browser_roles(owner: Engine) -> None:
    with owner.begin() as connection:
        driver = connection.connection.driver_connection
        assert isinstance(driver, PsycopgConnection)
        for role, variable in (
            ("veriq_password_verifier", "VERIQ_TEST_LOGIN_VERIFIER_PASSWORD"),
            ("veriq_browser_issuer", "VERIQ_TEST_LOGIN_ISSUER_PASSWORD"),
            ("veriq_mfa_verifier", "VERIQ_TEST_MFA_DB_PASSWORD"),
        ):
            password = secrets.token_hex(32)
            verifier = driver.pgconn.encrypt_password(
                password.encode(), role.encode(), b"scram-sha-256"
            ).decode()
            driver.execute(
                sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(verifier)
                )
            )
            os.environ[variable] = password


def mfa_http(
    address: str, tls: ssl.SSLContext, email: str, seed: bytes | None, owner: Engine
) -> None:
    origin = address.removesuffix(PREFIX)
    cookies: dict[str, str] = {}
    csrf = ""

    def call(
        path: str, data: dict[str, str] | None = None, *, site: str = origin
    ) -> tuple[int, bytes]:
        request = Request(
            origin + "/api/v1" + path,
            json.dumps(data).encode() if data is not None else None,
            {
                "Origin": site,
                "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items()),
                "Content-Type": "application/json",
                "X-Veriq-CSRF-Bootstrap": "1",
                "X-CSRF-Token": csrf,
            },
        )
        try:
            with urlopen(request, context=tls, timeout=10) as response:
                for cookie in response.headers.get_all("Set-Cookie", []):
                    name, value = cookie.split(";", 1)[0].split("=", 1)
                    assert (
                        "HttpOnly" in cookie
                        and "Secure" in cookie
                        and "SameSite=lax" in cookie
                    )
                    if value and value != '""':
                        cookies[name] = value
                    else:
                        cookies.pop(name, None)
                return response.status, response.read()
        except HTTPError as error:
            with error:
                return error.code, error.read()

    status, body = call("/auth/csrf")
    assert status == 200
    csrf = json.loads(body)["csrf_token"]
    if seed is None:
        assert call("/auth/mfa/recovery", {"email": email, "password": FINAL})[0] == 503
        assert call("/auth/password-reset/request", {"email": email})[0] == 503
        assert call("/auth/mfa/challenge", {"code": "invalid"})[0] == 503
        print("MFA HTTP fails closed during Redis outage.")
        return

    assert (
        call(
            "/auth/password-reset/request",
            {"email": email},
            site="https://other.example.invalid",
        )[0]
        == 403
    )
    assert call("/auth/password-reset/request", {"email": email}) == (202, b"")
    assert call(
        "/auth/password-reset/request", {"email": "unknown-reset-http@example.invalid"}
    ) == (202, b"")
    status, page = call("/auth/password-reset/confirm")
    assert status == 200 and b"history.replaceState" in page
    assert (
        query(
            owner,
            "SELECT count(*) FROM password_reset_proofs WHERE email_normalized=:email AND consumed_at IS NULL",
            email=email,
        )
        == 1
    )
    query(
        owner,
        "DELETE FROM password_reset_proofs WHERE email_normalized=:email RETURNING id",
        email=email,
    )
    assert call("/auth/login", {"email": email, "password": FINAL})[0] == 202
    assert "__Host-veriq-session" not in cookies
    assert "__Host-veriq-mfa-challenge" in cookies
    assert call("/me")[0] == 401
    assert call("/auth/mfa/challenge", {"code": "invalid"})[0] == 403
    status, body = call("/auth/csrf")
    assert status == 200
    csrf = json.loads(body)["csrf_token"]
    assert (
        call(
            "/auth/mfa/challenge",
            {"code": "invalid"},
            site="https://other.example.invalid",
        )[0]
        == 403
    )
    counter = query(
        owner, "SELECT floor(extract(epoch FROM clock_timestamp())/30)::bigint"
    )
    status, body = call("/auth/mfa/challenge", {"code": totp(seed, counter)})
    assert status == 200 and len(json.loads(body)["recovery_codes"]) == 10
    assert (
        "__Host-veriq-session" in cookies
        and "__Host-veriq-mfa-challenge" not in cookies
    )
    assert call("/me")[0] == 200
    status, body = call("/auth/csrf")
    assert status == 200
    csrf = json.loads(body)["csrf_token"]
    assert call("/auth/mfa/step-up", {"purpose": "sensitive"})[0] == 202
    status, body = call("/auth/csrf")
    assert status == 200
    csrf = json.loads(body)["csrf_token"]
    for _ in range(3):
        assert call("/auth/mfa/challenge", {"code": "invalid"})[0] == 401
    assert call("/auth/mfa/challenge", {"code": "invalid"})[0] == 429
    assert call("/me")[0] == 200
    print(
        "MFA HTTPS: password challenge, cookie isolation, CSRF, TOTP and session issuance passed."
    )


def configure_mfa(root: Path) -> FactorKeys:
    key = secrets.token_bytes(32)
    ring = root / "mfa.json"
    ring.write_text(
        json.dumps({"active": "test", "keys": {"test": key.hex()}}), encoding="ascii"
    )
    os.environ["VERIQ_ENABLE_TEST_MFA"] = "1"
    os.environ["VERIQ_ENABLE_TEST_MFA_RECOVERY"] = "1"
    os.environ["VERIQ_ENABLE_TEST_PASSWORD_RECOVERY"] = "1"
    os.environ["VERIQ_TEST_MFA_KEYRING"] = str(ring)
    return FactorKeys("test", {"test": key})


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
                for name in (
                    "VERIQ_TEST_LOGIN_VERIFIER_PASSWORD",
                    "VERIQ_TEST_LOGIN_ISSUER_PASSWORD",
                    "VERIQ_TEST_MFA_DB_PASSWORD",
                    "VERIQ_TEST_CSRF_KEY",
                ):
                    os.environ[name] = secrets.token_hex(32)
                os.environ["VERIQ_ENABLE_TEST_LOGIN"] = "1"
                configure_mfa(root)
                certfile, keyfile, tls = tls_fixture(root)
                with server(certfile, keyfile) as address:
                    mfa_http(address, tls, "outage@example.invalid", None, owner)
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
                verified_email = checks(address, owner, worker, Fernet(key), root)
            secrets_in_mail = [
                json.loads(path.read_text(encoding="utf-8"))["path"].split("#")[1]
                for path in root.glob("*.json")
            ]
            assert all(
                value not in captured.getvalue()
                for value in (INITIAL, FINAL, BLOCKED, *secrets_in_mail)
            )
            assert_denial(api, "SELECT * FROM public.veriq_password_candidate(NULL)")
            assert_denial(worker, "SELECT * FROM public.veriq_password_candidate(NULL)")
            provision_browser_roles(owner)
            for role, variable, sql_denied in (
                (
                    "veriq_password_verifier",
                    "VERIQ_TEST_LOGIN_VERIFIER_PASSWORD",
                    "SELECT public.veriq_auth_confirm(NULL, NULL, NULL, NULL, NULL, NULL)",
                ),
                (
                    "veriq_browser_issuer",
                    "VERIQ_TEST_LOGIN_ISSUER_PASSWORD",
                    "SELECT * FROM public.veriq_password_candidate(NULL)",
                ),
            ):
                restricted = create_engine(
                    url.set(username=role, password=os.environ[variable]),
                    hide_parameters=True,
                )
                try:
                    assert_denial(restricted, sql_denied)
                    assert_denial(restricted, "SELECT password_hash FROM users")
                finally:
                    restricted.dispose()
            verifier_engine = create_engine(
                url.set(
                    username="veriq_password_verifier",
                    password=os.environ["VERIQ_TEST_LOGIN_VERIFIER_PASSWORD"],
                ),
                hide_parameters=True,
            )
            try:
                rehash_race(owner, CredentialVerifier(verifier_engine))
            finally:
                verifier_engine.dispose()
            os.environ["VERIQ_ENABLE_TEST_LOGIN"] = "1"
            os.environ["VERIQ_TEST_CSRF_KEY"] = secrets.token_hex(32)
            certfile, keyfile, tls = tls_fixture(root)
            with server(certfile, keyfile) as address:
                browser_checks(address, tls, owner, verified_email)
            with server() as address:
                assert (
                    send(address, "/login", email=verified_email, password=FINAL)[0]
                    == 403
                )
            keys = configure_mfa(root)
            mfa_engine = create_engine(
                url.set(
                    username="veriq_mfa_verifier",
                    password=os.environ["VERIQ_TEST_MFA_DB_PASSWORD"],
                ),
                hide_parameters=True,
            )
            try:
                service = Mfa(mfa_engine, Sessions(api), keys)
                user = query(
                    owner,
                    "SELECT id FROM users WHERE email_normalized=:email",
                    email=verified_email,
                )
                seed = base64.b32decode(
                    service.prepare_enrollment(user, RequestContext.new())
                )
                captured_mfa = StringIO()
                with (
                    redirect_stderr(captured_mfa),
                    server(certfile, keyfile) as address,
                ):
                    mfa_http(address, tls, verified_email, seed, owner)
                assert (
                    base64.b32encode(seed).decode("ascii")
                    not in captured_mfa.getvalue()
                )
            finally:
                mfa_engine.dispose()
            with owner.begin() as connection:
                connection.exec_driver_sql(
                    "ALTER ROLE veriq_mfa_verifier NOLOGIN PASSWORD NULL"
                )
                connection.exec_driver_sql(
                    "ALTER ROLE veriq_password_verifier NOLOGIN PASSWORD NULL"
                )
                connection.exec_driver_sql(
                    "ALTER ROLE veriq_browser_issuer NOLOGIN PASSWORD NULL"
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
