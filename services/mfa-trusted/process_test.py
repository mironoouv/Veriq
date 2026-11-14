"""Run in the Linux CI container as root to launch distinct unprivileged UIDs."""

import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from threading import Barrier
from uuid import UUID, uuid4

from psycopg import connect, sql
from psycopg.errors import InsufficientPrivilege
from veriq.mfa_crypto import FactorKeys, totp


def main():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        root.chmod(0o755)
        directory = root / "socket"
        directory.mkdir()
        os.chown(directory, 10002, 10002)
        directory.chmod(0o750)
        endpoint = directory / "service.sock"
        seed = os.urandom(20)
        key = os.urandom(32)
        user, factor = uuid4(), uuid4()
        encrypted = FactorKeys("fixture", {"fixture": key}).encrypt(user, factor, seed)
        for name, value in {
            "keys": json.dumps({"active": "fixture", "keys": {"fixture": key.hex()}}),
            "password": "isolated-fixture-password",
            "factor": json.dumps(
                {
                    "user": str(user),
                    "factor": str(factor),
                    "key_id": "fixture",
                    "ciphertext": encrypted.hex(),
                }
            ),
        }.items():
            path = root / name
            path.write_text(value)
            os.chown(path, 10002, 10002)
            path.chmod(0o600)
        host = os.environ.get("VERIQ_TRUSTED_DB_HOST")
        token = uuid4().hex + "." + secrets.token_urlsafe(32)
        sid = token[:32]
        if host:
            password = os.urandom(32).hex()
            path = root / "password"
            path.write_text(password)
            with connect(
                host=host,
                dbname="veriq",
                user="veriq_dev",
                password=os.environ["VERIQ_DB_PASSWORD"],
            ) as db:
                assert db.execute("SHOW server_version_num").fetchone() == ("170011",)
                db.execute(
                    sql.SQL("ALTER ROLE veriq_mfa_trusted LOGIN PASSWORD {}").format(
                        sql.Literal(password)
                    )
                )
                db.execute(
                    "INSERT INTO users(id,email_normalized,password_hash) VALUES (%s,%s,'fixture')",
                    (user, f"{user.hex}@example.invalid"),
                )
                db.execute(
                    "INSERT INTO mfa_factors(user_id,id,key_id,ciphertext,confirmed_at,pending_until) VALUES (%s,%s,'fixture',%s,now(),now())",
                    (user, factor, encrypted),
                )
                db.execute(
                    """INSERT INTO auth_sessions(id,user_id,token_hash,mfa_level,authenticated_at,created_at,last_seen_at,idle_expires_at,absolute_expires_at)
                    VALUES (%s,%s,%s,1,now(),now(),now(),now()+interval '20 minutes',now()+interval '1 hour')""",
                    (sid, user, sha256(token.encode()).digest()),
                )
            with connect(
                host=host, dbname="veriq", user="veriq_mfa_trusted", password=password
            ) as db:
                scope = (user, factor, sid, sha256(token.encode()).digest(), None)
                proof = uuid4()
                assert db.execute(
                    "SELECT public.veriq_trusted_mfa_attest(%s,%s,%s,%s,%s,%s)",
                    (proof, *scope),
                ).fetchone() == (True,)
                db.rollback()
                try:
                    db.execute("UPDATE mfa_factors SET last_counter=0 WHERE false")
                except InsufficientPrivilege:
                    db.rollback()
                else:
                    raise AssertionError(
                        "Trusted login unexpectedly has direct factor DML"
                    )
                print(
                    "Trust boundary: SQL attestation requires trusted credentials and a current session proof"
                )

            def admin():
                return connect(
                    host=host,
                    dbname="veriq",
                    user="veriq_dev",
                    password=os.environ["VERIQ_DB_PASSWORD"],
                )

            sql_counter = int(time.time()) // 30
            barrier = Barrier(2)

            def sql_attempt(_):
                with connect(
                    host=host,
                    dbname="veriq",
                    user="veriq_mfa_trusted",
                    password=password,
                ) as db:
                    barrier.wait(timeout=5)
                    return db.execute(
                        "SELECT public.veriq_trusted_mfa_totp(%s,%s,%s,%s,%s,%s,%s,%s)",
                        (uuid4(), *scope, sql_counter, encrypted),
                    ).fetchone()[0]

            with ThreadPoolExecutor(2) as pool:
                assert sorted(pool.map(sql_attempt, range(2))) == [False, True]
            with admin() as db:
                db.execute(
                    "UPDATE mfa_factors SET last_counter=-1 WHERE id=%s", (factor,)
                )
        config = {
            **{k: v for k, v in os.environ.items() if k != "VERIQ_DB_PASSWORD"},
            "VERIQ_TEST_TRUSTED_DISABLE": "1",
            "VERIQ_MFA_PEER_UID": "10001",
            "VERIQ_MFA_SOCKET": str(endpoint),
            "VERIQ_TRUSTED_KEYRING": str(root / "keys"),
            "VERIQ_TRUSTED_DB_PASSWORD_FILE": str(root / "password"),
            "VERIQ_MFA_SYNTHETIC_FACTOR": str(root / "factor"),
        }
        command = [sys.executable, "/app/mfa_trusted.py"]
        identity = {"user": 10002, "group": 10002, "extra_groups": []}
        missing = subprocess.run(
            command,
            env={**config, "VERIQ_TRUSTED_KEYRING": str(root / "missing")},
            capture_output=True,
            timeout=5,
            check=False,
            **identity,
        )
        assert missing.returncode == 1 and not endpoint.exists()
        with subprocess.Popen(
            command,
            env=config,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **identity,
        ) as server:
            try:
                deadline = time.monotonic() + 5
                while not endpoint.exists():
                    assert server.poll() is None and time.monotonic() < deadline
                    time.sleep(0.02)
                assert endpoint.stat().st_mode & 0o777 == 0o660
                client = """
import socket, sys
with socket.socket(socket.AF_UNIX) as s:
    s.settimeout(4)
    s.connect(sys.argv[1])
    s.sendall(sys.stdin.buffer.read())
    print(s.makefile('rb').readline().decode(), end='')
"""

                def call(payload, uid=10001):
                    result = subprocess.run(
                        [sys.executable, "-c", client, str(endpoint)],
                        input=payload,
                        capture_output=True,
                        check=True,
                        timeout=6,
                        user=uid,
                        group=10002,
                        extra_groups=[],
                    )
                    return json.loads(result.stdout)

                def request(operation, args):
                    return (
                        json.dumps({"operation": operation, "arguments": args}) + "\n"
                    ).encode()

                assert call(request("health", {})) == {"ready": True}
                assert call(request("health", {}), uid=10003) == {"error": "denied"}
                assert call(request("unknown", {})) == {"error": "denied"}
                assert call(b"x" * 8193) == {"error": "denied"}
                counter = int(time.time()) // 30
                code = totp(seed, counter)
                wrong = next(
                    f"{i:06d}"
                    for i in range(3)
                    if f"{i:06d}" not in {code, totp(seed, counter - 1)}
                )
                if host:
                    args = {
                        "account": str(user),
                        "factor": str(factor),
                        "session": sid,
                        "organization": None,
                        "token": token,
                        "code": wrong,
                    }
                    assert call(request("attest_disable", args)) == {"error": "denied"}
                    args["code"] = code
                    assert call(
                        request("attest_disable", {**args, "factor": str(uuid4())})
                    ) == {"error": "denied"}
                    assert call(
                        request("attest_disable", {**args, "verified": True})
                    ) == {"error": "denied"}
                    assert call(
                        request("attest_disable", {**args, "counter": counter})
                    ) == {"error": "denied"}
                    key_path = root / "keys"
                    original = key_path.read_text()
                    key_path.write_text("{")
                    damaged = subprocess.run(
                        command,
                        env=config,
                        capture_output=True,
                        timeout=5,
                        check=False,
                        **identity,
                    )
                    assert damaged.returncode == 1 and damaged.stderr == missing.stderr
                    key_path.write_text(
                        json.dumps(
                            {
                                "active": "fixture",
                                "keys": {"fixture": os.urandom(32).hex()},
                            }
                        )
                    )
                    bad_config = {
                        **config,
                        "VERIQ_MFA_SOCKET": str(directory / "wrong.sock"),
                    }
                    with subprocess.Popen(
                        command,
                        env=bad_config,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        **identity,
                    ) as bad:
                        original_endpoint = endpoint
                        endpoint = directory / "wrong.sock"
                        try:
                            deadline = time.monotonic() + 5
                            while not endpoint.exists():
                                assert (
                                    bad.poll() is None and time.monotonic() < deadline
                                )
                                time.sleep(0.02)
                            assert call(request("attest_disable", args)) == {
                                "error": "denied"
                            }
                        finally:
                            bad.terminate()
                            assert bad.communicate(timeout=6) == (b"", b"")
                            endpoint = original_endpoint
                    key_path.write_text(original)
                    with admin() as db:
                        db.execute("""CREATE FUNCTION reject_fixture_attestation() RETURNS trigger LANGUAGE plpgsql AS
                            $$ BEGIN RAISE EXCEPTION 'fixture denial'; END $$;
                            CREATE TRIGGER reject_fixture_attestation BEFORE INSERT ON mfa_operation_attestations
                            FOR EACH ROW EXECUTE FUNCTION reject_fixture_attestation()""")
                    assert call(request("attest_disable", args)) == {"error": "denied"}
                    with admin() as db:
                        assert db.execute(
                            "SELECT last_counter FROM mfa_factors WHERE id=%s",
                            (factor,),
                        ).fetchone() == (-1,)
                        db.execute(
                            "DROP TRIGGER reject_fixture_attestation ON mfa_operation_attestations"
                        )
                    with ThreadPoolExecutor(2) as pool:
                        replies = list(
                            pool.map(call, [request("attest_disable", args)] * 2)
                        )
                    proofs = [r["attestation"] for r in replies if "attestation" in r]
                    assert len(proofs) == 1 and {"error": "denied"} in replies
                    assert call(request("attest_disable", args)) == {"error": "denied"}
                    assert call(request("check_fixture_totp", {"code": code})) == {
                        "error": "denied"
                    }
                    with connect(
                        host=host,
                        dbname="veriq",
                        user="veriq_dev",
                        password=os.environ["VERIQ_DB_PASSWORD"],
                    ) as db:
                        assert db.execute(
                            "SELECT user_id,factor_id,session_id,purpose FROM mfa_operation_attestations WHERE id=%s",
                            (proofs[0],),
                        ).fetchone() == (user, factor, UUID(sid), "factor_disable")
                    with connect(
                        host=host,
                        dbname="veriq",
                        user="veriq_dev",
                        password=os.environ["VERIQ_DB_PASSWORD"],
                    ) as db:
                        db.execute(
                            "UPDATE auth_sessions SET revoked_at=now(),revoke_reason='logout' WHERE id=%s",
                            (sid,),
                        )
                    assert call(request("attest_disable", args)) == {"error": "denied"}
                    assert call(
                        request("attest_disable", {**args, "account": str(uuid4())})
                    ) == {"error": "denied"}
                    assert call(
                        request("attest_disable", {**args, "session": str(uuid4())})
                    ) == {"error": "denied"}
                    disable_args = {
                        **args,
                        "request": str(uuid4()),
                        "correlation": str(uuid4()),
                    }
                    adapter = """
import json, sys
from veriq.mfa_ipc import disable_factor
disable_factor(sys.argv[1], **json.load(sys.stdin))
"""

                    def invoke_disable(path, arguments):
                        return subprocess.run(
                            [sys.executable, "-c", adapter, str(path)],
                            input=json.dumps(arguments).encode(),
                            check=False,
                            capture_output=True,
                            timeout=6,
                            user=10001,
                            group=10002,
                            extra_groups=[],
                        )

                    assert invoke_disable(endpoint, disable_args).returncode != 0
                    assert (
                        invoke_disable(
                            directory / "absent.sock", disable_args
                        ).returncode
                        != 0
                    )
                    with admin() as db:
                        db.execute(
                            "UPDATE auth_sessions SET revoked_at=NULL,revoke_reason=NULL WHERE id=%s",
                            (sid,),
                        )
                        db.execute(
                            "UPDATE mfa_factors SET last_counter=-1 WHERE id=%s",
                            (factor,),
                        )
                    with admin() as db:
                        before = db.execute(
                            "SELECT id, consumed_at FROM mfa_operation_attestations WHERE factor_id=%s ORDER BY id",
                            (factor,),
                        ).fetchall()
                        db.execute("""CREATE FUNCTION reject_fixture_audit() RETURNS trigger LANGUAGE plpgsql AS
                            $$ BEGIN RAISE EXCEPTION 'fixture audit denial'; END $$;
                            CREATE TRIGGER reject_fixture_audit BEFORE INSERT ON auth_audit_events
                            FOR EACH ROW EXECUTE FUNCTION reject_fixture_audit()""")
                    assert invoke_disable(endpoint, disable_args).returncode != 0
                    with admin() as db:
                        assert db.execute(
                            "SELECT last_counter FROM mfa_factors WHERE id=%s",
                            (factor,),
                        ).fetchone() == (-1,)
                        assert db.execute(
                            "SELECT revoked_at FROM auth_sessions WHERE id=%s", (sid,)
                        ).fetchone() == (None,)
                        assert db.execute(
                            "SELECT id, consumed_at FROM mfa_operation_attestations WHERE factor_id=%s ORDER BY id",
                            (factor,),
                        ).fetchall() == before
                        db.execute(
                            "DROP TRIGGER reject_fixture_audit ON auth_audit_events"
                        )
                    with ThreadPoolExecutor(2) as pool:
                        results = list(
                            pool.map(
                                lambda _: invoke_disable(endpoint, disable_args),
                                range(2),
                            )
                        )
                    assert sum(result.returncode == 0 for result in results) == 1
                    for result in results:
                        for secret in (token.encode(), code.encode(), seed):
                            assert secret not in result.stdout + result.stderr
                    with admin() as db:
                        assert (
                            db.execute(
                                "SELECT 1 FROM mfa_factors WHERE id=%s", (factor,)
                            ).fetchone()
                            is None
                        )
                        assert db.execute(
                            "SELECT count(*) FROM mfa_operation_attestations WHERE factor_id=%s AND consumed_at IS NOT NULL",
                            (factor,),
                        ).fetchone() == (1,)
                    with connect(
                        host=host,
                        dbname="postgres",
                        user="veriq_dev",
                        password=os.environ["VERIQ_DB_PASSWORD"],
                        autocommit=True,
                    ) as db:
                        db.execute("ALTER DATABASE veriq ALLOW_CONNECTIONS false")
                    assert call(request("health", {})) == {"error": "denied"}
                    assert call(request("attest_disable", args)) == {"error": "denied"}
                    assert call(request("check_fixture_totp", {"code": code})) == {
                        "error": "denied"
                    }
                else:
                    assert call(request("check_fixture_totp", {"code": wrong})) == {
                        "matches": False
                    }
                    assert call(request("check_fixture_totp", {"code": code})) == {
                        "matches": True
                    }
            finally:
                server.terminate()
                stdout, stderr = server.communicate(timeout=6)
            assert server.returncode == 0 and not endpoint.exists()
            assert not stdout and not stderr
        assert missing.stderr == b"Trusted MFA startup or runtime failure\n"
    print(
        "Trusted MFA process: UID, framing, TOTP, missing secret, shutdown and logs passed"
    )


if __name__ == "__main__":
    main()
