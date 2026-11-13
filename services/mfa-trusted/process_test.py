"""Run in the Linux CI container as root to launch distinct unprivileged UIDs."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from uuid import uuid4

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
        config = {
            **os.environ,
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
