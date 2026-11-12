"""RFC 6238 TOTP and authenticated storage for factor seeds."""

import base64
import hmac
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def totp(secret: bytes, counter: int, digits: int = 6) -> str:
    digest = hmac.digest(secret, counter.to_bytes(8, "big"), "sha1")
    offset = digest[-1] & 15
    number = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(number % (10**digits)).zfill(digits)


def matching_counter(secret: bytes, code: str, now: int) -> int | None:
    if len(code) != 6 or not code.isascii() or not code.isdecimal():
        return None
    counter = now // 30
    for allowed in (counter, counter - 1):
        if allowed >= 0 and hmac.compare_digest(totp(secret, allowed), code):
            return allowed
    return None


@dataclass(frozen=True)
class FactorKeys:
    active: str
    keys: dict[str, bytes] = field(repr=False)

    def __post_init__(self) -> None:
        if self.active not in self.keys or any(
            len(value) != 32 for value in self.keys.values()
        ):
            raise ValueError("MFA keyring requires an active AES-256 key")

    @classmethod
    def load(cls, path: Path) -> "FactorKeys":
        value = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            value["active"],
            {name: bytes.fromhex(key) for name, key in value["keys"].items()},
        )

    @staticmethod
    def associated(user: UUID, factor: UUID, key_id: str) -> bytes:
        return b"veriq:totp:v1:" + user.bytes + factor.bytes + key_id.encode("utf-8")

    def encrypt(self, user: UUID, factor: UUID, seed: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(self.keys[self.active]).encrypt(
            nonce, seed, self.associated(user, factor, self.active)
        )

    def decrypt(self, user: UUID, factor: UUID, key_id: str, payload: bytes) -> bytes:
        return AESGCM(self.keys[key_id]).decrypt(
            payload[:12], payload[12:], self.associated(user, factor, key_id)
        )


def seed_text(seed: bytes) -> str:
    return base64.b32encode(seed).decode("ascii")
