"""Password policy and email normalization shared by registration operations."""

import re
import unicodedata
from hashlib import sha256
from pathlib import Path

from argon2 import PasswordHasher
from argon2.profiles import RFC_9106_LOW_MEMORY

_LOCAL = re.compile(r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_DIGEST = re.compile(r"[0-9a-f]{64}")
HASHER = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)


def canonical_email(value: str) -> str:
    """Support ASCII dot-atom mailboxes, preserving plus and dot distinctions."""
    address = value.strip(" \t")
    if not address.isascii() or len(address) > 254 or address.count("@") != 1:
        raise ValueError("Invalid email")
    local, domain = address.lower().split("@")
    labels = domain.split(".")
    if len(local) > 64 or not _LOCAL.fullmatch(local) or len(labels) < 2:
        raise ValueError("Invalid email")
    if not all(_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Invalid email")
    return f"{local}@{domain}"


class PasswordPolicy:
    def __init__(self, path: Path) -> None:
        # Operator-supplied exact SHA-256 digests of NFC UTF-8 blocklisted passwords.
        digests = frozenset(path.read_text(encoding="ascii").splitlines())
        if not digests or any(not _DIGEST.fullmatch(item) for item in digests):
            raise ValueError("Invalid password blocklist")
        self.digests = digests

    def hash(self, password: str) -> str:
        normalized = unicodedata.normalize("NFC", password)
        if not 15 <= len(normalized) <= 128:
            raise ValueError("Password rejected")
        data = normalized.encode("utf-8")
        if sha256(data).hexdigest() in self.digests:
            raise ValueError("Password rejected")
        return HASHER.hash(data)
