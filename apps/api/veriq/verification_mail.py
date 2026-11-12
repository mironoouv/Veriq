"""Encrypted verification envelopes and an idempotent local mailbox transport."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Engine, text


@dataclass(frozen=True)
class VerificationMail:
    email: str = field(repr=False)
    proof: str = field(repr=False)

    def seal(self, cipher: Fernet) -> bytes:
        return cipher.encrypt(json.dumps([self.email, self.proof]).encode())

    @classmethod
    def open(cls, cipher: Fernet, envelope: bytes) -> "VerificationMail":
        email, proof = json.loads(cipher.decrypt(envelope, ttl=1800))
        return cls(email, proof)


@dataclass(frozen=True)
class LocalMailbox:
    directory: Path

    def send(self, proof_id: UUID, message: VerificationMail) -> None:
        # A proof ID is the delivery idempotency key, even across worker restarts.
        destination = self.directory / f"{proof_id}.json"
        if destination.exists():
            return
        with NamedTemporaryFile(
            mode="w", dir=self.directory, delete=False, encoding="utf-8"
        ) as output:
            pending = Path(output.name)
            try:
                json.dump(
                    {
                        "recipient": message.email,
                        "path": f"/api/v1/auth/verify-email#{message.proof}",
                    },
                    output,
                )
                output.flush()
                os.fsync(output.fileno())
                output.close()
                pending.replace(destination)
            finally:
                pending.unlink(missing_ok=True)


def deliver_verification(engine: Engine, cipher: Fernet, mailbox: LocalMailbox) -> bool:
    with engine.begin() as connection:
        row = connection.execute(
            text("SELECT * FROM public.veriq_signup_mail_next()")
        ).one_or_none()
        proof_id: UUID | None = None
        delivered = False
        if row is not None:
            proof_id = UUID(str(row.proof_id))
            try:
                mailbox.send(proof_id, VerificationMail.open(cipher, row.envelope))
                delivered = True
            except (OSError, InvalidToken):
                # Retain the encrypted envelope and retry after the database delay.
                pass
        connection.execute(
            text("SELECT public.veriq_signup_mail_finish(:id, :delivered)"),
            {"id": proof_id, "delivered": delivered},
        )
    return delivered
