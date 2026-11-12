"""Encrypted verification envelopes and an idempotent local mailbox transport."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Literal
from uuid import UUID, uuid4

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Engine, text


@dataclass(frozen=True)
class VerificationMail:
    email: str = field(repr=False)
    proof: str = field(repr=False)
    purpose: Literal["verify_email", "password_reset"] = "verify_email"

    def seal(self, cipher: Fernet) -> bytes:
        return cipher.encrypt(
            json.dumps([self.email, self.proof, self.purpose]).encode()
        )

    @classmethod
    def open(cls, cipher: Fernet, envelope: bytes) -> "VerificationMail":
        email, proof, *kind = json.loads(cipher.decrypt(envelope, ttl=1800))
        if kind == ["password_reset"]:
            return cls(email, proof, "password_reset")
        if kind not in ([], ["verify_email"]):
            raise InvalidToken
        return cls(email, proof)


@dataclass(frozen=True)
class LocalMailbox:
    directory: Path

    def send(self, proof_id: UUID, message: VerificationMail) -> None:
        route = (
            "password-reset/confirm"
            if message.purpose == "password_reset"
            else "verify-email"
        )
        self._deliver(
            proof_id,
            {
                "recipient": message.email,
                "path": f"/api/v1/auth/{route}#{message.proof}",
            },
        )

    def send_password_notice(self, event_id: UUID, email: str, event_type: str) -> None:
        self._deliver(event_id, {"recipient": email, "event": event_type})

    def _deliver(self, delivery_id: UUID, payload: dict[str, str]) -> None:
        destination = self.directory / f"{delivery_id}.json"
        if destination.exists():
            return
        with NamedTemporaryFile(
            mode="w", dir=self.directory, delete=False, encoding="utf-8"
        ) as output:
            pending = Path(output.name)
            try:
                json.dump(payload, output)
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


def deliver_password_notice(engine: Engine, mailbox: LocalMailbox) -> bool:
    claim = uuid4()
    with engine.begin() as connection:
        row = connection.execute(
            text("SELECT * FROM public.veriq_password_notice_claim(:claim)"),
            {"claim": claim},
        ).one_or_none()
        if row is None:
            return False
        try:
            mailbox.send_password_notice(row.event_id, row.email, row.event_type)
        except OSError:
            return False
        return bool(
            connection.execute(
                text("SELECT public.veriq_auth_ack_notice(:event,:claim)"),
                {"event": row.event_id, "claim": claim},
            ).scalar_one()
        )
