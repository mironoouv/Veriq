import asyncio
from threading import Event

import pytest
from argon2 import PasswordHasher

from veriq.password_work import PasswordCapacityExceeded, PasswordWork
from veriq.registration_policy import HASHER, supported_hash


def test_supported_argon2id_bounds() -> None:
    older = PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1)
    old_hash = older.hash("synthetic test passphrase")
    assert supported_hash(old_hash)
    assert HASHER.check_needs_rehash(old_hash)
    assert not supported_hash(old_hash.replace("m=19456", "m=999999"))
    assert not supported_hash(old_hash.replace("t=2", "t=99"))
    assert not supported_hash(old_hash.replace("p=1", "p=99"))
    assert not supported_hash(old_hash.replace("argon2id", "argon2i"))
    assert not supported_hash("malformed")


def test_capacity_remains_reserved_on_cancel_and_recovers() -> None:
    async def run() -> None:
        worker = PasswordWork[int](1)
        started = Event()
        finish = Event()

        def blocked() -> int:
            started.set()
            assert finish.wait(timeout=10)
            return 1

        task = asyncio.create_task(worker.run(blocked))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            with pytest.raises(PasswordCapacityExceeded):
                await worker.run(lambda: 2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            with pytest.raises(PasswordCapacityExceeded):
                await worker.run(lambda: 3)
        finally:
            finish.set()

        async with asyncio.timeout(5):
            while worker.active:
                await asyncio.sleep(0.01)

        def broken() -> int:
            raise RuntimeError("synthetic test failure")

        with pytest.raises(RuntimeError, match="synthetic test failure"):
            await worker.run(broken)
        assert await worker.run(lambda: 4) == 4
        assert await worker.run(lambda: 5) == 5

    asyncio.run(run())


@pytest.mark.parametrize("invalid_limit", [0, 5])
def test_password_capacity_configuration(invalid_limit: int) -> None:
    with pytest.raises(ValueError):
        PasswordWork[int](invalid_limit)
