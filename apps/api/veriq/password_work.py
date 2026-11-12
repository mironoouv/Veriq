"""Bound native password work without queuing requests or releasing on cancellation."""

import asyncio
from collections.abc import Callable
from typing import Generic, TypeVar

T = TypeVar("T")


class PasswordCapacityExceeded(RuntimeError):
    pass


class PasswordWork(Generic[T]):
    def __init__(self, limit: int = 2) -> None:
        if not 1 <= limit <= 4:
            raise ValueError("Password concurrency must be between 1 and 4")
        self.limit = limit
        self.active: set[asyncio.Task[T]] = set()

    def _complete(self, task: asyncio.Task[T]) -> None:
        self.active.discard(task)
        if not task.cancelled():
            task.exception()

    async def run(self, operation: Callable[[], T]) -> T:
        if len(self.active) >= self.limit:
            raise PasswordCapacityExceeded
        task = asyncio.create_task(asyncio.to_thread(operation))
        self.active.add(task)
        task.add_done_callback(self._complete)
        return await asyncio.shield(task)
