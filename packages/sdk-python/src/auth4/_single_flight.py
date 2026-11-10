from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Generic, TypeVar

T = TypeVar("T")


class _Call(Generic[T]):
    def __init__(self) -> None:
        self.done = threading.Event()
        self.result: T | None = None
        self.error: BaseException | None = None


class SingleFlight(Generic[T]):
    """Concurrent callers with the same key share one in-flight call and its result or error."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: dict[str, _Call[T]] = {}

    def in_flight(self, key: str) -> bool:
        with self._lock:
            return key in self._calls

    def run(
        self, key: str, work: Callable[[], T], before_start: Callable[[], None] | None = None
    ) -> T:
        """Joins the call for ``key`` or starts one. ``before_start`` runs under the lock only when
        this caller starts the call; it may raise to refuse starting."""
        with self._lock:
            call = self._calls.get(key)
            owner = call is None
            if call is None:
                if before_start is not None:
                    before_start()
                call = self._calls[key] = _Call()
        if not owner:
            call.done.wait()
            if call.error is not None:
                raise call.error
            return call.result  # type: ignore[return-value]
        try:
            call.result = work()
            return call.result
        except BaseException as error:
            call.error = error
            raise
        finally:
            with self._lock:
                del self._calls[key]
            call.done.set()
