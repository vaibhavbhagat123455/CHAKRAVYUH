"""Small cross-platform advisory file lock used by the append-only log."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from types import TracebackType


_PROCESS_LOCKS: dict[str, threading.Lock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


def _process_lock(path: str) -> threading.Lock:
    with _PROCESS_LOCKS_GUARD:
        return _PROCESS_LOCKS.setdefault(path, threading.Lock())


class FileLock:
    """Serialize writers with an in-process lock plus an OS advisory lock."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.lock_path = Path(str(self.path) + ".lock")
        self._process_lock = _process_lock(str(self.lock_path))
        self._handle = None

    def __enter__(self) -> "FileLock":
        self._process_lock.acquire()
        try:
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)
            self._handle = open(self.lock_path, "a+b")
            if self._handle.tell() == 0:
                self._handle.write(b"\0")
                self._handle.flush()
            self._handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._handle.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX)
        except Exception:
            self._process_lock.release()
            if self._handle is not None:
                self._handle.close()
                self._handle = None
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if self._handle is not None:
                if os.name == "nt":
                    import msvcrt

                    self._handle.seek(0)
                    try:
                        msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                else:
                    import fcntl

                    try:
                        fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
                    except OSError:
                        pass
                self._handle.close()
                self._handle = None
        finally:
            self._process_lock.release()
