"""Cross-platform advisory file locking for bounded exclusive concurrency control.

Uses fcntl.flock on POSIX platforms and msvcrt.locking on Windows.
Guarantees timeout-bounded acquisition to avoid exceeding the 8-second per-op budget.
"""
import os
import sys
import time
from pathlib import Path
from types import TracebackType
from typing import Optional, Type

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl


class LockTimeoutError(TimeoutError):
    """Raised when lock acquisition exceeds the configured timeout."""


class FileLock:
    """Exclusive file lock with bounded wait time."""

    def __init__(self, lock_file_path: Path, timeout_seconds: float = 2.0):
        self.lock_path = Path(lock_file_path)
        self.timeout_seconds = timeout_seconds
        self._fd: Optional[int] = None

    def acquire(self) -> None:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        self._fd = fd
        start = time.monotonic()
        deadline = start + self.timeout_seconds

        while True:
            try:
                if sys.platform == "win32":
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    self._fd = None
                    raise LockTimeoutError(
                        f"Failed to acquire lock on {self.lock_path} within {self.timeout_seconds}s"
                    ) from None
                time.sleep(0.01)

    def release(self) -> None:
        if self._fd is not None:
            try:
                if sys.platform == "win32":
                    os.lseek(self._fd, 0, os.SEEK_SET)
                    msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
            except OSError:
                pass
            finally:
                os.close(self._fd)
                self._fd = None

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.release()
