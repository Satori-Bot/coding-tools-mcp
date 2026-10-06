"""Opt-in, local diagnostic records. Never connected to product telemetry."""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
from pathlib import Path
from typing import Any

from .envutils import ENV_PREFIX


def _warn() -> None:
    # Neither the exception nor the configured path is safe to print.
    try:
        print(
            "coding-tools-mcp: local event journal unavailable; recording disabled "
            "for this runtime. Check directory permissions, writer ownership and disk space.",
            file=sys.stderr,
            flush=True,
        )
    except Exception:
        pass


def _check_private(info: os.stat_result, *, directory: bool = False) -> None:
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or (not directory and info.st_nlink != 1):
        raise ValueError("journal storage must be a directory or single-link regular file")
    if os.name != "nt" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise ValueError("journal storage must be private to its owner")


def _open_private(path: Path) -> int:
    try:
        _check_private(path.lstat())
    except FileNotFoundError:
        pass
    flags = os.O_CREAT | os.O_RDWR | os.O_APPEND
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        _check_private(os.fstat(fd))
    except Exception:
        os.close(fd)
        raise
    return fd


class ToolEventJournal:
    """One writer and a bounded ring per operator-selected private directory.

    The OS lock survives neither process exit nor close, but its file stays in
    place: unlinking it could let another process lock a different inode.
    Calls share a thread lock; separate processes must use separate directories.
    """

    def __init__(
        self, directory: Path, *, max_bytes: int = 1024 * 1024, backup_count: int = 3
    ) -> None:
        self.directory = directory.expanduser()
        if not self.directory.is_absolute() or max_bytes < 2 or backup_count < 0:
            raise ValueError("invalid journal configuration")
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.path = self.directory / "events.jsonl"
        self._mutex = threading.Lock()
        self._lock_fd: int | None = None
        self._disabled = False
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        _check_private(self.directory.lstat(), directory=True)
        fd = _open_private(self.directory / "journal.lock")
        try:
            if sys.platform == "win32":
                import msvcrt

                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Validate all managed files before accepting records. Existing
            # permissions are never widened or silently rewritten.
            for path in [self.path, *(self._backup(i) for i in range(1, backup_count + 1))]:
                if path.is_symlink() or path.exists():
                    info = path.lstat()
                    _check_private(info)
                    if info.st_size > max_bytes:
                        raise ValueError("existing journal exceeds configured size")
        except Exception:
            os.close(fd)
            raise
        self._lock_fd = fd

    @classmethod
    def from_env(cls) -> ToolEventJournal | None:
        configured = os.environ.get(f"{ENV_PREFIX}_EVENT_LOG_DIR")
        if not configured:
            return None
        try:
            return cls(Path(configured))
        except Exception:
            _warn()
            return None

    def _backup(self, index: int) -> Path:
        return self.directory / f"events.jsonl.{index}"

    def _rotate(self) -> None:
        if self.backup_count == 0:
            self.path.unlink()
            return
        for index in range(self.backup_count, 1, -1):
            source = self._backup(index - 1)
            if source.exists():
                os.replace(source, self._backup(index))
        os.replace(self.path, self._backup(1))

    def record(self, event: dict[str, Any]) -> None:
        """Append one bounded record; IO failure never changes a tool outcome."""
        with self._mutex:
            if self._disabled or self._lock_fd is None:
                return
            try:
                encoded = (json.dumps(event, separators=(",", ":"), ensure_ascii=True) + "\n").encode()
                if len(encoded) > min(self.max_bytes, 4096):
                    raise ValueError("journal record too large")
                fd = _open_private(self.path)
                try:
                    size = os.fstat(fd).st_size
                    # A killed process may leave a partial final record. Keep
                    # it as evidence, but never concatenate the next JSON to it.
                    separator = b""
                    if size:
                        os.lseek(fd, -1, os.SEEK_END)
                        if os.read(fd, 1) != b"\n":
                            separator = b"\n"
                    if size + len(separator) + len(encoded) > self.max_bytes:
                        old_fd, fd = fd, -1
                        os.close(old_fd)
                        self._rotate()
                        fd = _open_private(self.path)
                        separator = b""
                    remaining = separator + encoded
                    while remaining:
                        written = os.write(fd, remaining)
                        if written <= 0:
                            raise OSError("journal write made no progress")
                        remaining = remaining[written:]
                finally:
                    if fd != -1:
                        os.close(fd)
            except Exception:
                # In particular, do not keep writing after a partial write.
                self._disabled = True
                _warn()

    def close(self) -> None:
        with self._mutex:
            if self._lock_fd is not None:
                fd, self._lock_fd = self._lock_fd, None
                try:
                    os.close(fd)
                except OSError:
                    pass
