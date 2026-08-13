"""
WinLogin Forensics - Read-only evidence enforcement
===================================================
Opens evidence files with O_RDONLY, refuses write modes, hashes at open
and close, and aborts if the bytes change during analysis.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any, Optional, Union


class EvidenceWriteAttemptError(RuntimeError):
    """Raised when a write is attempted against an evidence path."""


class EvidenceTamperedError(RuntimeError):
    """Raised when the SHA-256 of an evidence file changes during analysis."""


class EvidenceIntegrityError(RuntimeError):
    """Raised when an evidence file cannot be opened safely."""


def compute_file_hash(path: Union[str, Path]) -> str:
    """
    Compute SHA-256 of a file without opening it for write.

    Parameters
    ----------
    path : str | Path
        Evidence file path.

    Returns
    -------
    str
        Lowercase hex digest.
    """
    digest = hashlib.sha256()
    fd = os.open(str(path), os.O_RDONLY)
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


def _mode_is_write(mode: str) -> bool:
    """Return True if an fopen-style mode requests write/create/append."""
    if not mode:
        return False
    # Strip binary/text/universal flags
    core = mode.replace("b", "").replace("t", "").replace("U", "")
    return any(flag in core for flag in ("w", "a", "x", "+"))


class ReadOnlyEvidenceFile:
    """
    Context manager that opens an evidence file read-only and verifies integrity.

    Purpose
    -------
    Guarantee that source evidence is never mutated during parsing. The file
    is opened with ``os.O_RDONLY``. Any write via this object raises
    :class:`EvidenceWriteAttemptError`. SHA-256 is computed at open and again
    at close; a mismatch raises :class:`EvidenceTamperedError`.

    Parameters
    ----------
    path : str | Path
        Evidence file path.
    mode : str
        Open mode. Must be a read-only mode (``r`` / ``rb``).

    Returns
    -------
    ReadOnlyEvidenceFile
        File-like wrapper. Use as a context manager.
    """

    def __init__(self, path: Union[str, Path], mode: str = "rb"):
        if _mode_is_write(mode):
            raise EvidenceWriteAttemptError(
                f"Write attempt detected on evidence path: {path} (mode={mode!r}). "
                "Analysis aborted."
            )
        self.path = Path(path)
        self.mode = mode
        self.file_path = str(self.path)
        self._fd: Optional[int] = None
        self._fh: Any = None
        self.open_hash: Optional[str] = None
        self.close_hash: Optional[str] = None
        self._closed = False

    def __enter__(self) -> "ReadOnlyEvidenceFile":
        if not self.path.exists():
            raise FileNotFoundError(f"Evidence file not found: {self.path}")
        flags = os.O_RDONLY
        # O_BINARY exists on Windows
        if hasattr(os, "O_BINARY") and "b" in self.mode:
            flags |= os.O_BINARY
        try:
            self._fd = os.open(str(self.path), flags)
        except OSError as exc:
            raise EvidenceIntegrityError(f"Unable to open evidence read-only: {exc}") from exc
        closefd = True
        self._fh = os.fdopen(self._fd, self.mode, closefd=closefd)
        self._fd = None  # now owned by _fh
        self.open_hash = compute_file_hash(self.path)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # --- file-like delegation (read-only) ---------------------------------

    @property
    def handle(self):
        """Underlying read-only file object."""
        return self._fh

    def read(self, size: int = -1) -> Any:
        """Read bytes/text from the evidence file."""
        self._ensure_open()
        return self._fh.read(size)

    def readline(self, size: int = -1) -> Any:
        """Read a single line from the evidence file."""
        self._ensure_open()
        return self._fh.readline(size)

    def readlines(self, hint: int = -1) -> list:
        """Read remaining lines from the evidence file."""
        self._ensure_open()
        return self._fh.readlines(hint)

    def seek(self, offset: int, whence: int = 0) -> int:
        """Seek the read cursor."""
        self._ensure_open()
        return self._fh.seek(offset, whence)

    def tell(self) -> int:
        """Return the current read cursor."""
        self._ensure_open()
        return self._fh.tell()

    def write(self, data: Any) -> int:
        """
        Reject any write against evidence.

        Parameters
        ----------
        data : Any
            Ignored. Present to match the file-like protocol.

        Returns
        -------
        int
            Never returns; always raises.

        Raises
        ------
        EvidenceWriteAttemptError
            Always.
        """
        raise EvidenceWriteAttemptError(
            f"Write attempt detected on evidence path: {self.path}. Analysis aborted."
        )

    def writelines(self, lines: Any) -> None:
        """Reject batched writes against evidence."""
        raise EvidenceWriteAttemptError(
            f"Write attempt detected on evidence path: {self.path}. Analysis aborted."
        )

    def truncate(self, size: Optional[int] = None) -> int:
        """Reject truncation of evidence."""
        raise EvidenceWriteAttemptError(
            f"Write attempt detected on evidence path: {self.path}. Analysis aborted."
        )

    def flush(self) -> None:
        """No-op flush — the file is read-only."""
        return None

    def close(self) -> None:
        """Close the handle and verify the on-disk hash is unchanged."""
        if self._closed:
            return
        self._closed = True
        try:
            if self._fh is not None:
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None
            if self.path.exists() and self.open_hash:
                self.close_hash = compute_file_hash(self.path)
                if self.close_hash != self.open_hash:
                    raise EvidenceTamperedError(
                        f"Evidence hash changed during analysis: {self.path} "
                        f"(open={self.open_hash} close={self.close_hash}). Analysis aborted."
                    )
        finally:
            self._fh = None

    def _ensure_open(self) -> None:
        if self._fh is None or self._closed:
            raise EvidenceIntegrityError(f"Evidence file is not open: {self.path}")

    def __iter__(self):
        self._ensure_open()
        return iter(self._fh)


def open_evidence(path: Union[str, Path], mode: str = "rb") -> ReadOnlyEvidenceFile:
    """
    Open an evidence file, aborting immediately if ``mode`` is writable.

    Parameters
    ----------
    path : str | Path
        Evidence path.
    mode : str
        Open mode.

    Returns
    -------
    ReadOnlyEvidenceFile
        Opened read-only wrapper (already entered).

    Raises
    ------
    EvidenceWriteAttemptError
        If ``mode`` requests write access.
    """
    wrapper = ReadOnlyEvidenceFile(path, mode=mode)
    return wrapper.__enter__()


def assert_readonly_path(path: Union[str, Path]) -> None:
    """
    Best-effort check that an evidence path is not world-writable.

    Parameters
    ----------
    path : str | Path
        Evidence path.

    Returns
    -------
    None
    """
    p = Path(path)
    if not p.exists():
        return
    mode = p.stat().st_mode
    if mode & stat.S_IWOTH:
        raise EvidenceWriteAttemptError(
            f"Evidence path is other-writable: {p}. Refusing to continue."
        )
