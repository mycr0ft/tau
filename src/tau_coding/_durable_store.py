"""Durable versioned JSON storage shared by Tau's security stores.

Implements ProjectTrustStore's durability contract once so every security
store gets identical semantics:

- file lock across read-modify-write (fcntl/msvcrt);
- same-directory atomic replacement with fsync;
- a fail-closed undo journal: readers refuse the store while the journal
  exists, so a torn write can never resurrect a revoked denial or manufacture
  a new grant;
- recovery is attempted only by the writer that observed its own failure.

Schema validation and serialization are supplied per store via ``parse`` and
``serialize``. A ``parse`` callable raises the final user-facing error
directly; it is never wrapped. Envelope-level failures raise ``error_factory``
(default :class:`DurableStoreError`) so each store can keep its historical
exception type and messages.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import IO

type Parser[T: object] = Callable[[object], T]
"""Validate one decoded envelope and return the store's typed state.

Parse errors are raised as the final user-facing exception and propagate
untouched, so per-store messages stay exact.
"""

type Serializer[T] = Callable[[T], Mapping[str, object]]
"""Return the JSON-ready envelope for the store's typed state."""


class DurableStoreError(RuntimeError):
    """A durable store path, lock, parse, or persistence operation failed."""


def _lock_file(handle: IO[bytes]) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _unlock_file(handle: IO[bytes]) -> None:
    try:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class DurableJsonStore[T: object]:
    """Versioned, locked, atomically replaced JSON store with fail-closed journal."""

    def __init__(
        self,
        path: Path,
        *,
        parse: Parser[T],
        serialize: Serializer[T],
        empty_factory: Callable[[], T],
        error_factory: type[Exception] = DurableStoreError,
        label: str = "durable store",
    ) -> None:
        self.path = path
        self.lock_path = path.parent / (path.name + ".lock")
        self.pending_path = path.parent / (path.name + ".pending")
        self._parse = parse
        self._serialize = serialize
        self._empty_factory = empty_factory
        self._error_factory = error_factory
        self._label = label

    def _error(self, message: str) -> Exception:
        return self._error_factory(message)

    def read(self) -> T:
        """Return the validated store state, raising while recovery is pending."""
        with self._locked():
            return self._read_unlocked()

    def update(self, mutate: Callable[[T], T | None]) -> None:
        """Apply ``mutate`` under one read-modify-write lock.

        ``mutate`` receives the validated state and returns the updated state
        to persist, or ``None`` to skip writing entirely.
        """
        with self._locked():
            state = self._read_unlocked()
            updated = mutate(state)
            if updated is None:
                return
            self._write_unlocked(self._serialize(updated))

    @contextmanager
    def _locked(self) -> Iterator[None]:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with self.lock_path.open("a+b") as handle:
                os.chmod(self.lock_path, 0o600)
                _lock_file(handle)
                try:
                    yield
                finally:
                    _unlock_file(handle)
        except self._error_factory:
            raise
        except OSError as exc:
            raise self._error(f"Could not lock {self._label} {self.path}: {exc}") from exc

    def _read_unlocked(self) -> T:
        # A pending journal means an update did not reach its commit point.
        # Ordinary reads must never guess whether the interrupted operation was
        # a grant or a revocation: either direction could resurrect trust.
        # Recovery is attempted only by the writer that observed its own
        # failure; a journal left by a crash remains visibly fail-closed.
        if self.pending_path.exists():
            raise self._error(
                f"{self._label.capitalize()} {self.path} has an incomplete update; "
                f"pending journal requires explicit recovery: {self.pending_path}"
            )
        if not self.path.exists():
            return self._empty_factory()
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise self._error(f"Could not read {self._label} {self.path}: {exc}") from exc
        return self._parse(payload)

    def _write_unlocked(self, payload: Mapping[str, object]) -> None:
        data = (json.dumps(payload, indent=2) + "\n").encode()
        prior_bytes = self.path.read_bytes() if self.path.exists() else None

        # Persist a fail-closed undo journal before touching the destination.
        # Readers reject the store while this marker exists, so even failed
        # recovery can never expose newly granting bytes.
        journal = (b"present\n" + prior_bytes) if prior_bytes is not None else b"absent\n"
        try:
            self._atomic_replace(self.pending_path, journal, prefix=".durable-pending-")
            self._atomic_replace(self.path, data, prefix=".durable-")
        except OSError as exc:
            recovery_error = self._recover_unlocked()
            detail = f"; recovery failed: {recovery_error}" if recovery_error else ""
            raise self._error(f"Could not write {self._label} {self.path}: {exc}{detail}") from exc

        # The destination and its directory entry are durable. Failure to clear
        # the journal is still a failed update and must restore the prior state.
        try:
            self.pending_path.unlink()
        except OSError as exc:
            recovery_error = self._recover_unlocked()
            detail = f"; recovery failed: {recovery_error}" if recovery_error else ""
            raise self._error(f"Could not commit {self._label} {self.path}: {exc}{detail}") from exc
        # Journal cleanup is not part of the data commit. If this fsync fails,
        # either the deletion persists (the durable destination grants) or the
        # journal reappears after a crash (reads fail closed).
        with suppress(OSError):
            _fsync_directory(self.path.parent)

    def _atomic_replace(self, destination: Path, data: bytes, *, prefix: str) -> None:
        fd = -1
        temporary: Path | None = None
        try:
            fd, raw = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=self.path.parent)
            temporary = Path(raw)
            os.chmod(temporary, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            temporary = None
            _fsync_directory(self.path.parent)
        finally:
            if fd >= 0:
                os.close(fd)
            if temporary is not None:
                with suppress(OSError):
                    temporary.unlink(missing_ok=True)

    def _recover_unlocked(self) -> OSError | None:
        """Restore the journaled state; retain the marker on every failure."""
        if not self.pending_path.exists():
            return None
        try:
            journal = self.pending_path.read_bytes()
            marker, separator, prior_bytes = journal.partition(b"\n")
            if not separator or marker not in {b"present", b"absent"}:
                raise OSError("malformed durable store recovery journal")
            if marker == b"present":
                self._atomic_replace(self.path, prior_bytes, prefix=".durable-rollback-")
            else:
                self.path.unlink(missing_ok=True)
                _fsync_directory(self.path.parent)
            self.pending_path.unlink()
            with suppress(OSError):
                _fsync_directory(self.path.parent)
        except OSError as exc:
            return exc
        return None
