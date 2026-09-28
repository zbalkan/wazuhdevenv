"""Managed wazuhdevenv state and process locking."""

from __future__ import annotations

import errno
import fcntl
import json
import os
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from .errors import ConfigurationError


def ensure_managed_home(path: Path) -> None:
    if path.is_symlink():
        raise ConfigurationError(f"managed home must not be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True)
    for name in ("cache", "corpora", "logs"):
        child = path / name
        if child.is_symlink():
            raise ConfigurationError(
                f"managed state directory must not be a symlink: {child}"
            )
        child.mkdir(exist_ok=True)


def managed_lock_path(path: Path) -> Path:
    """Return the stable sibling lock path for a managed home."""
    return path.with_name(f"{path.name}.lock")


@contextmanager
def managed_lock(path: Path) -> Generator[None]:
    lock_path = managed_lock_path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW  # type: ignore
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ConfigurationError(
                f"lock file must not be a symlink: {lock_path}"
            ) from exc
        raise

    with os.fdopen(fd, "a+", encoding="utf-8") as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore
        except BlockingIOError as exc:
            raise RuntimeError(
                "another wazuhdevenv operation is already running"
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)  # type: ignore


def _valid_schema_version(value: object) -> bool:
    return type(value) is int and value == 1


def load_state(path: Path) -> dict[str, object]:
    state_path = path / "state.json"
    if state_path.is_symlink():
        raise ConfigurationError(f"state file must not be a symlink: {state_path}")
    if not state_path.exists():
        return {"schema_version": 1}
    data = json.loads(state_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not _valid_schema_version(
        data.get("schema_version")
    ):
        raise ValueError(f"unsupported state file: {state_path}")
    return data


def save_state(path: Path, state: dict[str, object]) -> None:
    schema_version = state.get("schema_version", 1)
    if not _valid_schema_version(schema_version):
        raise ValueError(f"unsupported state schema version: {schema_version}")

    target = path / "state.json"
    fd, temporary_name = tempfile.mkstemp(prefix=".state.", dir=path, text=True)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({**state, "schema_version": 1}, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
