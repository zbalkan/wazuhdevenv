from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from wazuhdevenv.errors import CommandError  # type: ignore
from wazuhdevenv.paths import InvokingUser  # type: ignore
from wazuhdevenv.runner import TRUSTED_EXEC_PATH, CommandRunner  # type: ignore


def _user(tmp_path: Path) -> InvokingUser:
    return InvokingUser("test", 1000, 1000, tmp_path)


def test_trusted_which_uses_privileged_system_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str | None]] = []

    def fake_which(executable: str, path: str | None = None) -> str | None:
        calls.append((executable, path))
        if path == TRUSTED_EXEC_PATH:
            return f"/usr/bin/{executable}"
        return f"/home/test/bin/{executable}"

    monkeypatch.setattr(shutil, "which", fake_which)

    assert CommandRunner.trusted_which("install") == "/usr/bin/install"
    assert calls == [("install", TRUSTED_EXEC_PATH)]


def test_privileged_bare_command_uses_trusted_system_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_which(executable: str, path: str | None = None) -> str | None:
        if executable == "sudo":
            return "/usr/bin/sudo"
        if executable == "cat" and path is not None:
            return "/usr/bin/cat"
        if executable == "cat":
            return "/tmp/attacker/cat"
        return None

    monkeypatch.setattr(shutil, "which", fake_which)

    assert CommandRunner(_user(tmp_path)).command(
        ["cat", "/etc/fstab"],
        privileged=True,
    ) == [
        "/usr/bin/sudo",
        "--",
        "/usr/bin/cat",
        "/etc/fstab",
    ]


def test_privileged_wazuh_absolute_executable_is_allowed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        shutil,
        "which",
        lambda executable, path=None: "/usr/bin/sudo" if executable == "sudo" else None,
    )

    assert CommandRunner(_user(tmp_path)).command(
        ["/var/ossec/bin/wazuh-analysisd", "-t"],
        privileged=True,
    ) == [
        "/usr/bin/sudo",
        "--",
        "/var/ossec/bin/wazuh-analysisd",
        "-t",
    ]


@pytest.mark.parametrize("executable", ["./tool", "../tool", "subdir/tool"])
def test_privileged_relative_path_is_rejected(
    tmp_path: Path,
    executable: str,
) -> None:
    with pytest.raises(CommandError, match="absolute path or bare command name"):
        CommandRunner(_user(tmp_path)).command([executable], privileged=True)


def test_privileged_absolute_executable_outside_trusted_roots_is_rejected(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "tool"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")

    with pytest.raises(CommandError, match="outside trusted roots"):
        CommandRunner(_user(tmp_path)).command([str(executable)], privileged=True)


def test_unprivileged_command_uses_normal_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        shutil,
        "which",
        lambda executable, path=None: "/usr/local/bin/tool" if executable == "tool" else None,
    )

    assert CommandRunner(_user(tmp_path)).command(["tool", "arg"]) == [
        "/usr/local/bin/tool",
        "arg",
    ]


def test_missing_command_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda executable, path=None: None)

    with pytest.raises(CommandError, match="required command not found"):
        CommandRunner(_user(tmp_path)).command(["missing"])
