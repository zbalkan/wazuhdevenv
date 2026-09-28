import os
from pathlib import Path

import pytest

from wazuhdevenv.errors import ConfigurationError  # type: ignore
from wazuhdevenv.paths import (  # type: ignore
    InvokingUser,
    managed_home,
    resolve_workspace,
)


def test_workspace_is_resolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "a").mkdir()
    child = tmp_path / "a/../project"

    assert resolve_workspace(str(child)) == (tmp_path / "project").resolve()


@pytest.mark.parametrize("path", ["/", "/etc", "/var/lib", "/usr/local"])
def test_sensitive_system_workspaces_are_rejected(path: str) -> None:
    with pytest.raises(ConfigurationError, match="refusing to use system directory"):
        resolve_workspace(path)


def test_workspace_default_and_relative_paths_are_resolved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    resolved = tmp_path.resolve()

    assert resolve_workspace(None) == resolved
    assert resolve_workspace("project") == resolved / "project"


def test_workspace_expands_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    assert resolve_workspace("~/project") == tmp_path.resolve() / "project"


@pytest.mark.parametrize("override", ["/", "/etc/wazuhdevenv", "/var/lib/wazuhdevenv"])
def test_managed_home_rejects_sensitive_system_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: str,
) -> None:
    monkeypatch.setenv("WAZUHDEVENV_HOME", override)

    with pytest.raises(ConfigurationError):
        managed_home(InvokingUser("test", 1000, 1000, tmp_path))


def test_managed_home_rejects_symlink_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "managed-link"
    link.symlink_to(target, target_is_directory=True)
    monkeypatch.setenv("WAZUHDEVENV_HOME", str(link))

    with pytest.raises(ConfigurationError, match="managed home must not be a symlink"):
        managed_home(InvokingUser("test", 1000, 1000, tmp_path))


def test_invoking_user_uses_current_uid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Entry:
        pw_name = "tester"
        pw_uid = 1000
        pw_gid = 1000
        pw_dir = str(tmp_path)

    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr("wazuhdevenv.paths.pwd.getpwuid", lambda uid: Entry())

    assert InvokingUser.current() == InvokingUser("tester", 1000, 1000, tmp_path)


def test_unknown_invoking_user_is_reported_as_configuration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "getuid", lambda: 424242)
    monkeypatch.setattr(
        "wazuhdevenv.paths.pwd.getpwuid",
        lambda uid: (_ for _ in ()).throw(KeyError(uid)),
    )

    with pytest.raises(ConfigurationError, match="invoking user does not exist: 424242"):
        InvokingUser.current()
