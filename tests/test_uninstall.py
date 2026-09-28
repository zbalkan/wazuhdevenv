from __future__ import annotations

import json
from pathlib import Path

import pytest

from wazuhdevenv import uninstall  # type: ignore
from wazuhdevenv.errors import ConfigurationError  # type: ignore


def test_required_state_accepts_legacy_state(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    home.mkdir()
    workspace = tmp_path / "workspace"
    (home / "state.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "workspace": str(workspace),
                "wazuh_home": "/var/ossec",
                "wazuh_version": "4.14.8",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    _, resolved, provenance, legacy = uninstall._required_state(home)

    assert resolved == workspace
    assert provenance == {}
    assert legacy is True


def test_required_state_reads_uninstall_provenance(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    home.mkdir()
    workspace = tmp_path / "workspace"
    provenance = {"wazuh_installed_by_tool": True}
    (home / "state.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "workspace": str(workspace),
                "provisioning": provenance,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    _, resolved, loaded, legacy = uninstall._required_state(home)

    assert resolved == workspace
    assert loaded == provenance
    assert legacy is False


def test_remove_mounts_unmounts_and_verifies_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    events: list[list[str]] = []

    class FakeRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ):
            assert privileged is True
            if args[0] == "mountpoint":
                assert check is False
            elif args[0] == "umount":
                assert check is True
            events.append(args)
            return type(
                "Result",
                (),
                {"returncode": 1 if args[0] == "mountpoint" else 0},
            )()

    monkeypatch.setattr(uninstall, "_same_bind_mount", lambda *args: True)

    removed = uninstall._remove_mounts(FakeRunner(), workspace, set())  # type: ignore

    assert events == [
        ["umount", "/var/ossec/etc/rules"],
        ["mountpoint", "-q", "/var/ossec/etc/rules"],
        ["umount", "/var/ossec/etc/decoders"],
        ["mountpoint", "-q", "/var/ossec/etc/decoders"],
    ]
    assert removed == [
        "bind mount: /var/ossec/etc/rules",
        "bind mount: /var/ossec/etc/decoders",
    ]


def test_remove_mounts_refuses_to_continue_if_target_remains_mounted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"

    class FakeRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ):
            del check
            assert privileged is True
            return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(uninstall, "_same_bind_mount", lambda *args: True)

    with pytest.raises(
        ConfigurationError,
        match="failed to unmount /var/ossec/etc/rules",
    ):
        uninstall._remove_mounts(FakeRunner(), workspace, set())  # type: ignore


def test_prepare_package_directories_empties_and_restores_metadata() -> None:
    commands: list[tuple[list[str], bool]] = []

    class FakeRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ):
            assert privileged is True
            commands.append((args, check))
            if args[0] == "mountpoint":
                return type("Result", (), {"returncode": 1})()
            if args[:2] == ["test", "-L"]:
                return type("Result", (), {"returncode": 1})()
            return type("Result", (), {"returncode": 0})()

        def capture(
            self,
            args: list[str],
            *,
            privileged: bool = False,
        ) -> str:
            assert args == ["findmnt", "-rn", "-o", "TARGET"]
            assert privileged is True
            return ""

    uninstall._prepare_package_directories(FakeRunner())  # type: ignore

    for target in (
        "/var/ossec/etc/rules",
        "/var/ossec/etc/decoders",
    ):
        assert (["mountpoint", "-q", target], False) in commands
        assert (["test", "-L", target], False) in commands
        assert (["test", "-e", target], False) in commands
        assert (["test", "-d", target], False) in commands
        assert (
            [
                "find",
                target,
                "-mindepth",
                "1",
                "-maxdepth",
                "1",
                "-exec",
                "rm",
                "-rf",
                "--",
                "{}",
                "+",
            ],
            True,
        ) in commands
        assert (["chown", "root:wazuh", target], True) in commands
        assert (["chmod", "0770", target], True) in commands
        assert (["rm", "-rf", "--", target], True) not in commands


def test_prepare_package_directories_creates_missing_target() -> None:
    commands: list[tuple[list[str], bool]] = []

    class FakeRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ):
            assert privileged is True
            commands.append((args, check))
            if args[0] == "mountpoint" or args[:2] == ["test", "-L"]:
                return type("Result", (), {"returncode": 1})()
            if args[:2] == ["test", "-e"]:
                return type("Result", (), {"returncode": 1})()
            return type("Result", (), {"returncode": 0})()

        def capture(
            self,
            args: list[str],
            *,
            privileged: bool = False,
        ) -> str:
            assert args == ["findmnt", "-rn", "-o", "TARGET"]
            assert privileged is True
            return ""

    uninstall._prepare_package_directories(FakeRunner())  # type: ignore

    for target in (
        "/var/ossec/etc/rules",
        "/var/ossec/etc/decoders",
    ):
        assert (["mkdir", "-p", target], True) in commands
        assert (["chown", "root:wazuh", target], True) in commands
        assert (["chmod", "0770", target], True) in commands


def test_prepare_package_directories_refuses_mounted_target() -> None:
    class FakeRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ):
            del args, check
            assert privileged is True
            return type("Result", (), {"returncode": 0})()

    with pytest.raises(
        ConfigurationError,
        match="/var/ossec/etc/rules is still mounted",
    ):
        uninstall._prepare_package_directories(FakeRunner())  # type: ignore


def test_prepare_package_directories_preflights_both_targets_before_mutation() -> None:
    commands: list[list[str]] = []

    class FakeRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ):
            assert privileged is True
            commands.append(args)
            if args == ["mountpoint", "-q", "/var/ossec/etc/decoders"]:
                assert check is False
                return type("Result", (), {"returncode": 0})()
            if args[0] == "mountpoint" or args[:2] == ["test", "-L"]:
                return type("Result", (), {"returncode": 1})()
            return type("Result", (), {"returncode": 0})()

        def capture(
            self,
            args: list[str],
            *,
            privileged: bool = False,
        ) -> str:
            assert args == ["findmnt", "-rn", "-o", "TARGET"]
            assert privileged is True
            return ""

    with pytest.raises(
        ConfigurationError,
        match="/var/ossec/etc/decoders is still mounted",
    ):
        uninstall._prepare_package_directories(FakeRunner())  # type: ignore

    assert not any(
        args[0] in {"find", "mkdir", "chown", "chmod"}
        for args in commands
    )


def test_prepare_package_directories_refuses_nested_mount_before_mutation() -> None:
    commands: list[list[str]] = []

    class FakeRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ):
            assert privileged is True
            commands.append(args)
            if args[0] == "mountpoint" or args[:2] == ["test", "-L"]:
                return type("Result", (), {"returncode": 1})()
            return type("Result", (), {"returncode": 0})()

        def capture(
            self,
            args: list[str],
            *,
            privileged: bool = False,
        ) -> str:
            assert args == ["findmnt", "-rn", "-o", "TARGET"]
            assert privileged is True
            return "/var/ossec/etc/rules/nested\n"

    with pytest.raises(
        ConfigurationError,
        match="contains mounted content",
    ):
        uninstall._prepare_package_directories(FakeRunner())  # type: ignore

    assert not any(
        args[0] in {"find", "mkdir", "chown", "chmod"}
        for args in commands
    )


def test_remove_fstab_entries_preserves_unrelated_content_and_reloads_systemd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    rules = (workspace / "rules").resolve()
    decoders = (workspace / "decoders").resolve()
    original = (
        "UUID=root / ext4 defaults 0 1\n"
        f"{rules} /var/ossec/etc/rules none bind 0 0\n"
        f"{decoders} /var/ossec/etc/decoders none bind 0 0\n"
        "# keep this comment\n"
    )
    expected = (
        "UUID=root / ext4 defaults 0 1\n"
        "# keep this comment\n"
    )
    current = original
    writes: list[str] = []
    commands: list[list[str]] = []

    class FakeRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ):
            del check
            assert privileged is True
            commands.append(args)
            return type("Result", (), {"returncode": 0})()

    def read_fstab(runner: object, path: Path) -> str:
        del runner, path
        return current

    def rewrite_fstab(runner: object, path: Path, text: str) -> None:
        nonlocal current
        del runner, path
        current = text
        writes.append(text)

    monkeypatch.setattr(uninstall, "_read_optional_privileged", read_fstab)
    monkeypatch.setattr(uninstall, "_rewrite_preserving_metadata", rewrite_fstab)
    monkeypatch.setattr(uninstall, "_service_manager", lambda: "systemd")

    removed = uninstall._remove_fstab_entries(FakeRunner(), workspace, set())  # type: ignore

    assert removed == [
        "/etc/fstab entry for /var/ossec/etc/rules",
        "/etc/fstab entry for /var/ossec/etc/decoders",
    ]
    assert writes == [expected]
    assert current == expected
    assert commands == [["systemctl", "daemon-reload"]]


def test_remove_fstab_entries_refuses_if_rewrite_does_not_persist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    rules = (workspace / "rules").resolve()
    original = f"{rules} /var/ossec/etc/rules none bind 0 0\n"

    monkeypatch.setattr(
        uninstall,
        "_read_optional_privileged",
        lambda runner, path: original,
    )
    monkeypatch.setattr(
        uninstall,
        "_rewrite_preserving_metadata",
        lambda runner, path, text: None,
    )

    with pytest.raises(
        ConfigurationError,
        match="failed to remove managed /etc/fstab entries",
    ):
        uninstall._remove_fstab_entries(object(), workspace, set())  # type: ignore


def test_remove_fstab_entries_refuses_changed_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    original = (
        "/somewhere-else /var/ossec/etc/rules none bind 0 0\n"
    )

    monkeypatch.setattr(
        uninstall,
        "_read_optional_privileged",
        lambda runner, path: original,
    )

    with pytest.raises(ConfigurationError, match="changed since initialization"):
        uninstall._remove_fstab_entries(object(), workspace, set())  # type: ignore


def test_remove_fstab_entries_refuses_whitespace_changed_managed_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    rules = (workspace / "rules").resolve()
    original = f"  {rules} /var/ossec/etc/rules none bind 0 0\n"

    monkeypatch.setattr(
        uninstall,
        "_read_optional_privileged",
        lambda runner, path: original,
    )

    with pytest.raises(ConfigurationError, match="changed since initialization"):
        uninstall._remove_fstab_entries(object(), workspace, set())  # type: ignore


def test_detach_workspace_validates_fstab_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    stages: list[str] = []

    monkeypatch.setattr(
        uninstall,
        "_preflight_retained_mounts",
        lambda *args, **kwargs: stages.append("mount-preflight"),
    )
    monkeypatch.setattr(
        uninstall,
        "_preflight_fstab_entries",
        lambda *args: stages.append("fstab-preflight"),
    )
    monkeypatch.setattr(
        uninstall,
        "stop_wazuh",
        lambda runner: stages.append("stop"),
    )
    monkeypatch.setattr(
        uninstall,
        "_remove_mounts",
        lambda *args: stages.append("mounts") or ["mounts removed"],  # type: ignore
    )
    monkeypatch.setattr(
        uninstall,
        "_remove_fstab_entries",
        lambda *args: stages.append("fstab") or ["fstab removed"],  # type: ignore
    )

    removed = uninstall._detach_workspace(
        object(),  # type: ignore
        workspace,
        set(),
        set(),
        removing_wazuh=False,
    )

    assert stages == [
        "mount-preflight",
        "fstab-preflight",
        "stop",
        "mounts",
        "fstab",
    ]
    assert removed == ["mounts removed", "fstab removed"]


def test_detach_workspace_changed_fstab_fails_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    mutations: list[str] = []

    monkeypatch.setattr(
        uninstall,
        "_preflight_retained_mounts",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        uninstall,
        "_preflight_fstab_entries",
        lambda *args: (_ for _ in ()).throw(
            ConfigurationError("fstab entry changed")
        ),
    )
    monkeypatch.setattr(
        uninstall,
        "stop_wazuh",
        lambda runner: mutations.append("stop"),
    )
    monkeypatch.setattr(
        uninstall,
        "_remove_mounts",
        lambda *args: mutations.append("mounts") or [],  # type: ignore
    )

    with pytest.raises(ConfigurationError, match="fstab entry changed"):
        uninstall._detach_workspace(
            object(),  # type: ignore
            workspace,
            set(),
            set(),
            removing_wazuh=False,
        )

    assert mutations == []


def test_detach_workspace_rejects_retained_mount_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    retained = Path("/var/ossec/etc/rules")
    mutations: list[str] = []

    class FakeRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ):
            assert args == ["mountpoint", "-q", str(retained)]
            assert privileged is True
            assert check is False
            return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(
        uninstall,
        "stop_wazuh",
        lambda runner: mutations.append("stop"),
    )
    monkeypatch.setattr(
        uninstall,
        "_remove_mounts",
        lambda *args: mutations.append("mounts") or [],  # type: ignore
    )
    monkeypatch.setattr(
        uninstall,
        "_preflight_fstab_entries",
        lambda *args: mutations.append("fstab-preflight"),
    )

    with pytest.raises(
        ConfigurationError,
        match="cannot remove tool-installed Wazuh",
    ):
        uninstall._detach_workspace(
            FakeRunner(),  # type: ignore
            workspace,
            {retained},
            set(),
            removing_wazuh=True,
        )

    assert mutations == []


def test_preflight_wazuh_version_rejects_changed_installation() -> None:
    class FakePackageManager:
        def installed_version(self) -> str:
            return "4.15.0"

    with pytest.raises(ConfigurationError, match="changed since initialization"):
        uninstall._preflight_wazuh_version(
            FakePackageManager(),  # type: ignore
            {"wazuh_version": "4.14.8"},
        )


def test_preflight_wazuh_version_allows_removed_package() -> None:
    class FakePackageManager:
        def installed_version(self) -> None:
            return None

    uninstall._preflight_wazuh_version(
        FakePackageManager(),  # type: ignore
        {"wazuh_version": "4.14.8"},
    )



def test_targets_rejects_malformed_provenance() -> None:
    with pytest.raises(ConfigurationError, match="preexisting_mounts"):
        uninstall._targets(["/var/ossec/etc/rules", 123], "preexisting_mounts")


def test_restore_service_restarts_with_recorded_enablement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    monkeypatch.setattr(
        uninstall,
        "start_wazuh",
        lambda runner, *, enable: events.append(("start", enable)),
    )
    monkeypatch.setattr(
        uninstall,
        "wait_for_logtest",
        lambda runner: events.append("ready"),
    )

    uninstall._restore_service(
        object(),  # type: ignore
        was_active=True,
        was_enabled=False,
    )

    assert events == [("start", False), "ready"]


def test_remove_wazuh_recreates_directories_before_package_removal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stages: list[object] = []

    class FakePackageManager:
        family = "rpm"
        command = "dnf"

        def installed_version(self) -> str:
            return "4.14.8"

    class FakeRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ):
            del check
            assert privileged is True
            stages.append(args)
            return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(
        uninstall,
        "_prepare_package_directories",
        lambda runner: stages.append("directories"),
    )

    assert uninstall._remove_wazuh(FakeRunner(), FakePackageManager()) is True  # type: ignore
    assert stages == [
        "directories",
        ["dnf", "-y", "remove", "wazuh-manager"],
        ["rm", "-rf", "/var/ossec"],
    ]


def test_remove_group_membership_is_idempotent() -> None:
    class FakeRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ):
            del privileged, check
            assert args == ["getent", "group", "wazuh"]
            return type("Result", (), {"returncode": 0})()

        def capture(
            self,
            args: list[str],
            *,
            privileged: bool = False,
        ) -> str:
            assert args == ["id", "-nG", "tester"]
            assert privileged is True
            return "tester users\n"

    removed = uninstall._remove_group_membership(
        FakeRunner(),  # type: ignore
        type(  # type: ignore
            "User",
            (),
            {"name": "tester"},
        )(),
        {"group_membership_added": True},
    )

    assert removed is False


def test_format_uninstall_report_lists_remnants_explicitly(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    managed_home = tmp_path / "managed"
    result = uninstall.UninstallResult(
        workspace=workspace,
        removed=("Wazuh Manager package",),
        restored=("pre-initialization repository configuration",),
        preserved=(f"user workspace content: {workspace / 'rules'}",),
        remnants=("system prerequisite packages retained: util-linux",),
    )

    report = uninstall.format_uninstall_report(result, managed_home)

    assert "Removed:" in report
    assert "Restored:" in report
    assert "Preserved:" in report
    assert "Remnants:" in report
    assert f"managed state: {managed_home}" in report
    assert "system prerequisite packages retained: util-linux" in report
    assert "persistent operation lock retained for serialization" in report
    assert str(managed_home.with_name(f"{managed_home.name}.lock")) in report


def test_strings_rejects_malformed_dependency_provenance() -> None:
    with pytest.raises(ConfigurationError, match="system_dependencies_installed"):
        uninstall._strings(
            ["util-linux", 123],
            "system_dependencies_installed",
        )


def test_preflight_restore_accepts_already_restored_state() -> None:
    original = "<config>original</config>"

    class FakeRunner:
        def capture(
            self,
            args: list[str],
            *,
            privileged: bool = False,
        ) -> str:
            assert args == ["cat", "/var/ossec/etc/ossec.conf"]
            assert privileged is True
            return original

    uninstall._preflight_restore(
        FakeRunner(),  # type: ignore
        Path("/var/ossec/etc/ossec.conf"),
        original,
        lambda value: value.replace("original", "configured"),
    )


def test_preflight_restore_rejects_unattributed_later_change() -> None:
    class FakeRunner:
        def capture(
            self,
            args: list[str],
            *,
            privileged: bool = False,
        ) -> str:
            del args
            assert privileged is True
            return "<config>changed later</config>"

    with pytest.raises(ConfigurationError, match="changed after initialization"):
        uninstall._preflight_restore(
            FakeRunner(),  # type: ignore
            Path("/var/ossec/etc/ossec.conf"),
            "<config>original</config>",
            lambda value: value.replace("original", "configured"),
        )
