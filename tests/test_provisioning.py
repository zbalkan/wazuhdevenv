from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from wazuhdevenv import provisioning  # type: ignore
from wazuhdevenv.errors import ConfigurationError  # type: ignore
from wazuhdevenv.paths import InvokingUser  # type: ignore
from wazuhdevenv.provisioning import (  # type: ignore
    PackageManager,
    ProvisioningSnapshot,
)
from wazuhdevenv.runner import CommandRunner  # type: ignore


class RecordingRunner:
    def __init__(self, *, find_output: str = "") -> None:
        self.find_output = find_output
        self.commands: list[list[str]] = []
        self.find_targets: list[Path] = []

    def capture(self, args: list[str], *, privileged: bool = False) -> str:
        del privileged
        if args[0] == "find":
            self.find_targets.append(Path(args[1]))
            return self.find_output
        raise AssertionError(f"unexpected capture command: {args}")

    def run(
        self,
        args: list[str],
        *,
        privileged: bool = False,
        check: bool = True,
    ) -> SimpleNamespace:
        del privileged, check
        self.commands.append(args)
        return SimpleNamespace(returncode=0)


class DpkgRunner:
    def __init__(self, states: dict[str, str]) -> None:
        self.states = states

    def trusted_which(self, command: str) -> str | None:
        if command == "dpkg-query":
            return "/usr/bin/dpkg-query"
        return None

    def capture(self, args: list[str], *, privileged: bool = False) -> str:
        del privileged
        if args[:2] != ["/usr/bin/dpkg-query", "-W"]:
            raise AssertionError(f"unexpected command: {args}")
        package = args[-1]
        value = self.states.get(package)
        if value is None:
            raise provisioning.CommandError(f"package not found: {package}")
        return value


def _apt_manager(runner: object) -> PackageManager:
    manager = object.__new__(PackageManager)
    manager.runner = runner  # type: ignore
    manager.family = "apt"
    manager.command = "apt-get"
    return manager


def _snapshot(
    active: bool = False,
    enabled: bool | None = None,
) -> ProvisioningSnapshot:
    return ProvisioningSnapshot(
        service_was_active=active,
        service_was_enabled=enabled,
        ossec_conf="original ossec",
        windows_rules="original windows",
        fstab="original fstab",
        preexisting_mounts=frozenset(),
    )


def test_replace_simple_tag_is_idempotent() -> None:
    source = "<logall_json>no</logall_json>"
    changed = provisioning._replace_simple_tag(
        source,
        "logall_json",
        "yes",
        {"yes", "no"},
    )
    assert changed == "<logall_json>yes</logall_json>"
    assert (
        provisioning._replace_simple_tag(
            changed,
            "logall_json",
            "yes",
            {"yes", "no"},
        )
        == changed
    )


def test_replace_simple_tag_rejects_unknown_state() -> None:
    with pytest.raises(ConfigurationError, match="unexpected <logall_json>"):
        provisioning._replace_simple_tag(
            "<logall_json>maybe</logall_json>",
            "logall_json",
            "yes",
            {"yes", "no"},
        )


def test_rule_test_values_are_overwritten_without_reimplementing_wazuh_validation() -> (
    None
):
    text = """
<rule_test>
  <threads>unexpected</threads>
  <max_sessions>not-a-number</max_sessions>
  <session_timeout>whatever</session_timeout>
</rule_test>
"""
    text = provisioning._replace_block_child(
        text,
        r"<rule_test>.*?</rule_test>",
        "threads",
        "auto",
        None,
        "rule_test",
    )
    text = provisioning._replace_block_child(
        text,
        r"<rule_test>.*?</rule_test>",
        "max_sessions",
        "500",
        None,
        "rule_test",
    )
    text = provisioning._replace_block_child(
        text,
        r"<rule_test>.*?</rule_test>",
        "session_timeout",
        "1m",
        None,
        "rule_test",
    )

    assert "<threads>auto</threads>" in text
    assert "<max_sessions>500</max_sessions>" in text
    assert "<session_timeout>1m</session_timeout>" in text


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("4.14.8-1", "4.14.8"),
        ("wazuh-manager-4.14.10", "4.14.10"),
    ],
)
def test_normalize_wazuh_version(value: str, expected: str) -> None:
    assert provisioning._normalize_wazuh_version(value) == expected


def test_normalize_wazuh_version_rejects_invalid_value() -> None:
    with pytest.raises(ConfigurationError, match="cannot determine Wazuh version"):
        provisioning._normalize_wazuh_version("unknown")


def test_windows_rule_testing_transforms_only_known_default() -> None:
    changed = provisioning._render_windows_rule_testing(
        f"prefix\n{provisioning.WINDOWS_RULE_DEFAULT}\nsuffix"
    )

    assert provisioning.WINDOWS_RULE_EXPECTED in changed
    assert provisioning.WINDOWS_RULE_DEFAULT not in changed


def test_windows_rule_testing_rejects_unknown_rule_state() -> None:
    with pytest.raises(
        ConfigurationError, match="rule 60000 is in an unexpected state"
    ):
        provisioning._render_windows_rule_testing('<rule id="60000">different</rule>')


@pytest.mark.parametrize(
    ("target_name", "find_output"),
    [
        ("rules", ""),
        ("rules", "local_rules.xml\n"),
        ("decoders", ""),
        ("decoders", "local_decoder.xml\n"),
    ],
)
def test_default_wazuh_content_is_accepted(
    tmp_path: Path,
    target_name: str,
    find_output: str,
) -> None:
    runner = RecordingRunner(find_output=find_output)

    target = tmp_path / target_name
    provisioning._require_default_wazuh_content(
        runner,  # type: ignore
        target,
    )

    assert runner.find_targets == [target]


@pytest.mark.parametrize(
    ("target_name", "find_output"),
    [
        ("rules", "custom.xml\n"),
        ("rules", "local_rules.xml\ncustom.xml\n"),
        ("decoders", "custom.xml\n"),
        ("decoders", "subdir\n"),
    ],
)
def test_existing_custom_wazuh_content_is_rejected(
    tmp_path: Path,
    target_name: str,
    find_output: str,
) -> None:
    runner = RecordingRunner(find_output=find_output)

    with pytest.raises(
        ConfigurationError,
        match="expects a fresh/default development installation",
    ):
        target = tmp_path / target_name
        provisioning._require_default_wazuh_content(
            runner,  # type: ignore
            target,
        )

        assert runner.find_targets == [target]


def test_configure_bind_mounts_checks_wazuh_directories_before_mounting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, Path]] = []
    mounted: set[Path] = set()

    class BindRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ) -> SimpleNamespace:
            del privileged, check
            if args[:2] == ["mountpoint", "-q"]:
                return SimpleNamespace(returncode=0 if Path(args[2]) in mounted else 1)
            if args[:2] == ["mount", "--bind"]:
                target = Path(args[3])
                events.append(("mount", target))
                mounted.add(target)
                return SimpleNamespace(returncode=0)
            raise AssertionError(f"unexpected command: {args}")

    def require_default(runner: object, target: Path) -> None:
        del runner
        events.append(("check", target))

    monkeypatch.setattr(provisioning, "_require_default_wazuh_content", require_default)
    monkeypatch.setattr(provisioning, "_ensure_fstab", lambda *args: None)

    provisioning.configure_bind_mounts(BindRunner(), tmp_path / "workspace")  # type: ignore

    expected = [
        provisioning.WAZUH_HOME / "etc/rules",
        provisioning.WAZUH_HOME / "etc/decoders",
    ]
    assert events == [
        ("check", expected[0]),
        ("mount", expected[0]),
        ("check", expected[1]),
        ("mount", expected[1]),
    ]


@pytest.mark.parametrize(
    ("family", "path", "enabled_text", "disabled_text"),
    [
        (
            "apt",
            Path("/etc/apt/sources.list.d/wazuh.list"),
            provisioning.APT_REPOSITORY,
            f"#{provisioning.APT_REPOSITORY}",
        ),
        (
            "rpm",
            Path("/etc/yum.repos.d/wazuh.repo"),
            provisioning.RPM_REPOSITORY.format(enabled=1),
            provisioning.RPM_REPOSITORY.format(enabled=0),
        ),
    ],
)
def test_repository_toggle_only_rewrites_managed_content(
    monkeypatch: pytest.MonkeyPatch,
    family: str,
    path: Path,
    enabled_text: str,
    disabled_text: str,
) -> None:
    class RepoRunner:
        def __init__(self) -> None:
            self.content = disabled_text

        def capture(self, args: list[str], *, privileged: bool = False) -> str:
            assert args == ["cat", str(path)]
            assert privileged is True
            return self.content

    runner = RepoRunner()
    manager = object.__new__(PackageManager)
    manager.runner = runner  # type: ignore
    rewritten: list[str] = []

    monkeypatch.setattr(provisioning, "_privileged_exists", lambda *args: True)
    monkeypatch.setattr(
        provisioning,
        "_rewrite_preserving_metadata",
        lambda runner, target, content: rewritten.append(content),
    )

    if family == "apt":
        manager._set_apt_repository_enabled(True)
    else:
        manager._set_rpm_repository_enabled(True)

    assert rewritten == [enabled_text]


@pytest.mark.parametrize("family", ["apt", "rpm"])
def test_repository_setup_refuses_to_overwrite_custom_configuration(
    monkeypatch: pytest.MonkeyPatch,
    family: str,
) -> None:
    class RepoRunner:
        def capture(self, args: list[str], *, privileged: bool = False) -> str:
            del args
            assert privileged is True
            return "custom repository configuration\n"

    manager = object.__new__(PackageManager)
    manager.runner = RepoRunner()  # type: ignore
    monkeypatch.setattr(provisioning, "_privileged_exists", lambda *args: True)

    with pytest.raises(ConfigurationError, match="refusing to overwrite"):
        if family == "apt":
            manager._set_apt_repository_enabled(True)
        else:
            manager._set_rpm_repository_enabled(True)


def test_failed_apt_repository_setup_attempts_cleanup() -> None:
    manager = object.__new__(PackageManager)
    manager.family = "apt"
    manager.command = "apt-get"
    manager.runner = object()  # type: ignore
    manager.installed_version = lambda: None  # type: ignore[method-assign]
    events: list[str] = []

    def fail_setup() -> None:
        events.append("setup")
        raise RuntimeError("setup failed")

    manager._setup_apt_repository = fail_setup  # type: ignore[method-assign]
    manager._disable_apt_repository = lambda: events.append("cleanup")  # type: ignore[method-assign]
    manager._apt_install = (  # type: ignore[method-assign]
        lambda packages: (_ for _ in ()).throw(
            AssertionError(f"install must not run: {packages}")
        )
    )

    with pytest.raises(RuntimeError, match="setup failed"):
        manager.install_wazuh("4.14.8")

    assert events == ["setup", "cleanup"]


def test_failed_rpm_repository_setup_attempts_cleanup() -> None:
    manager = object.__new__(PackageManager)
    manager.family = "rpm"
    manager.command = "dnf"
    manager.runner = object()  # type: ignore
    manager.installed_version = lambda: None  # type: ignore[method-assign]
    events: list[object] = []

    def fail_setup() -> None:
        events.append("setup")
        raise RuntimeError("setup failed")

    manager._setup_rpm_repository = fail_setup  # type: ignore[method-assign]
    manager._set_rpm_repository_enabled = (  # type: ignore[method-assign]
        lambda enabled: events.append(("repository", enabled))
    )

    with pytest.raises(RuntimeError, match="setup failed"):
        manager.install_wazuh("4.14.8")

    assert events == ["setup", ("repository", False)]


def test_failed_apt_wazuh_install_disables_repository() -> None:
    events: list[object] = []

    class AptCleanupRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ) -> SimpleNamespace:
            del check
            assert args == ["apt-get", "update"]
            assert privileged is True
            events.append(("refresh", args))
            return SimpleNamespace(returncode=0)

    manager = object.__new__(PackageManager)
    manager.family = "apt"
    manager.command = "apt-get"
    manager.runner = AptCleanupRunner()  # type: ignore

    manager.installed_version = lambda: None  # type: ignore[method-assign]
    manager._setup_apt_repository = lambda: events.append("enable")  # type: ignore[method-assign]

    def fail_install(packages: list[str]) -> None:
        events.append(("install", packages))
        raise RuntimeError("install failed")

    manager._apt_install = fail_install  # type: ignore[method-assign]
    manager._set_apt_repository_enabled = (  # type: ignore[method-assign]
        lambda enabled: events.append(("repository", enabled))
    )

    with pytest.raises(RuntimeError, match="install failed"):
        manager.install_wazuh("4.14.8")

    assert events == [
        "enable",
        ("install", ["wazuh-manager=4.14.8-1"]),
        ("repository", False),
        ("refresh", ["apt-get", "update"]),
    ]


def test_failed_rpm_wazuh_install_disables_repository() -> None:
    events: list[object] = []

    class FailingRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ) -> SimpleNamespace:
            del check
            assert privileged is True
            events.append(("install", args))
            raise RuntimeError("install failed")

    manager = object.__new__(PackageManager)
    manager.family = "rpm"
    manager.command = "dnf"
    manager.runner = FailingRunner()  # type: ignore
    manager.installed_version = lambda: None  # type: ignore[method-assign]
    manager._setup_rpm_repository = lambda: events.append("enable")  # type: ignore[method-assign]
    manager._set_rpm_repository_enabled = (  # type: ignore[method-assign]
        lambda enabled: events.append(("repository", enabled))
    )

    with pytest.raises(RuntimeError, match="install failed"):
        manager.install_wazuh("4.14.8")

    assert events == [
        "enable",
        ("install", ["dnf", "-y", "install", "wazuh-manager-4.14.8-1"]),
        ("repository", False),
    ]


def test_repository_cleanup_failure_does_not_hide_install_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager = object.__new__(PackageManager)
    manager.family = "apt"
    manager.command = "apt-get"
    manager.runner = object()  # type: ignore
    manager.installed_version = lambda: None  # type: ignore[method-assign]
    manager._setup_apt_repository = lambda: None  # type: ignore[method-assign]

    def fail_install(packages: list[str]) -> None:
        del packages
        raise ValueError("original install failure")

    def fail_cleanup(enabled: bool) -> None:
        assert enabled is False
        raise RuntimeError("cleanup failure")

    manager._apt_install = fail_install  # type: ignore[method-assign]
    manager._set_apt_repository_enabled = fail_cleanup  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="original install failure"):
        manager.install_wazuh(None)

    assert "cleanup failure" in caplog.text


def test_package_manager_selection_uses_trusted_path() -> None:
    class TrustedPathRunner:
        def __init__(self) -> None:
            self.lookups: list[str] = []

        def trusted_which(self, command: str) -> str | None:
            self.lookups.append(command)
            if command == "dnf":
                return "/usr/bin/dnf"
            return None

    runner = TrustedPathRunner()
    manager = PackageManager(runner)  # type: ignore[arg-type]

    assert manager.family == "rpm"
    assert manager.command == "dnf"
    assert runner.lookups == ["apt-get", "dnf"]


def test_service_manager_uses_trusted_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lookups: list[str] = []

    def trusted_which(command: str) -> str | None:
        lookups.append(command)
        if command == "service":
            return "/usr/sbin/service"
        return None

    monkeypatch.setattr(CommandRunner, "trusted_which", staticmethod(trusted_which))

    assert provisioning._service_manager() == "sysv"
    assert lookups == ["systemctl", "service"]


def test_removed_apt_wazuh_package_is_not_reported_as_installed() -> None:
    manager = _apt_manager(
        DpkgRunner(
            {
                "wazuh-manager": "deinstall ok config-files\t4.14.8-1\n",
            }
        )
    )

    assert manager.installed_version() is None


def test_installed_rpm_wazuh_package_uses_trusted_query_path() -> None:
    class RpmVersionRunner:
        def trusted_which(self, command: str) -> str | None:
            return "/usr/bin/rpm" if command == "rpm" else None

        def capture(self, args: list[str], *, privileged: bool = False) -> str:
            assert privileged is False
            assert args == [
                "/usr/bin/rpm",
                "-q",
                "--qf",
                "%{VERSION}-%{RELEASE}",
                "wazuh-manager",
            ]
            return "4.14.8-1"

    manager = object.__new__(PackageManager)
    manager.runner = RpmVersionRunner()  # type: ignore
    manager.family = "rpm"
    manager.command = "dnf"

    assert manager.installed_version() == "4.14.8"


def test_installed_apt_wazuh_package_returns_normalized_version() -> None:
    manager = _apt_manager(
        DpkgRunner(
            {
                "wazuh-manager": "install ok installed\t4.14.8-1\n",
            }
        )
    )

    assert manager.installed_version() == "4.14.8"


def test_apt_dependency_probe_reinstalls_config_files_state() -> None:
    states = {
        "python3-venv": "deinstall ok config-files\t3.13.0-1\n",
        "util-linux": "install ok installed\t2.40.0\n",
        "coreutils": "install ok installed\t9.5\n",
        "findutils": "install ok installed\t4.10\n",
        "gnupg": "install ok installed\t2.4\n",
        "apt-transport-https": "install ok installed\t2.9\n",
    }
    manager = _apt_manager(DpkgRunner(states))
    installed: list[list[str]] = []
    manager._apt_install = lambda packages: installed.append(packages)  # type: ignore[method-assign]

    assert manager.ensure_system_dependencies() == ["python3-venv"]

    assert installed == [["python3-venv"]]


def test_missing_trusted_rpm_query_is_reported() -> None:
    class MissingRpmRunner:
        def trusted_which(self, command: str) -> str | None:
            return None

        def capture(self, args: list[str], *, privileged: bool = False) -> str:
            raise AssertionError(
                f"package query must not run when trusted rpm is missing: {args}, {privileged}"
            )

    manager = object.__new__(PackageManager)
    manager.runner = MissingRpmRunner()  # type: ignore
    manager.family = "rpm"
    manager.command = "dnf"

    with pytest.raises(
        provisioning.UnsupportedPlatformError,
        match="required package query command not found: rpm",
    ):
        manager.installed_version()


def test_rpm_dependencies_accept_coreutils_single_commands() -> None:
    class RpmRunner:
        def __init__(self) -> None:
            self.installs: list[list[str]] = []

        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ) -> SimpleNamespace:
            del check
            if args[:2] == ["/usr/bin/rpm", "-q"]:
                if args[2] not in {"python3", "util-linux", "findutils", "gnupg2"}:
                    raise AssertionError(f"unexpected RPM dependency probe: {args[2]}")
                return SimpleNamespace(returncode=1 if args[2] == "gnupg2" else 0)
            if args[:3] == ["dnf", "-y", "install"]:
                assert privileged is True
                self.installs.append(args[3:])
                return SimpleNamespace(returncode=0)
            raise AssertionError(f"unexpected command: {args}")

        def trusted_which(self, command: str) -> str | None:
            return f"/usr/bin/{command}"

    runner = RpmRunner()
    manager = object.__new__(PackageManager)
    manager.runner = runner  # type: ignore
    manager.family = "rpm"
    manager.command = "dnf"

    manager.ensure_system_dependencies()

    assert runner.installs == [["gnupg2"]]


def test_rpm_dependencies_install_coreutils_when_commands_are_missing() -> None:
    class RpmRunner:
        def __init__(self) -> None:
            self.installs: list[list[str]] = []

        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ) -> SimpleNamespace:
            del check
            if args[:2] == ["/usr/bin/rpm", "-q"]:
                return SimpleNamespace(returncode=0)
            if args[:3] == ["dnf", "-y", "install"]:
                assert privileged is True
                self.installs.append(args[3:])
                return SimpleNamespace(returncode=0)
            raise AssertionError(f"unexpected command: {args}")

        def trusted_which(self, command: str) -> str | None:
            return None if command == "install" else f"/usr/bin/{command}"

    runner = RpmRunner()
    manager = object.__new__(PackageManager)
    manager.runner = runner  # type: ignore
    manager.family = "rpm"
    manager.command = "dnf"

    manager.ensure_system_dependencies()

    assert runner.installs == [["coreutils"]]


def test_missing_fstab_is_created_with_first_bind_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MissingFstabRunner:
        def run(
            self,
            args: list[str],
            *,
            privileged: bool = False,
            check: bool = True,
        ) -> SimpleNamespace:
            del check
            assert privileged is True
            assert args == ["test", "-e", "/etc/fstab"]
            return SimpleNamespace(returncode=1)

        def capture(self, args: list[str], *, privileged: bool = False) -> str:
            raise AssertionError(
                f"missing fstab must not be read: {args}, {privileged}"
            )

    written: list[tuple[Path, str]] = []
    monkeypatch.setattr(
        provisioning,
        "_write_privileged",
        lambda runner, path, content, **kwargs: written.append((path, content)),
    )

    provisioning._ensure_fstab(
        MissingFstabRunner(),  # type: ignore
        Path("/workspace/rules"),
        Path("/var/ossec/etc/rules"),
    )

    assert written == [
        (
            Path("/etc/fstab"),
            "/workspace/rules /var/ossec/etc/rules none bind 0 0\n",
        )
    ]


def test_rollback_removes_fstab_created_by_failed_init(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = RecordingRunner()
    workspace = tmp_path / "workspace"
    (workspace / "rules").mkdir(parents=True)
    (workspace / "decoders").mkdir(parents=True)
    restored: list[Path] = []

    monkeypatch.setattr(provisioning, "_same_bind_mount", lambda *args: False)
    monkeypatch.setattr(
        provisioning,
        "_restore_text_if_changed",
        lambda runner, path, original: restored.append(path),
    )
    monkeypatch.setattr(provisioning, "stop_wazuh", lambda *args: None)

    snapshot = ProvisioningSnapshot(
        service_was_active=False,
        service_was_enabled=None,
        ossec_conf="original ossec",
        windows_rules="original windows",
        fstab=None,
        preexisting_mounts=frozenset(),
    )

    provisioning._rollback_provisioning(runner, workspace, snapshot)  # type: ignore

    assert ["rm", "-f", "/etc/fstab"] in runner.commands
    assert restored == [
        provisioning.OSSEC_CONF,
        provisioning.WINDOWS_RULES,
    ]


def test_group_membership_already_present_skips_usermod() -> None:
    class GroupRunner:
        def __init__(self) -> None:
            self.commands: list[list[str]] = []

        def capture(self, args: list[str], **kwargs: object) -> str:
            assert args == ["id", "-nG", "tester"]
            assert kwargs == {"privileged": True}
            return "tester wazuh\n"

        def run(self, args: list[str], **kwargs: object) -> SimpleNamespace:
            del kwargs
            self.commands.append(args)
            return SimpleNamespace(returncode=0)

    runner = GroupRunner()
    user = InvokingUser("tester", 1000, 1000, Path("/home/tester"))

    assert provisioning.ensure_group_membership(runner, user) is False  # type: ignore

    assert runner.commands == []


def test_group_membership_is_added_and_verified() -> None:
    class GroupRunner:
        def __init__(self) -> None:
            self.capture_calls = 0
            self.commands: list[list[str]] = []

        def capture(self, args: list[str], **kwargs: object) -> str:
            del args, kwargs
            self.capture_calls += 1
            return "tester\n" if self.capture_calls == 1 else "tester wazuh\n"

        def run(self, args: list[str], **kwargs: object) -> SimpleNamespace:
            del kwargs
            self.commands.append(args)
            return SimpleNamespace(returncode=0)

    runner = GroupRunner()
    user = InvokingUser("tester", 1000, 1000, Path("/home/tester"))

    assert provisioning.ensure_group_membership(runner, user) is True  # type: ignore

    assert runner.commands == [["usermod", "-a", "-G", "wazuh", "tester"]]
    assert runner.capture_calls == 2


def test_group_membership_failure_is_fatal() -> None:
    class GroupRunner:
        def capture(self, args: list[str], **kwargs: object) -> str:
            del args, kwargs
            return "tester\n"

        def run(self, args: list[str], **kwargs: object) -> SimpleNamespace:
            del args, kwargs
            return SimpleNamespace(returncode=0)

    user = InvokingUser("tester", 1000, 1000, Path("/home/tester"))

    with pytest.raises(
        ConfigurationError, match="failed to add tester to the wazuh group"
    ):
        provisioning.ensure_group_membership(GroupRunner(), user)  # type: ignore


def test_default_acls_are_applied_when_setfacl_is_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AclRunner:
        def __init__(self) -> None:
            self.commands: list[tuple[list[str], bool]] = []

        def run_as_user(
            self,
            args: list[str],
            *,
            check: bool = True,
        ) -> SimpleNamespace:
            self.commands.append((args, check))
            return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        provisioning.shutil,
        "which",
        lambda command: "/usr/bin/setfacl" if command == "setfacl" else None,
    )
    runner = AclRunner()
    workspace = tmp_path / "workspace"

    provisioning.configure_default_acls(runner, workspace)  # type: ignore

    acl = "u:wazuh:rwx,g:wazuh:rwx,o::---"
    assert runner.commands == [
        (["setfacl", "-d", "-m", acl, str(workspace / "rules")], False),
        (["setfacl", "-d", "-m", acl, str(workspace / "decoders")], False),
    ]


def test_default_acls_are_optional_when_setfacl_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AclRunner:
        def run_as_user(self, *args: object, **kwargs: object) -> object:
            raise AssertionError("setfacl must not be invoked")

    monkeypatch.setattr(provisioning.shutil, "which", lambda command: None)

    provisioning.configure_default_acls(AclRunner(), tmp_path / "workspace")  # type: ignore


def test_default_acl_failure_does_not_fail_provisioning_helper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AclRunner:
        def run_as_user(
            self,
            args: list[str],
            *,
            check: bool = True,
        ) -> SimpleNamespace:
            del args, check
            return SimpleNamespace(returncode=1)

    monkeypatch.setattr(
        provisioning.shutil, "which", lambda command: "/usr/bin/setfacl"
    )

    provisioning.configure_default_acls(AclRunner(), tmp_path / "workspace")  # type: ignore


def test_workspace_permissions_keep_invoking_user_as_owner(tmp_path: Path) -> None:
    runner = RecordingRunner()
    workspace = tmp_path / "workspace"
    (workspace / "rules").mkdir(parents=True)
    (workspace / "decoders").mkdir()
    user = InvokingUser("tester", 1000, 1000, tmp_path)

    provisioning.configure_permissions(runner, workspace, user)  # type: ignore

    for name in ("rules", "decoders"):
        path = str(workspace / name)
        assert [
            "find",
            path,
            "-type",
            "d",
            "-exec",
            "chown",
            "tester:wazuh",
            "{}",
            "+",
        ] in runner.commands
        assert [
            "find",
            path,
            "-type",
            "f",
            "-exec",
            "chown",
            "tester:wazuh",
            "{}",
            "+",
        ] in runner.commands


def test_initialize_rejects_second_init_before_provisioning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    workspace = tmp_path / "workspace"
    (home / "state.json").write_text(
        '{"schema_version": 1, "workspace": "/existing/workspace", '
        '"wazuh_home": "/var/ossec", "wazuh_version": "4.14.8"}\n',
        encoding="utf-8",
    )
    user = InvokingUser("tester", os.getuid(), os.getgid(), tmp_path)  # type: ignore
    events: list[str] = []

    monkeypatch.setattr(provisioning, "ensure_linux", lambda: events.append("linux"))

    def unexpected_runner(user: InvokingUser) -> object:
        del user
        events.append("runner")
        raise AssertionError("provisioning must not start")

    monkeypatch.setattr(provisioning, "CommandRunner", unexpected_runner)

    with pytest.raises(
        ConfigurationError,
        match=r"already initialized.*init.*only be run once",
    ) as exc_info:
        provisioning.initialize(workspace, home, user)

    message = str(exc_info.value)
    assert "Workspace: /existing/workspace" in message
    assert "Wazuh home: /var/ossec" in message
    assert "Wazuh version: 4.14.8" in message
    assert f"State: {home / 'state.json'}" in message
    assert events == ["linux"]


def test_initialize_checks_service_manager_before_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    user = InvokingUser("tester", os.getuid(), os.getgid(), tmp_path)  # type: ignore

    class FakePackageManager:
        def __init__(self, runner: object) -> None:
            del runner

        def ensure_system_dependencies(self) -> None:
            events.append("dependencies")

        def install_wazuh(self, requested_version: str | None) -> str:
            del requested_version
            events.append("install")
            return "4.14.8"

    monkeypatch.setattr(provisioning, "ensure_linux", lambda: events.append("linux"))
    monkeypatch.setattr(provisioning, "CommandRunner", lambda user: object())
    monkeypatch.setattr(provisioning, "PackageManager", FakePackageManager)
    monkeypatch.setattr(
        provisioning, "_service_manager", lambda: events.append("service") or "systemd"
    )  # type: ignore
    monkeypatch.setattr(
        provisioning, "prepare_workspace", lambda *args: events.append("workspace")
    )
    monkeypatch.setattr(
        provisioning, "ensure_workspace_venv", lambda *args: events.append("venv")
    )
    monkeypatch.setattr(
        provisioning, "preflight_bind_mounts", lambda *args: events.append("preflight")
    )
    monkeypatch.setattr(provisioning, "is_wazuh_active", lambda runner: False)
    monkeypatch.setattr(provisioning, "is_wazuh_enabled", lambda runner: False)
    monkeypatch.setattr(provisioning, "_capture_snapshot", lambda *args: _snapshot())
    monkeypatch.setattr(provisioning, "_render_ossec_config", lambda value: value)
    monkeypatch.setattr(
        provisioning, "_render_windows_rule_testing", lambda value: value
    )
    monkeypatch.setattr(
        provisioning, "ensure_group_membership", lambda *args: events.append("group")
    )
    monkeypatch.setattr(
        provisioning, "stop_wazuh", lambda *args: events.append("stop") or False
    )  # type: ignore
    monkeypatch.setattr(
        provisioning, "configure_ossec", lambda *args: events.append("ossec")
    )
    monkeypatch.setattr(
        provisioning,
        "configure_windows_rule_testing",
        lambda *args: events.append("windows"),
    )
    monkeypatch.setattr(
        provisioning, "configure_bind_mounts", lambda *args: events.append("mounts")
    )
    monkeypatch.setattr(
        provisioning,
        "configure_permissions",
        lambda *args: events.append("permissions"),
    )
    monkeypatch.setattr(
        provisioning, "configure_default_acls", lambda *args: events.append("acls")
    )
    monkeypatch.setattr(
        provisioning, "validate_wazuh", lambda *args: events.append("validate")
    )
    monkeypatch.setattr(
        provisioning, "start_wazuh", lambda *args: events.append("start")
    )
    monkeypatch.setattr(
        provisioning, "wait_for_logtest", lambda *args: events.append("ready")
    )
    monkeypatch.setattr(provisioning, "load_state", lambda *args: {"schema_version": 1})
    monkeypatch.setattr(
        provisioning, "save_state", lambda *args: events.append("state")
    )

    assert (
        provisioning.initialize(tmp_path / "workspace", tmp_path / "home", user)
        == "4.14.8"
    )

    assert (
        events.index("dependencies") < events.index("service") < events.index("install")
    )
    assert events.index("validate") < events.index("start") < events.index("ready")
    assert events[-1] == "state"


def test_group_membership_failure_does_not_enter_host_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    user = InvokingUser("tester", os.getuid(), os.getgid(), tmp_path)  # type: ignore

    class FakePackageManager:
        def __init__(self, runner: object) -> None:
            del runner

        def ensure_system_dependencies(self) -> None:
            pass

        def install_wazuh(self, requested_version: str | None) -> str:
            del requested_version
            return "4.14.8"

    monkeypatch.setattr(provisioning, "ensure_linux", lambda: None)
    monkeypatch.setattr(provisioning, "CommandRunner", lambda user: object())
    monkeypatch.setattr(provisioning, "PackageManager", FakePackageManager)
    monkeypatch.setattr(provisioning, "_service_manager", lambda: "systemd")
    monkeypatch.setattr(provisioning, "prepare_workspace", lambda *args: None)
    monkeypatch.setattr(provisioning, "ensure_workspace_venv", lambda *args: None)
    monkeypatch.setattr(provisioning, "preflight_bind_mounts", lambda *args: None)
    monkeypatch.setattr(provisioning, "is_wazuh_active", lambda runner: True)
    monkeypatch.setattr(provisioning, "is_wazuh_enabled", lambda runner: True)
    monkeypatch.setattr(
        provisioning,
        "_capture_snapshot",
        lambda *args: _snapshot(active=True, enabled=True),
    )
    monkeypatch.setattr(provisioning, "_render_ossec_config", lambda value: value)
    monkeypatch.setattr(
        provisioning, "_render_windows_rule_testing", lambda value: value
    )
    monkeypatch.setattr(
        provisioning,
        "ensure_group_membership",
        lambda *args: (_ for _ in ()).throw(ConfigurationError("group failure")),
    )
    monkeypatch.setattr(provisioning, "stop_wazuh", lambda *args: events.append("stop"))
    monkeypatch.setattr(
        provisioning,
        "_rollback_provisioning",
        lambda *args: events.append("rollback"),
    )
    monkeypatch.setattr(provisioning, "load_state", lambda *args: {"schema_version": 1})

    with pytest.raises(ConfigurationError, match="group failure"):
        provisioning.initialize(tmp_path / "workspace", tmp_path / "home", user)

    assert events == []


def test_failed_host_configuration_uses_small_rollback_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    user = InvokingUser("tester", os.getuid(), os.getgid(), tmp_path)  # type: ignore

    class FakePackageManager:
        def __init__(self, runner: object) -> None:
            del runner

        def ensure_system_dependencies(self) -> None:
            pass

        def install_wazuh(self, requested_version: str | None) -> str:
            del requested_version
            return "4.14.8"

    monkeypatch.setattr(provisioning, "ensure_linux", lambda: None)
    monkeypatch.setattr(provisioning, "CommandRunner", lambda user: object())
    monkeypatch.setattr(provisioning, "PackageManager", FakePackageManager)
    monkeypatch.setattr(provisioning, "_service_manager", lambda: "systemd")
    monkeypatch.setattr(provisioning, "prepare_workspace", lambda *args: None)
    monkeypatch.setattr(provisioning, "ensure_workspace_venv", lambda *args: None)
    monkeypatch.setattr(provisioning, "preflight_bind_mounts", lambda *args: None)
    monkeypatch.setattr(provisioning, "is_wazuh_active", lambda runner: False)
    monkeypatch.setattr(provisioning, "is_wazuh_enabled", lambda runner: False)
    monkeypatch.setattr(provisioning, "_capture_snapshot", lambda *args: _snapshot())
    monkeypatch.setattr(provisioning, "_render_ossec_config", lambda value: value)
    monkeypatch.setattr(
        provisioning, "_render_windows_rule_testing", lambda value: value
    )
    monkeypatch.setattr(provisioning, "ensure_group_membership", lambda *args: None)
    monkeypatch.setattr(provisioning, "stop_wazuh", lambda *args: False)
    monkeypatch.setattr(provisioning, "configure_ossec", lambda *args: None)
    monkeypatch.setattr(
        provisioning, "configure_windows_rule_testing", lambda *args: None
    )
    monkeypatch.setattr(provisioning, "configure_bind_mounts", lambda *args: None)
    monkeypatch.setattr(provisioning, "configure_permissions", lambda *args: None)
    monkeypatch.setattr(provisioning, "configure_default_acls", lambda *args: None)

    def fail_validation(*args: object) -> None:
        raise ConfigurationError("invalid configuration")

    monkeypatch.setattr(provisioning, "validate_wazuh", fail_validation)
    monkeypatch.setattr(
        provisioning,
        "_rollback_provisioning",
        lambda *args: events.append("rollback"),
    )

    with pytest.raises(ConfigurationError, match="invalid configuration"):
        provisioning.initialize(tmp_path / "workspace", tmp_path / "home", user)

    assert events == ["rollback"]


def test_rollback_restores_only_system_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = RecordingRunner()
    workspace = tmp_path / "workspace"
    (workspace / "rules").mkdir(parents=True)
    (workspace / "decoders").mkdir(parents=True)
    restored: list[Path] = []

    monkeypatch.setattr(provisioning, "_same_bind_mount", lambda *args: True)
    monkeypatch.setattr(
        provisioning,
        "_restore_text_if_changed",
        lambda runner, path, original: restored.append(path),
    )

    provisioning._rollback_provisioning(
        runner,  # type: ignore
        workspace,
        _snapshot(active=False),
    )

    assert ["umount", "/var/ossec/etc/decoders"] in runner.commands
    assert ["umount", "/var/ossec/etc/rules"] in runner.commands
    assert restored == [
        Path("/etc/fstab"),
        provisioning.OSSEC_CONF,
        provisioning.WINDOWS_RULES,
    ]


def test_rollback_restores_active_but_disabled_systemd_service(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = RecordingRunner()
    workspace = tmp_path / "workspace"
    (workspace / "rules").mkdir(parents=True)
    (workspace / "decoders").mkdir(parents=True)

    monkeypatch.setattr(provisioning, "_same_bind_mount", lambda *args: False)
    monkeypatch.setattr(provisioning, "_restore_text_if_changed", lambda *args: None)
    monkeypatch.setattr(provisioning, "_service_manager", lambda: "systemd")
    monkeypatch.setattr(provisioning, "wait_for_logtest", lambda *args: None)

    provisioning._rollback_provisioning(
        runner,  # type: ignore
        workspace,
        _snapshot(active=True, enabled=False),
    )

    assert ["systemctl", "disable", "wazuh-manager"] in runner.commands
    assert ["systemctl", "start", "wazuh-manager"] in runner.commands


def test_start_wazuh_uses_start_after_deliberate_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = RecordingRunner()
    monkeypatch.setattr(provisioning, "_service_manager", lambda: "systemd")

    provisioning.start_wazuh(runner)  # type: ignore

    assert ["systemctl", "start", "wazuh-manager"] in runner.commands
    assert ["systemctl", "restart", "wazuh-manager"] not in runner.commands


def test_start_wazuh_uses_sysv_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = RecordingRunner()
    monkeypatch.setattr(provisioning, "_service_manager", lambda: "sysv")

    provisioning.start_wazuh(runner)  # type: ignore

    assert ["service", "wazuh-manager", "start"] in runner.commands
    assert ["service", "wazuh-manager", "restart"] not in runner.commands


@pytest.mark.parametrize(
    ("manager", "expected"),
    [
        ("systemd", "systemctl status wazuh-manager"),
        ("sysv", "service wazuh-manager status"),
    ],
)
def test_logtest_timeout_reports_service_manager_troubleshooting(
    monkeypatch: pytest.MonkeyPatch,
    manager: str,
    expected: str,
) -> None:
    monkeypatch.setattr(provisioning, "_service_manager", lambda: manager)

    with pytest.raises(ConfigurationError) as exc_info:
        provisioning.wait_for_logtest(RecordingRunner(), timeout=0)  # type: ignore

    message = str(exc_info.value)
    assert expected in message
    assert "/var/ossec/queue/sockets" in message
    if manager == "systemd":
        assert "journalctl -u wazuh-manager" in message


def test_initialize_rolls_back_when_state_persistence_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    user = InvokingUser("tester", os.getuid(), os.getgid(), tmp_path)  # type: ignore

    class FakePackageManager:
        def __init__(self, runner: object) -> None:
            del runner

        def ensure_system_dependencies(self) -> None:
            pass

        def install_wazuh(self, requested_version: str | None) -> str:
            del requested_version
            return "4.14.8"

    monkeypatch.setattr(provisioning, "ensure_linux", lambda: None)
    monkeypatch.setattr(provisioning, "CommandRunner", lambda user: object())
    monkeypatch.setattr(provisioning, "PackageManager", FakePackageManager)
    monkeypatch.setattr(provisioning, "load_state", lambda *args: {"schema_version": 1})
    monkeypatch.setattr(provisioning, "_service_manager", lambda: "systemd")
    monkeypatch.setattr(provisioning, "prepare_workspace", lambda *args: None)
    monkeypatch.setattr(provisioning, "ensure_workspace_venv", lambda *args: None)
    monkeypatch.setattr(provisioning, "preflight_bind_mounts", lambda *args: None)
    monkeypatch.setattr(provisioning, "is_wazuh_active", lambda runner: False)
    monkeypatch.setattr(provisioning, "is_wazuh_enabled", lambda runner: False)
    monkeypatch.setattr(provisioning, "_capture_snapshot", lambda *args: _snapshot())
    monkeypatch.setattr(provisioning, "_render_ossec_config", lambda value: value)
    monkeypatch.setattr(
        provisioning, "_render_windows_rule_testing", lambda value: value
    )
    monkeypatch.setattr(provisioning, "ensure_group_membership", lambda *args: None)
    monkeypatch.setattr(provisioning, "stop_wazuh", lambda *args: False)
    monkeypatch.setattr(provisioning, "configure_ossec", lambda *args: None)
    monkeypatch.setattr(
        provisioning, "configure_windows_rule_testing", lambda *args: None
    )
    monkeypatch.setattr(provisioning, "configure_bind_mounts", lambda *args: None)
    monkeypatch.setattr(provisioning, "configure_permissions", lambda *args: None)
    monkeypatch.setattr(provisioning, "configure_default_acls", lambda *args: None)
    monkeypatch.setattr(provisioning, "validate_wazuh", lambda *args: None)
    monkeypatch.setattr(provisioning, "start_wazuh", lambda *args, **kwargs: None)
    monkeypatch.setattr(provisioning, "wait_for_logtest", lambda *args: None)
    monkeypatch.setattr(
        provisioning,
        "save_state",
        lambda *args: (_ for _ in ()).throw(OSError("state write failed")),
    )
    monkeypatch.setattr(
        provisioning,
        "_rollback_provisioning",
        lambda *args: events.append("rollback"),
    )

    with pytest.raises(OSError, match="state write failed"):
        provisioning.initialize(tmp_path / "workspace", tmp_path / "home", user)

    assert events == ["rollback"]


def test_initialize_rejects_malformed_state_before_host_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    user = InvokingUser("tester", os.getuid(), os.getgid(), tmp_path)  # type: ignore

    class FakePackageManager:
        def __init__(self, runner: object) -> None:
            del runner

        def ensure_system_dependencies(self) -> None:
            events.append("dependencies")

    monkeypatch.setattr(provisioning, "ensure_linux", lambda: None)
    monkeypatch.setattr(provisioning, "CommandRunner", lambda user: object())
    monkeypatch.setattr(provisioning, "PackageManager", FakePackageManager)
    monkeypatch.setattr(
        provisioning,
        "load_state",
        lambda *args: (_ for _ in ()).throw(ValueError("unsupported state file")),
    )

    with pytest.raises(ValueError, match="unsupported state file"):
        provisioning.initialize(tmp_path / "workspace", tmp_path / "home", user)

    assert events == []
