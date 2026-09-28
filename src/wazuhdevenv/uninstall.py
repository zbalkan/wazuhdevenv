"""Teardown for a wazuhdevenv-managed environment."""

from __future__ import annotations

import logging
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigurationError, WazuhDevenvError
from .paths import InvokingUser
from .provisioning import (
    APT_REPOSITORY,
    OSSEC_CONF,
    RPM_REPOSITORY,
    WAZUH_HOME,
    WINDOWS_RULES,
    PackageManager,
    _privileged_exists,
    _read_optional_privileged,
    _render_ossec_config,
    _render_windows_rule_testing,
    _rewrite_preserving_metadata,
    _same_bind_mount,
    _service_manager,
    _write_privileged,
    is_wazuh_active,
    is_wazuh_enabled,
    start_wazuh,
    stop_wazuh,
    wait_for_logtest,
)
from .runner import CommandRunner
from .state import load_state, managed_lock_path

LOG = logging.getLogger(__name__)

OSSEC_BACKUP = OSSEC_CONF.with_name("ossec.conf.wazuhdevenv.bak")
WINDOWS_RULES_BACKUP = WINDOWS_RULES.with_name(WINDOWS_RULES.name + ".wazuhdevenv.bak")
APT_REPOSITORY_PATH = Path("/etc/apt/sources.list.d/wazuh.list")
RPM_REPOSITORY_PATH = Path("/etc/yum.repos.d/wazuh.repo")
APT_KEYRING_PATH = Path("/usr/share/keyrings/wazuh.gpg")


@dataclass(frozen=True)
class UninstallResult:
    workspace: Path
    removed: tuple[str, ...]
    restored: tuple[str, ...]
    preserved: tuple[str, ...]
    remnants: tuple[str, ...]


def format_uninstall_report(result: UninstallResult, managed_home: Path) -> str:
    sections = (
        ("Removed", (*result.removed, f"managed state: {managed_home}")),
        ("Restored", result.restored),
        ("Preserved", result.preserved),
        (
            "Remnants",
            (
                *result.remnants,
                "persistent operation lock retained for serialization: ",
                f"{managed_lock_path(managed_home)}",
            ),
        ),
    )
    lines = ["Uninstall complete."]
    for title, entries in sections:
        lines.extend(("", f"{title}:"))
        if entries:
            lines.extend(f"  - {entry}" for entry in entries)
        else:
            lines.append("  - none")
    return "\n".join(lines)


def _required_state(
    home: Path,
) -> tuple[dict[str, object], Path, dict[str, object], bool]:
    state = load_state(home)
    workspace = state.get("workspace")
    if not isinstance(workspace, str):
        raise WazuhDevenvError("workspace is not initialized; nothing to uninstall")

    provenance = state.get("provisioning")
    if isinstance(provenance, dict):
        return state, Path(workspace), provenance, False

    return state, Path(workspace), {}, True


def _targets(values: object, field: str) -> set[Path]:
    if not isinstance(values, list) or not all(
        isinstance(value, str) for value in values
    ):
        raise ConfigurationError(f"invalid {field} provenance in state.json")
    return {Path(value) for value in values}


def _strings(values: object, field: str) -> list[str]:
    if not isinstance(values, list) or not all(
        isinstance(value, str) for value in values
    ):
        raise ConfigurationError(f"invalid {field} provenance in state.json")
    return list(values)


def _required_bool(provenance: dict[str, object], field: str) -> bool:
    value = provenance.get(field)
    if not isinstance(value, bool):
        raise ConfigurationError(f"invalid {field} provenance in state.json")
    return value


def _optional_bool(provenance: dict[str, object], field: str) -> bool | None:
    value = provenance.get(field)
    if value is not None and not isinstance(value, bool):
        raise ConfigurationError(f"invalid {field} provenance in state.json")
    return value


def _required_text(provenance: dict[str, object], field: str) -> str:
    value = provenance.get(field)
    if not isinstance(value, str):
        raise ConfigurationError(f"invalid {field} provenance in state.json")
    return value


def _preflight_wazuh_version(
    package_manager: PackageManager,
    state: dict[str, object],
) -> None:
    recorded = state.get("wazuh_version")
    if not isinstance(recorded, str):
        raise ConfigurationError("missing recorded Wazuh version in state.json")

    actual = package_manager.installed_version()
    if actual is not None and actual != recorded:
        raise ConfigurationError(
            "Wazuh version changed since initialization: "
            f"recorded {recorded}, installed {actual}"
        )


def _preflight_mounts(
    runner: CommandRunner,
    workspace: Path,
    preexisting: set[Path],
) -> None:
    for name in ("rules", "decoders"):
        target = WAZUH_HOME / "etc" / name
        if target in preexisting:
            continue
        if (
            runner.run(
                ["mountpoint", "-q", str(target)],
                privileged=True,
                check=False,
            ).returncode
            != 0
        ):
            continue
        if not _same_bind_mount(runner, (workspace / name).resolve(), target):
            raise ConfigurationError(
                f"{target} is mounted from unexpected content; refusing to unmount it"
            )


def _remove_mounts(
    runner: CommandRunner,
    workspace: Path,
    preexisting: set[Path],
) -> list[str]:
    removed: list[str] = []
    for name in ("rules", "decoders"):
        target = WAZUH_HOME / "etc" / name
        if target in preexisting:
            continue
        if _same_bind_mount(runner, (workspace / name).resolve(), target):
            runner.run(["umount", str(target)], privileged=True)
            if (
                runner.run(
                    ["mountpoint", "-q", str(target)],
                    privileged=True,
                    check=False,
                ).returncode
                == 0
            ):
                raise ConfigurationError(
                    f"failed to unmount {target}; refusing to continue uninstall"
                )
            removed.append(f"bind mount: {target}")
    return removed


def _fstab_cleanup_plan(
    runner: CommandRunner,
    workspace: Path,
    preexisting: set[Path],
) -> tuple[Path, str | None, str, list[str]]:
    path = Path("/etc/fstab")
    text = _read_optional_privileged(runner, path)
    if text is None:
        return path, None, "", []

    expected = {
        WAZUH_HOME / "etc" / name: (
            f"{(workspace / name).resolve()} {WAZUH_HOME / 'etc' / name} none bind 0 0"
        )
        for name in ("rules", "decoders")
        if WAZUH_HOME / "etc" / name not in preexisting
    }

    output: list[str] = []
    removed: list[str] = []
    for raw in text.splitlines(keepends=True):
        exact_line = raw.rstrip("\r\n")
        parsed_line = exact_line.strip()
        fields = parsed_line.split()
        target = (
            Path(fields[1])
            if len(fields) >= 2 and not parsed_line.startswith("#")
            else None
        )
        if target not in expected:
            output.append(raw)
            continue
        if exact_line != expected[target]:
            raise ConfigurationError(
                f"fstab entry for {target} changed since initialization"
            )
        removed.append(f"/etc/fstab entry for {target}")

    return path, text, "".join(output), removed


def _preflight_fstab_entries(
    runner: CommandRunner,
    workspace: Path,
    preexisting: set[Path],
) -> None:
    _fstab_cleanup_plan(runner, workspace, preexisting)


def _remove_fstab_entries(
    runner: CommandRunner,
    workspace: Path,
    preexisting: set[Path],
) -> list[str]:
    path, text, updated, removed = _fstab_cleanup_plan(
        runner,
        workspace,
        preexisting,
    )
    if text is not None and removed:
        _rewrite_preserving_metadata(runner, path, updated)
        _, _, _, remaining = _fstab_cleanup_plan(
            runner,
            workspace,
            preexisting,
        )
        if remaining:
            raise ConfigurationError(
                "failed to remove managed /etc/fstab entries: " + ", ".join(remaining)
            )
        if _service_manager() == "systemd":
            runner.run(
                ["systemctl", "daemon-reload"],
                privileged=True,
            )
    return removed


def _preflight_retained_mounts(
    runner: CommandRunner,
    preexisting_mounts: set[Path],
    *,
    removing_wazuh: bool,
) -> None:
    if not removing_wazuh:
        return

    active = [
        target
        for target in sorted(preexisting_mounts)
        if runner.run(
            ["mountpoint", "-q", str(target)],
            privileged=True,
            check=False,
        ).returncode
        == 0
    ]
    if active:
        raise ConfigurationError(
            "cannot remove tool-installed Wazuh while preserving pre-existing "
            "bind mounts; unmount them before retrying uninstall: "
            + ", ".join(str(target) for target in active)
        )


def _detach_workspace(
    runner: CommandRunner,
    workspace: Path,
    preexisting_mounts: set[Path],
    preexisting_fstab: set[Path],
    *,
    removing_wazuh: bool,
) -> list[str]:
    _preflight_retained_mounts(
        runner,
        preexisting_mounts,
        removing_wazuh=removing_wazuh,
    )
    _preflight_fstab_entries(runner, workspace, preexisting_fstab)
    stop_wazuh(runner)
    removed = _remove_mounts(runner, workspace, preexisting_mounts)
    removed.extend(_remove_fstab_entries(runner, workspace, preexisting_fstab))
    return removed


def _nested_mounts(
    runner: CommandRunner,
    target: Path,
) -> list[Path]:
    output = runner.capture(
        ["findmnt", "-rn", "-o", "TARGET"],
        privileged=True,
    )
    prefix = f"{target}/"
    return [
        Path(line)
        for raw in output.splitlines()
        if (line := raw.strip()).startswith(prefix)
    ]


def _preflight_package_directories(
    runner: CommandRunner,
) -> dict[Path, bool]:
    states: dict[Path, bool] = {}
    for name in ("rules", "decoders"):
        target = WAZUH_HOME / "etc" / name
        if (
            runner.run(
                ["mountpoint", "-q", str(target)],
                privileged=True,
                check=False,
            ).returncode
            == 0
        ):
            raise ConfigurationError(
                f"{target} is still mounted; refusing to prepare package removal"
            )
        if (
            runner.run(
                ["test", "-L", str(target)],
                privileged=True,
                check=False,
            ).returncode
            == 0
        ):
            raise ConfigurationError(
                f"{target} is a symlink; refusing to prepare package removal"
            )

        nested_mounts = _nested_mounts(runner, target)
        if nested_mounts:
            raise ConfigurationError(
                f"{target} contains mounted content; refusing recursive cleanup: "
                + ", ".join(str(path) for path in nested_mounts)
            )

        exists = (
            runner.run(
                ["test", "-e", str(target)],
                privileged=True,
                check=False,
            ).returncode
            == 0
        )
        if exists and (
            runner.run(
                ["test", "-d", str(target)],
                privileged=True,
                check=False,
            ).returncode
            != 0
        ):
            raise ConfigurationError(
                f"{target} is not a directory; refusing to prepare package removal"
            )
        states[target] = exists
    return states


def _prepare_package_directories(runner: CommandRunner) -> None:
    states = _preflight_package_directories(runner)

    for target, exists in states.items():
        if exists:
            runner.run(
                [
                    "find",
                    str(target),
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
                privileged=True,
            )
        else:
            runner.run(["mkdir", "-p", str(target)], privileged=True)

        runner.run(["chown", "root:wazuh", str(target)], privileged=True)
        runner.run(["chmod", "0770", str(target)], privileged=True)


def _preflight_restore(
    runner: CommandRunner,
    target: Path,
    original: str,
    render: Callable[[str], str],
) -> None:
    current = runner.capture(["cat", str(target)], privileged=True)
    expected = render(original)
    if current not in {expected, original}:
        raise ConfigurationError(
            f"{target} changed after initialization; refusing to overwrite it"
        )


def _legacy_original(
    runner: CommandRunner,
    backup: Path,
) -> str:
    if not _privileged_exists(runner, backup):
        raise ConfigurationError(
            f"required legacy initialization backup is missing: {backup}"
        )
    return runner.capture(["cat", str(backup)], privileged=True)


def _restore_text(
    runner: CommandRunner,
    target: Path,
    original: str,
) -> None:
    _rewrite_preserving_metadata(runner, target, original)


def _cleanup_workspace_access(
    runner: CommandRunner,
    workspace: Path,
    user: InvokingUser,
) -> list[str]:
    changed: list[str] = []
    if runner.trusted_which("setfacl"):
        for name in ("rules", "decoders"):
            path = workspace / name
            if path.is_dir() and not path.is_symlink():
                result = runner.run_as_user(
                    [
                        "setfacl",
                        "-d",
                        "-x",
                        "u:wazuh,g:wazuh",
                        str(path),
                    ],
                    check=False,
                )
                if result.returncode == 0:
                    changed.append(f"default Wazuh ACL entries: {path}")

    if runner.run(["getent", "group", "wazuh"], check=False).returncode != 0:
        return changed

    for name in ("rules", "decoders"):
        path = workspace / name
        if path.is_dir() and not path.is_symlink():
            runner.run(
                [
                    "find",
                    str(path),
                    "-group",
                    "wazuh",
                    "-exec",
                    "chgrp",
                    str(user.gid),
                    "{}",
                    "+",
                ],
                privileged=True,
            )
    changed.append(
        "workspace files using the wazuh group were returned to the invoking user's primary group"
    )
    return changed


def _remove_group_membership(
    runner: CommandRunner,
    user: InvokingUser,
    provenance: dict[str, object],
) -> bool:
    if provenance.get("group_membership_added") is not True:
        return False
    if runner.run(["getent", "group", "wazuh"], check=False).returncode != 0:
        return False
    groups = runner.capture(["id", "-nG", user.name], privileged=True).split()
    if "wazuh" not in groups:
        return False
    runner.run(["gpasswd", "-d", user.name, "wazuh"], privileged=True)
    return True


def _remove_wazuh(
    runner: CommandRunner,
    package_manager: PackageManager,
) -> bool:
    package_present = package_manager.installed_version() is not None
    if package_present:
        _prepare_package_directories(runner)
        if package_manager.family == "apt":
            runner.run(
                ["apt-get", "remove", "--purge", "wazuh-manager", "-y"],
                privileged=True,
            )
        else:
            runner.run(
                [package_manager.command, "-y", "remove", "wazuh-manager"],
                privileged=True,
            )

    runner.run(["rm", "-rf", str(WAZUH_HOME)], privileged=True)
    return package_present


def _restore_repository(
    runner: CommandRunner,
    package_manager: PackageManager,
    before: object,
) -> tuple[str | None, str | None, bool]:
    path = (
        APT_REPOSITORY_PATH if package_manager.family == "apt" else RPM_REPOSITORY_PATH
    )
    current = _read_optional_privileged(runner, path)
    managed = (
        {APT_REPOSITORY, f"#{APT_REPOSITORY}"}
        if package_manager.family == "apt"
        else {
            RPM_REPOSITORY.format(enabled=0),
            RPM_REPOSITORY.format(enabled=1),
        }
    )

    if current is not None and current not in managed:
        return (
            None,
            f"modified Wazuh repository configuration left unchanged: {path}",
            False,
        )

    if before is None:
        if current is not None:
            runner.run(["rm", "-f", str(path)], privileged=True)
            description = f"pre-initialization repository absence: {path}"
        else:
            description = None
    elif isinstance(before, str):
        if current is None:
            _write_privileged(runner, path, before)
        elif current != before:
            _rewrite_preserving_metadata(runner, path, before)
        description = f"pre-initialization repository configuration: {path}"
    else:
        raise ConfigurationError("invalid repository provenance in state.json")

    if package_manager.family == "apt":
        runner.run(["apt-get", "update"], privileged=True)

    return description, None, True


def _restore_service(
    runner: CommandRunner,
    *,
    was_active: bool,
    was_enabled: bool | None,
) -> str:
    if was_active:
        start_wazuh(runner, enable=was_enabled)
        wait_for_logtest(runner)
        return "pre-initialization Wazuh Manager service state (running)"

    stop_wazuh(runner)
    if was_enabled is not None:
        action = "enable" if was_enabled else "disable"
        runner.run(["systemctl", action, "wazuh-manager"], privileged=True)
    return "pre-initialization Wazuh Manager service state (stopped)"


def _account_remnants(runner: CommandRunner) -> list[str]:
    remnants: list[str] = []
    if runner.run(["getent", "passwd", "wazuh"], check=False).returncode == 0:
        remnants.append(
            "Wazuh system user remains after package removal; package-manager "
            "account cleanup is not overridden"
        )
    if runner.run(["getent", "group", "wazuh"], check=False).returncode == 0:
        remnants.append(
            "Wazuh system group remains after package removal; package-manager "
            "account cleanup is not overridden"
        )
    return remnants


def uninstall_environment(home: Path, user: InvokingUser) -> UninstallResult:
    state, workspace, provenance, legacy_state = _required_state(home)
    runner = CommandRunner(user)
    package_manager = PackageManager(runner)
    _preflight_wazuh_version(package_manager, state)

    removed: list[str] = []
    restored: list[str] = []
    preserved: list[str] = [
        f"user workspace content: {workspace / 'rules'}",
        f"user workspace content: {workspace / 'decoders'}",
        f"user workspace content: {workspace / 'tests'}",
    ]
    remnants: list[str] = [
        "the wazuhdevenv Python/pipx installation itself is not self-removed; ",
        "remove it separately with the installer used to install the CLI",
        "workspace rule/decoder modes set during initialization are not ",
        "reconstructed; directories/files may retain 0770/0660 modes, and ",
        "pre-initialization non-primary group ownership is not tracked",
    ]

    if legacy_state:
        LOG.warning(
            "State predates uninstall provenance tracking; uncertain ownership "
            "will be preserved and reported explicitly."
        )
        installed_by_tool = False
        remove_venv = False
        preexisting_mounts: set[Path] = set()
        preexisting_fstab: set[Path] = set()
        repository_before: str | None = None
        apt_keyring_preexisting: bool | None = None
        system_dependencies: list[str] = []
        ossec_original = _legacy_original(runner, OSSEC_BACKUP)
        windows_original = _legacy_original(runner, WINDOWS_RULES_BACKUP)
        ossec_backup_preexisting = True
        windows_backup_preexisting = True
        remnants.append(
            "legacy state has no ownership provenance; Wazuh Manager, group "
            "membership, workspace .venv, and initialization backup files are preserved"
        )
    else:
        installed_by_tool = _required_bool(
            provenance,
            "wazuh_installed_by_tool",
        )
        remove_venv = _required_bool(
            provenance,
            "workspace_venv_created_by_tool",
        )
        _required_bool(provenance, "group_membership_added")
        preexisting_mounts = _targets(
            provenance.get("preexisting_mounts"),
            "preexisting_mounts",
        )
        preexisting_fstab = _targets(
            provenance.get("preexisting_fstab_entries"),
            "preexisting_fstab_entries",
        )
        system_dependencies = _strings(
            provenance.get("system_dependencies_installed"),
            "system_dependencies_installed",
        )
        repository_value = provenance.get("repository_before")
        if repository_value is not None and not isinstance(repository_value, str):
            raise ConfigurationError(
                "invalid repository_before provenance in state.json"
            )
        repository_before = repository_value
        apt_keyring_preexisting = _optional_bool(
            provenance,
            "apt_keyring_preexisting",
        )
        ossec_original = _required_text(provenance, "ossec_conf_before")
        windows_original = _required_text(provenance, "windows_rules_before")
        ossec_backup_preexisting = _required_bool(
            provenance,
            "ossec_backup_preexisting",
        )
        windows_backup_preexisting = _required_bool(
            provenance,
            "windows_backup_preexisting",
        )

        family = provenance.get("package_manager_family")
        if family not in {"apt", "rpm"}:
            raise ConfigurationError(
                "invalid package_manager_family provenance in state.json"
            )
        if family != package_manager.family:
            raise ConfigurationError(
                "package manager differs from initialization; refusing unsafe uninstall"
            )

    if system_dependencies:
        remnants.append(
            "system prerequisite packages installed by wazuhdevenv are intentionally "
            "retained: " + ", ".join(system_dependencies)
        )

    if installed_by_tool or system_dependencies:
        remnants.append(
            "package-manager cache/metadata changes made by apt, dnf, or yum "
            "are not rolled back"
        )

    _preflight_mounts(runner, workspace, preexisting_mounts)

    if not installed_by_tool:
        _preflight_restore(
            runner,
            OSSEC_CONF,
            ossec_original,
            _render_ossec_config,
        )
        _preflight_restore(
            runner,
            WINDOWS_RULES,
            windows_original,
            _render_windows_rule_testing,
        )

    venv = workspace / ".venv"
    if remove_venv and venv.is_symlink():
        raise ConfigurationError(
            f"workspace virtual environment became a symlink: {venv}"
        )

    if legacy_state:
        service_was_active = is_wazuh_active(runner)
        service_was_enabled = is_wazuh_enabled(runner)
    else:
        active_value = provenance.get("service_was_active")
        enabled_value = provenance.get("service_was_enabled")
        if not isinstance(active_value, bool):
            raise ConfigurationError(
                "invalid pre-initialization service state in state.json"
            )
        if enabled_value is not None and not isinstance(enabled_value, bool):
            raise ConfigurationError(
                "invalid pre-initialization service enablement in state.json"
            )
        service_was_active = active_value
        service_was_enabled = enabled_value

    removed.extend(
        _detach_workspace(
            runner,
            workspace,
            preexisting_mounts,
            preexisting_fstab,
            removing_wazuh=installed_by_tool,
        )
    )
    workspace_access_removed = _cleanup_workspace_access(runner, workspace, user)
    removed.extend(workspace_access_removed)
    if any(
        item.startswith("default Wazuh ACL entries:")
        for item in workspace_access_removed
    ):
        remnants.append(
            "only Wazuh-specific default ACL entries are removed; any "
            "pre-existing/default base ACL and mask entries are preserved"
        )

    if _remove_group_membership(runner, user, provenance):
        removed.append(f"{user.name} membership in the wazuh group")
        remnants.append(
            "already-running login sessions may retain the wazuh supplementary "
            "group until the user starts a new login session"
        )

    if installed_by_tool:
        if _remove_wazuh(runner, package_manager):
            removed.append("Wazuh Manager package")
        removed.append(str(WAZUH_HOME))

        repository_restored, repository_remnant, repository_safe = _restore_repository(
            runner,
            package_manager,
            repository_before,
        )
        if repository_restored:
            restored.append(repository_restored)
        if repository_remnant:
            remnants.append(repository_remnant)

        if (
            package_manager.family == "apt"
            and apt_keyring_preexisting is False
            and not repository_safe
        ):
            remnants.append(
                "the Wazuh APT keyring created during initialization is retained "
                "because the repository configuration was modified later"
            )

        if (
            package_manager.family == "apt"
            and apt_keyring_preexisting is False
            and repository_safe
            and _privileged_exists(runner, APT_KEYRING_PATH)
        ):
            runner.run(
                ["rm", "-f", str(APT_KEYRING_PATH)],
                privileged=True,
            )
            removed.append(f"Wazuh APT keyring: {APT_KEYRING_PATH}")

        if package_manager.family == "rpm":
            remnants.append(
                "the Wazuh RPM signing-key database entry is not removed; "
                "RPM key ownership cannot be attributed safely"
            )

        remnants.extend(_account_remnants(runner))
    else:
        _restore_text(runner, OSSEC_CONF, ossec_original)
        _restore_text(runner, WINDOWS_RULES, windows_original)
        restored.extend(
            [
                f"pre-initialization configuration: {OSSEC_CONF}",
                f"pre-initialization rule file: {WINDOWS_RULES}",
                _restore_service(
                    runner,
                    was_active=service_was_active,
                    was_enabled=service_was_enabled,
                ),
            ]
        )
        preserved.append("pre-existing Wazuh Manager package")

        if not ossec_backup_preexisting and _privileged_exists(runner, OSSEC_BACKUP):
            runner.run(["rm", "-f", str(OSSEC_BACKUP)], privileged=True)
            removed.append(f"initialization backup: {OSSEC_BACKUP}")
        elif ossec_backup_preexisting:
            preserved.append(f"pre-existing backup: {OSSEC_BACKUP}")

        if not windows_backup_preexisting and _privileged_exists(
            runner, WINDOWS_RULES_BACKUP
        ):
            runner.run(
                ["rm", "-f", str(WINDOWS_RULES_BACKUP)],
                privileged=True,
            )
            removed.append(f"initialization backup: {WINDOWS_RULES_BACKUP}")
        elif windows_backup_preexisting:
            preserved.append(f"pre-existing backup: {WINDOWS_RULES_BACKUP}")

    if remove_venv and venv.exists():
        shutil.rmtree(venv)
        removed.append(f"workspace virtual environment: {venv}")
    elif venv.exists():
        preserved.append(f"workspace virtual environment: {venv}")

    return UninstallResult(
        workspace=workspace,
        removed=tuple(removed),
        restored=tuple(restored),
        preserved=tuple(preserved),
        remnants=tuple(remnants),
    )
