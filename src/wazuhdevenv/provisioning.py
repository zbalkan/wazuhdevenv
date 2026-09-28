"""One-shot provisioning for a Wazuh development workspace."""

from __future__ import annotations

import logging
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .errors import CommandError, ConfigurationError, UnsupportedPlatformError
from .paths import InvokingUser
from .runner import CommandRunner
from .state import load_state, save_state

LOG = logging.getLogger(__name__)

WAZUH_HOME = Path("/var/ossec")
OSSEC_CONF = WAZUH_HOME / "etc/ossec.conf"
WINDOWS_RULES = WAZUH_HOME / "ruleset/rules/0575-win-base_rules.xml"
LOGTEST_SOCKET = WAZUH_HOME / "queue/sockets/logtest"

APT_REPOSITORY = (
    "deb [signed-by=/usr/share/keyrings/wazuh.gpg] "
    "https://packages.wazuh.com/4.x/apt/ stable main\n"
)
RPM_REPOSITORY = """[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled={enabled}
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
"""

DISPOSABLE_WAZUH_SAMPLES = {
    ("rules", "local_rules.xml"),
    ("decoders", "local_decoder.xml"),
}

WINDOWS_RULE_DEFAULT = """  <rule id="60000" level="0">
    <category>ossec</category>
    <decoded_as>windows_eventchannel</decoded_as>
    <field name="win.system.providerName">\\.+</field>
    <options>no_full_log</options>
    <description>Group of windows rules.</description>
  </rule>"""

WINDOWS_RULE_EXPECTED = """  <rule id="60000" level="0">
    <!-- <category>ossec</category> -->
    <!-- <decoded_as>windows_eventchannel</decoded_as> -->
    <field name="win.system.providerName">\\.+</field>
    <options>no_full_log</options>
    <description>Group of windows rules.</description>
    <decoded_as>json</decoded_as>
  </rule>"""


def ensure_linux() -> None:
    if sys.platform != "linux":
        raise UnsupportedPlatformError(
            "wazuhdevenv supports Linux only; use WSL on Windows"
        )


def _write_privileged(
    runner: CommandRunner,
    target: Path,
    content: str,
    *,
    mode: str = "0644",
    owner: str = "root",
    group: str = "root",
) -> None:
    fd, name = tempfile.mkstemp(prefix=".wazuhdevenv.")
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        runner.run(
            [
                "install",
                "-m",
                mode,
                "-o",
                owner,
                "-g",
                group,
                str(temporary),
                str(target),
            ],
            privileged=True,
        )
    finally:
        temporary.unlink(missing_ok=True)


def _privileged_exists(runner: CommandRunner, path: Path) -> bool:
    return (
        runner.run(["test", "-e", str(path)], privileged=True, check=False).returncode
        == 0
    )


def _rewrite_preserving_metadata(
    runner: CommandRunner, target: Path, content: str
) -> None:
    metadata = (
        runner.capture(["stat", "-Lc", "%a %U %G", str(target)], privileged=True)
        .strip()
        .split()
    )
    if len(metadata) != 3:
        raise ConfigurationError(f"cannot determine metadata for {target}")
    mode, owner, group = metadata
    _write_privileged(runner, target, content, mode=mode, owner=owner, group=group)


def _download(url: str) -> Path:
    fd, name = tempfile.mkstemp(prefix="wazuhdevenv-download.")
    os.close(fd)
    target = Path(name)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "wazuhdevenv"})
        with urllib.request.urlopen(request, timeout=30) as response:
            target.write_bytes(response.read())
        return target
    except Exception:
        target.unlink(missing_ok=True)
        raise


@dataclass(frozen=True)
class ProvisioningSnapshot:
    service_was_active: bool
    service_was_enabled: bool | None
    ossec_conf: str
    windows_rules: str
    fstab: str | None
    preexisting_mounts: frozenset[Path]
    ossec_backup_preexisting: bool = False
    windows_backup_preexisting: bool = False


class PackageManager:
    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner
        self.wazuh_installed_by_tool = False
        self.repository_before: str | None = None
        self.apt_keyring_preexisting: bool | None = None
        if runner.trusted_which("apt-get"):
            self.family = "apt"
            self.command = "apt-get"
        elif runner.trusted_which("dnf"):
            self.family = "rpm"
            self.command = "dnf"
        elif runner.trusted_which("yum"):
            self.family = "rpm"
            self.command = "yum"
        else:
            raise UnsupportedPlatformError(
                "supported package manager not found (APT, DNF, or YUM)"
            )

    def _trusted_query(self, executable: str) -> str:
        resolved = self.runner.trusted_which(executable)
        if not resolved:
            raise UnsupportedPlatformError(
                f"required package query command not found: {executable}"
            )
        return resolved

    def _apt_package_version(self, package: str) -> str | None:
        try:
            raw = self.runner.capture(
                [
                    self._trusted_query("dpkg-query"),
                    "-W",
                    "-f=${Status}\t${Version}\n",
                    package,
                ]
            )
        except CommandError:
            return None

        status, separator, version = raw.rstrip("\n").partition("\t")
        if status != "install ok installed" or not separator:
            return None
        version = version.strip()
        return version or None

    def installed_version(self) -> str | None:
        if self.family == "apt":
            raw = self._apt_package_version("wazuh-manager")
            if raw is None:
                return None
        else:
            try:
                raw = self.runner.capture(
                    [
                        self._trusted_query("rpm"),
                        "-q",
                        "--qf",
                        "%{VERSION}-%{RELEASE}",
                        "wazuh-manager",
                    ]
                )
            except CommandError:
                return None
        return _normalize_wazuh_version(raw)

    def _apt_install(self, packages: list[str]) -> None:
        self.runner.run(["apt-get", "update"], privileged=True)
        self.runner.run(
            [
                "env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "-y",
                "--no-install-recommends",
                *packages,
            ],
            privileged=True,
        )

    def ensure_system_dependencies(self) -> list[str]:
        if self.family == "apt":
            packages = [
                "python3-venv",
                "util-linux",
                "coreutils",
                "findutils",
                "gnupg",
                "apt-transport-https",
            ]
            missing = [
                package
                for package in packages
                if self._apt_package_version(package) is None
            ]
            if missing:
                self._apt_install(missing)
            return missing

        packages = ["python3", "util-linux", "findutils", "gnupg2"]
        missing = [
            package
            for package in packages
            if self.runner.run(
                [self._trusted_query("rpm"), "-q", package],
                check=False,
            ).returncode
            != 0
        ]

        coreutils_commands = (
            "cat",
            "chmod",
            "chown",
            "cp",
            "env",
            "id",
            "install",
            "rm",
            "stat",
            "test",
        )
        if any(
            self.runner.trusted_which(command) is None for command in coreutils_commands
        ):
            missing.append("coreutils")
        missing = list(dict.fromkeys(missing))
        if missing:
            self.runner.run(
                [self.command, "-y", "install", *missing],
                privileged=True,
            )
        return missing

    def _set_apt_repository_enabled(self, enabled: bool) -> None:
        path = Path("/etc/apt/sources.list.d/wazuh.list")
        target = APT_REPOSITORY if enabled else f"#{APT_REPOSITORY}"
        alternate = f"#{APT_REPOSITORY}" if enabled else APT_REPOSITORY
        if not _privileged_exists(self.runner, path):
            if enabled:
                _write_privileged(self.runner, path, target)
            return
        current = self.runner.capture(["cat", str(path)], privileged=True)
        if current == target:
            return
        if current == alternate:
            _rewrite_preserving_metadata(self.runner, path, target)
            return
        raise ConfigurationError(
            f"existing Wazuh APT repository configuration is not managed by "
            f"wazuhdevenv; refusing to overwrite: {path}"
        )

    def _disable_apt_repository(self) -> None:
        self._set_apt_repository_enabled(False)
        self.runner.run(["apt-get", "update"], privileged=True)

    def _set_rpm_repository_enabled(self, enabled: bool) -> None:
        path = Path("/etc/yum.repos.d/wazuh.repo")
        target = RPM_REPOSITORY.format(enabled=1 if enabled else 0)
        alternate = RPM_REPOSITORY.format(enabled=0 if enabled else 1)
        if not _privileged_exists(self.runner, path):
            if enabled:
                _write_privileged(self.runner, path, target)
            return
        current = self.runner.capture(["cat", str(path)], privileged=True)
        if current == target:
            return
        if current == alternate:
            _rewrite_preserving_metadata(self.runner, path, target)
            return
        raise ConfigurationError(
            f"existing Wazuh RPM repository configuration is not managed by "
            f"wazuhdevenv; refusing to overwrite: {path}"
        )

    def _setup_apt_repository(self) -> None:
        self._apt_install(["gnupg", "apt-transport-https"])
        keyring = Path("/usr/share/keyrings/wazuh.gpg")
        key = _download("https://packages.wazuh.com/key/GPG-KEY-WAZUH")
        try:
            self.runner.run(
                [
                    "gpg",
                    "--no-default-keyring",
                    "--keyring",
                    "gnupg-ring:/usr/share/keyrings/wazuh.gpg",
                    "--import",
                    str(key),
                ],
                privileged=True,
            )
            self.runner.run(["chmod", "0644", str(keyring)], privileged=True)
        finally:
            key.unlink(missing_ok=True)

        self._set_apt_repository_enabled(True)

    def _setup_rpm_repository(self) -> None:
        key = _download("https://packages.wazuh.com/key/GPG-KEY-WAZUH")
        try:
            self.runner.run(["rpm", "--import", str(key)], privileged=True)
        finally:
            key.unlink(missing_ok=True)

        self._set_rpm_repository_enabled(True)

    def install_wazuh(self, requested_version: str | None) -> str:
        current = self.installed_version()
        requested_normalized = (
            _normalize_wazuh_version(requested_version) if requested_version else None
        )
        if current:
            if requested_normalized and current != requested_normalized:
                raise ConfigurationError(
                    f"Wazuh {current} is already installed; requested {requested_version}. "
                    "wazuhdevenv does not perform Wazuh upgrades"
                )
            LOG.info("Wazuh Manager already installed: %s", current)
            return current

        if hasattr(self, "wazuh_installed_by_tool"):
            self.wazuh_installed_by_tool = True
            repository_path = (
                Path("/etc/apt/sources.list.d/wazuh.list")
                if self.family == "apt"
                else Path("/etc/yum.repos.d/wazuh.repo")
            )
            self.repository_before = _read_optional_privileged(
                self.runner,
                repository_path,
            )
            if self.family == "apt":
                self.apt_keyring_preexisting = _privileged_exists(
                    self.runner,
                    Path("/usr/share/keyrings/wazuh.gpg"),
                )

        LOG.info("Installing Wazuh Manager")
        if self.family == "apt":
            package = "wazuh-manager"
            if requested_version:
                package += (
                    f"={requested_version}-1"
                    if "-" not in requested_version
                    else f"={requested_version}"
                )
            try:
                self._setup_apt_repository()
                self._apt_install([package])
            except Exception:
                try:
                    self._disable_apt_repository()
                except Exception as cleanup_error:  # noqa: BLE001
                    LOG.error(
                        "Could not disable the Wazuh APT repository after setup or installation failed: %s",
                        cleanup_error,
                    )
                raise
            self._disable_apt_repository()
        else:
            package = "wazuh-manager"
            if requested_version:
                package += (
                    f"-{requested_version}-1"
                    if "-" not in requested_version
                    else f"-{requested_version}"
                )
            try:
                self._setup_rpm_repository()
                self.runner.run(
                    [self.command, "-y", "install", package], privileged=True
                )
            except Exception:
                try:
                    self._set_rpm_repository_enabled(False)
                except Exception as cleanup_error:  # noqa: BLE001
                    LOG.error(
                        "Could not disable the Wazuh RPM repository after setup or installation failed: %s",
                        cleanup_error,
                    )
                raise
            self._set_rpm_repository_enabled(False)

        installed = self.installed_version()
        if not installed:
            raise ConfigurationError(
                "Wazuh package installation completed but version could not be determined"
            )
        return installed


def _normalize_wazuh_version(value: str) -> str:
    match = re.search(r"\d+\.\d+\.\d+", value)
    if not match:
        raise ConfigurationError(f"cannot determine Wazuh version from {value!r}")
    return match.group(0)


def _replace_simple_tag(text: str, tag: str, value: str, allowed: set[str]) -> str:
    pattern = re.compile(rf"(<{re.escape(tag)}>\s*)([^<]*?)(\s*</{re.escape(tag)}>)")
    match = pattern.search(text)
    if not match:
        raise ConfigurationError(f"missing <{tag}> in ossec.conf")
    current = match.group(2).strip()
    if current not in allowed:
        raise ConfigurationError(f"unexpected <{tag}> value: {current!r}")
    return (
        text[: match.start()]
        + match.group(1)
        + value
        + match.group(3)
        + text[match.end() :]
    )


def _replace_block_child(
    text: str,
    block_pattern: str,
    child: str,
    value: str,
    allowed: set[str] | None,
    description: str,
) -> str:
    block_re = re.compile(block_pattern, re.DOTALL)
    block_match = block_re.search(text)
    if not block_match:
        raise ConfigurationError(f"missing {description} block in ossec.conf")
    block = block_match.group(0)
    child_re = re.compile(
        rf"(<{re.escape(child)}>\s*)([^<]*?)(\s*</{re.escape(child)}>)"
    )
    child_match = child_re.search(block)
    if not child_match:
        raise ConfigurationError(f"missing <{child}> in {description} block")
    current = child_match.group(2).strip()
    if allowed is not None and current not in allowed:
        raise ConfigurationError(
            f"unexpected {description} <{child}> value: {current!r}"
        )
    replacement = (
        block[: child_match.start()]
        + child_match.group(1)
        + value
        + child_match.group(3)
        + block[child_match.end() :]
    )
    return text[: block_match.start()] + replacement + text[block_match.end() :]


def _render_ossec_config(original: str) -> str:
    text = original
    text = _replace_simple_tag(text, "logall_json", "yes", {"yes", "no"})
    text = _replace_block_child(
        text,
        r"<logging>.*?</logging>",
        "log_format",
        "plain,json",
        {"plain", "json", "plain,json"},
        "logging",
    )
    text = _replace_block_child(
        text,
        r'<wodle\s+name=["\']syscollector["\'][^>]*>.*?</wodle>',
        "disabled",
        "yes",
        {"yes", "no"},
        "syscollector",
    )
    text = _replace_block_child(
        text,
        r"<rootcheck>.*?</rootcheck>",
        "disabled",
        "yes",
        {"yes", "no"},
        "rootcheck",
    )
    text = _replace_block_child(
        text,
        r"<syscheck>.*?</syscheck>",
        "disabled",
        "yes",
        {"yes", "no"},
        "syscheck",
    )
    text = _replace_block_child(
        text,
        r"<sca>.*?</sca>",
        "enabled",
        "no",
        {"yes", "no"},
        "sca",
    )
    text = _replace_block_child(
        text,
        r"<indexer>.*?</indexer>",
        "enabled",
        "no",
        {"yes", "no"},
        "indexer",
    )
    text = _replace_block_child(
        text,
        r"<vulnerability-detection>.*?</vulnerability-detection>",
        "enabled",
        "no",
        {"yes", "no"},
        "vulnerability-detection",
    )
    text = _replace_block_child(
        text,
        r"<rule_test>.*?</rule_test>",
        "threads",
        "auto",
        None,
        "rule_test",
    )
    text = _replace_block_child(
        text,
        r"<rule_test>.*?</rule_test>",
        "max_sessions",
        "500",
        None,
        "rule_test",
    )
    return _replace_block_child(
        text,
        r"<rule_test>.*?</rule_test>",
        "session_timeout",
        "1m",
        None,
        "rule_test",
    )


def configure_ossec(runner: CommandRunner) -> None:
    original = runner.capture(["cat", str(OSSEC_CONF)], privileged=True)
    text = _render_ossec_config(original)
    if text != original:
        backup = OSSEC_CONF.with_name("ossec.conf.wazuhdevenv.bak")
        if not _privileged_exists(runner, backup):
            runner.run(
                [
                    "cp",
                    "--preserve=mode,ownership,timestamps",
                    str(OSSEC_CONF),
                    str(backup),
                ],
                privileged=True,
            )
        _rewrite_preserving_metadata(runner, OSSEC_CONF, text)


def _render_windows_rule_testing(text: str) -> str:
    if WINDOWS_RULE_EXPECTED in text:
        return text
    if WINDOWS_RULE_DEFAULT not in text:
        raise ConfigurationError(
            "rule 60000 is in an unexpected state; refusing to rewrite it"
        )
    return text.replace(WINDOWS_RULE_DEFAULT, WINDOWS_RULE_EXPECTED, 1)


def configure_windows_rule_testing(runner: CommandRunner) -> None:
    original = runner.capture(["cat", str(WINDOWS_RULES)], privileged=True)
    text = _render_windows_rule_testing(original)
    if text == original:
        return
    backup = WINDOWS_RULES.with_name(WINDOWS_RULES.name + ".wazuhdevenv.bak")
    if not _privileged_exists(runner, backup):
        runner.run(
            [
                "cp",
                "--preserve=mode,ownership,timestamps",
                str(WINDOWS_RULES),
                str(backup),
            ],
            privileged=True,
        )
    _rewrite_preserving_metadata(runner, WINDOWS_RULES, text)


def prepare_workspace(workspace: Path, user: InvokingUser) -> None:
    del user
    workspace.mkdir(parents=True, exist_ok=True)

    for name in ("rules", "decoders", "tests"):
        path = workspace / name
        if path.is_symlink():
            raise ConfigurationError(f"workspace {name} path is a symlink: {path}")
        path.mkdir(exist_ok=True)


def _wazuh_directory_entries(runner: CommandRunner, target: Path) -> list[str]:
    output = runner.capture(
        ["find", str(target), "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\n"],
        privileged=True,
    )
    return [line for line in output.splitlines() if line]


def _require_default_wazuh_content(runner: CommandRunner, target: Path) -> None:
    allowed = {
        name for directory, name in DISPOSABLE_WAZUH_SAMPLES if directory == target.name
    }
    unexpected = [
        name for name in _wazuh_directory_entries(runner, target) if name not in allowed
    ]
    if unexpected:
        listed = ", ".join(sorted(unexpected))
        raise ConfigurationError(
            f"existing custom Wazuh content under {target}: {listed}. "
            "wazuhdevenv expects a fresh/default development installation; "
            "move custom content manually before running init"
        )


def _same_bind_mount(runner: CommandRunner, source: Path, target: Path) -> bool:
    if (
        runner.run(
            ["mountpoint", "-q", str(target)], privileged=True, check=False
        ).returncode
        != 0
    ):
        return False
    source_id = runner.capture(
        ["stat", "-Lc", "%d:%i", str(source)], privileged=True
    ).strip()
    target_id = runner.capture(
        ["stat", "-Lc", "%d:%i", str(target)], privileged=True
    ).strip()
    return source_id == target_id


def _read_optional_privileged(runner: CommandRunner, path: Path) -> str | None:
    if not _privileged_exists(runner, path):
        return None
    return runner.capture(["cat", str(path)], privileged=True)


def _fstab_has_entry(runner: CommandRunner, source: Path, target: Path) -> bool:
    text = _read_optional_privileged(runner, Path("/etc/fstab"))
    if text is None:
        return False
    expected = f"{source} {target} none bind 0 0"
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[1] == str(target):
            if line == expected:
                return True
            raise ConfigurationError(f"conflicting fstab entry for {target}: {line}")
    return False


def _ensure_fstab(runner: CommandRunner, source: Path, target: Path) -> None:
    if _fstab_has_entry(runner, source, target):
        return
    fstab_path = Path("/etc/fstab")
    text = _read_optional_privileged(runner, fstab_path)
    updated = text or ""
    if updated and not updated.endswith("\n"):
        updated += "\n"
    updated += f"{source} {target} none bind 0 0\n"
    if text is None:
        _write_privileged(runner, fstab_path, updated)
    else:
        _rewrite_preserving_metadata(runner, fstab_path, updated)


def preflight_bind_mounts(
    runner: CommandRunner,
    workspace: Path,
) -> None:
    for name in ("rules", "decoders"):
        source = (workspace / name).resolve()
        target = WAZUH_HOME / "etc" / name
        if any(ch.isspace() for ch in str(source)):
            raise ConfigurationError(
                f"workspace path contains whitespace and cannot be persisted safely: {source}"
            )

        mounted = (
            runner.run(
                ["mountpoint", "-q", str(target)],
                privileged=True,
                check=False,
            ).returncode
            == 0
        )
        if mounted:
            if not _same_bind_mount(runner, source, target):
                raise ConfigurationError(
                    f"{target} is already a mount point for different content"
                )
        else:
            _require_default_wazuh_content(runner, target)

        _fstab_has_entry(runner, source, target)


def configure_bind_mounts(
    runner: CommandRunner,
    workspace: Path,
) -> None:
    for name in ("rules", "decoders"):
        source = (workspace / name).resolve()
        target = WAZUH_HOME / "etc" / name
        if any(ch.isspace() for ch in str(source)):
            raise ConfigurationError(
                f"workspace path contains whitespace and cannot be persisted safely: {source}"
            )

        if (
            runner.run(
                ["mountpoint", "-q", str(target)],
                privileged=True,
                check=False,
            ).returncode
            == 0
        ):
            if _same_bind_mount(runner, source, target):
                _ensure_fstab(runner, source, target)
                continue
            raise ConfigurationError(
                f"{target} is already a mount point for different content"
            )

        _require_default_wazuh_content(runner, target)
        runner.run(["mount", "--bind", str(source), str(target)], privileged=True)
        if (
            runner.run(
                ["mountpoint", "-q", str(target)],
                privileged=True,
                check=False,
            ).returncode
            != 0
        ):
            raise ConfigurationError(f"bind mount failed: {source} -> {target}")
        _ensure_fstab(runner, source, target)


def ensure_group_membership(runner: CommandRunner, user: InvokingUser) -> bool:
    groups = runner.capture(["id", "-nG", user.name], privileged=True).split()
    if "wazuh" in groups:
        return False
    runner.run(["usermod", "-a", "-G", "wazuh", user.name], privileged=True)
    groups = runner.capture(["id", "-nG", user.name], privileged=True).split()
    if "wazuh" not in groups:
        raise ConfigurationError(f"failed to add {user.name} to the wazuh group")
    LOG.info(
        "Added %s to the wazuh group. Start a new login session before using "
        "Wazuh tools without sudo.",
        user.name,
    )
    return True


def configure_default_acls(runner: CommandRunner, workspace: Path) -> None:
    if shutil.which("setfacl") is None:
        LOG.info("setfacl not available; skipping optional default ACLs")
        return

    acl = "u:wazuh:rwx,g:wazuh:rwx,o::---"
    for name in ("rules", "decoders"):
        path = workspace / name
        result = runner.run_as_user(
            ["setfacl", "-d", "-m", acl, str(path)],
            check=False,
        )
        if result.returncode != 0:
            LOG.warning(
                "Could not configure optional default ACLs on %s; continuing without them",
                path,
            )


def configure_permissions(
    runner: CommandRunner,
    workspace: Path,
    user: InvokingUser,
) -> None:
    owner = f"{user.name}:wazuh"
    for name in ("rules", "decoders"):
        path = workspace / name
        runner.run(
            ["find", str(path), "-type", "d", "-exec", "chown", owner, "{}", "+"],
            privileged=True,
        )
        runner.run(
            ["find", str(path), "-type", "d", "-exec", "chmod", "0770", "{}", "+"],
            privileged=True,
        )
        runner.run(
            ["find", str(path), "-type", "f", "-exec", "chown", owner, "{}", "+"],
            privileged=True,
        )
        runner.run(
            ["find", str(path), "-type", "f", "-exec", "chmod", "0660", "{}", "+"],
            privileged=True,
        )


def _service_manager() -> str:
    if (
        CommandRunner.trusted_which("systemctl")
        and Path("/run/systemd/system").exists()
    ):
        return "systemd"
    if CommandRunner.trusted_which("service"):
        return "sysv"
    raise UnsupportedPlatformError(
        "supported service manager not found (systemd or service)"
    )


def is_wazuh_active(runner: CommandRunner) -> bool:
    manager = _service_manager()
    if manager == "systemd":
        return (
            runner.run(
                ["systemctl", "is-active", "--quiet", "wazuh-manager"],
                privileged=True,
                check=False,
            ).returncode
            == 0
        )
    return (
        runner.run(
            ["service", "wazuh-manager", "status"],
            privileged=True,
            check=False,
        ).returncode
        == 0
    )


def is_wazuh_enabled(runner: CommandRunner) -> bool | None:
    if _service_manager() != "systemd":
        return None
    return (
        runner.run(
            ["systemctl", "is-enabled", "--quiet", "wazuh-manager"],
            privileged=True,
            check=False,
        ).returncode
        == 0
    )


def stop_wazuh(runner: CommandRunner) -> bool:
    was_active = is_wazuh_active(runner)
    if not was_active:
        return False
    manager = _service_manager()
    if manager == "systemd":
        runner.run(["systemctl", "stop", "wazuh-manager"], privileged=True)
    else:
        runner.run(["service", "wazuh-manager", "stop"], privileged=True)
    return True


def validate_wazuh(runner: CommandRunner) -> None:
    for executable in (
        "/var/ossec/bin/wazuh-syscheckd",
        "/var/ossec/bin/wazuh-logcollector",
        "/var/ossec/bin/wazuh-modulesd",
        "/var/ossec/bin/wazuh-analysisd",
    ):
        runner.run([executable, "-t"], privileged=True)


def start_wazuh(runner: CommandRunner, *, enable: bool | None = True) -> None:
    manager = _service_manager()
    if manager == "systemd":
        runner.run(["systemctl", "daemon-reload"], privileged=True)
        if enable is True:
            runner.run(["systemctl", "enable", "wazuh-manager"], privileged=True)
        elif enable is False:
            runner.run(["systemctl", "disable", "wazuh-manager"], privileged=True)
        runner.run(["systemctl", "start", "wazuh-manager"], privileged=True)
    else:
        runner.run(["service", "wazuh-manager", "start"], privileged=True)


def wait_for_logtest(
    runner: CommandRunner, timeout: int = 120, stable_for: int = 5
) -> None:
    stable = 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready = (
            runner.run(
                ["test", "-S", str(LOGTEST_SOCKET)], privileged=True, check=False
            ).returncode
            == 0
        )
        if ready:
            stable += 1
            if stable >= stable_for:
                return
        else:
            stable = 0
        time.sleep(1)
    if _service_manager() == "systemd":
        diagnostics = (
            "check 'sudo systemctl status wazuh-manager', "
            "'sudo journalctl -u wazuh-manager -n 50 --no-pager', and "
            "'sudo ls -l /var/ossec/queue/sockets'"
        )
    else:
        diagnostics = (
            "check 'sudo service wazuh-manager status' and "
            "'sudo ls -l /var/ossec/queue/sockets'"
        )
    raise ConfigurationError(
        f"timeout waiting for stable logtest socket: {LOGTEST_SOCKET}; {diagnostics}"
    )


def ensure_workspace_venv(runner: CommandRunner, workspace: Path) -> None:
    venv = workspace / ".venv"
    if venv.is_symlink():
        raise ConfigurationError(
            f"refusing to use symlinked virtual environment: {venv}"
        )
    if not (venv / "pyvenv.cfg").is_file():
        if venv.exists() and not venv.is_dir():
            raise ConfigurationError(f"{venv} exists but is not a directory")
        runner.run_as_user([sys.executable, "-m", "venv", str(venv)])

    python = venv / "bin/python"
    if not python.exists():
        raise ConfigurationError(f"virtual environment Python not found: {python}")
    tester_spec = os.environ.get("WAZUHTESTER_SPEC", "wazuhtester>=0.1.0rc1,<0.2")
    runner.run_as_user([str(python), "-m", "pip", "install", "--upgrade", "pip"])
    runner.run_as_user(
        [str(python), "-m", "pip", "install", "pytest>=8,<10", tester_spec]
    )


def _capture_snapshot(
    runner: CommandRunner,
    workspace: Path,
    service_was_active: bool,
    service_was_enabled: bool | None,
) -> ProvisioningSnapshot:
    preexisting_mounts: set[Path] = set()
    for name in ("rules", "decoders"):
        source = (workspace / name).resolve()
        target = WAZUH_HOME / "etc" / name
        if _same_bind_mount(runner, source, target):
            preexisting_mounts.add(target)

    return ProvisioningSnapshot(
        service_was_active=service_was_active,
        service_was_enabled=service_was_enabled,
        ossec_conf=runner.capture(["cat", str(OSSEC_CONF)], privileged=True),
        windows_rules=runner.capture(["cat", str(WINDOWS_RULES)], privileged=True),
        fstab=_read_optional_privileged(runner, Path("/etc/fstab")),
        preexisting_mounts=frozenset(preexisting_mounts),
        ossec_backup_preexisting=_privileged_exists(
            runner,
            OSSEC_CONF.with_name("ossec.conf.wazuhdevenv.bak"),
        ),
        windows_backup_preexisting=_privileged_exists(
            runner,
            WINDOWS_RULES.with_name(WINDOWS_RULES.name + ".wazuhdevenv.bak"),
        ),
    )


def _restore_text_if_changed(
    runner: CommandRunner,
    path: Path,
    original: str,
) -> None:
    current = runner.capture(["cat", str(path)], privileged=True)
    if current != original:
        _rewrite_preserving_metadata(runner, path, original)


def _rollback_provisioning(
    runner: CommandRunner,
    workspace: Path,
    snapshot: ProvisioningSnapshot,
) -> None:
    recovery_errors: list[str] = []

    for name in reversed(("rules", "decoders")):
        source = (workspace / name).resolve()
        target = WAZUH_HOME / "etc" / name
        if target in snapshot.preexisting_mounts:
            continue
        try:
            if _same_bind_mount(runner, source, target):
                runner.run(["umount", str(target)], privileged=True)
        except Exception as exc:  # noqa: BLE001
            recovery_errors.append(f"unmount {target}: {exc}")

    fstab_path = Path("/etc/fstab")
    try:
        if snapshot.fstab is None:
            if _privileged_exists(runner, fstab_path):
                runner.run(["rm", "-f", str(fstab_path)], privileged=True)
        else:
            _restore_text_if_changed(runner, fstab_path, snapshot.fstab)
    except Exception as exc:  # noqa: BLE001
        recovery_errors.append(f"restore {fstab_path}: {exc}")

    for path, original in (
        (OSSEC_CONF, snapshot.ossec_conf),
        (WINDOWS_RULES, snapshot.windows_rules),
    ):
        try:
            _restore_text_if_changed(runner, path, original)
        except Exception as exc:  # noqa: BLE001
            recovery_errors.append(f"restore {path}: {exc}")

    try:
        if snapshot.service_was_active:
            start_wazuh(runner, enable=snapshot.service_was_enabled)
            wait_for_logtest(runner)
        else:
            stop_wazuh(runner)
            if (
                snapshot.service_was_enabled is not None
                and _service_manager() == "systemd"
            ):
                action = "enable" if snapshot.service_was_enabled else "disable"
                runner.run(
                    ["systemctl", action, "wazuh-manager"],
                    privileged=True,
                )
    except Exception as exc:  # noqa: BLE001
        recovery_errors.append(f"restore Wazuh Manager service state: {exc}")

    if recovery_errors:
        LOG.error(
            "Provisioning rollback was incomplete: %s",
            "; ".join(recovery_errors),
        )


def initialize(
    workspace: Path,
    home: Path,
    user: InvokingUser,
    *,
    wazuh_version: str | None = None,
) -> str:
    ensure_linux()
    state = load_state(home)
    if "workspace" in state:
        existing_workspace = state["workspace"]
        raise ConfigurationError(
            "wazuhdevenv is already initialized; 'init' may only be run once. "
            f"Workspace: {existing_workspace}; "
            f"Wazuh home: {state.get('wazuh_home', 'unknown')}; "
            f"Wazuh version: {state.get('wazuh_version', 'unknown')}; "
            f"State: {home / 'state.json'}"
        )

    runner = CommandRunner(user)
    package_manager = PackageManager(runner)

    system_dependencies_installed = package_manager.ensure_system_dependencies() or []
    _service_manager()
    prepare_workspace(workspace, user)

    workspace_venv_created_by_tool = not (workspace / ".venv").exists()
    ensure_workspace_venv(runner, workspace)

    installed = package_manager.install_wazuh(wazuh_version)
    wazuh_installed_by_tool = bool(
        getattr(package_manager, "wazuh_installed_by_tool", False)
    )
    repository_before = getattr(package_manager, "repository_before", None)
    apt_keyring_preexisting = getattr(
        package_manager,
        "apt_keyring_preexisting",
        None,
    )

    preflight_bind_mounts(runner, workspace)
    service_was_active = is_wazuh_active(runner)
    service_was_enabled = is_wazuh_enabled(runner)
    snapshot = _capture_snapshot(
        runner,
        workspace,
        service_was_active,
        service_was_enabled,
    )

    # Refuse unexpected file structure before stopping Wazuh.
    _render_ossec_config(snapshot.ossec_conf)
    _render_windows_rule_testing(snapshot.windows_rules)

    preexisting_fstab_entries: list[str] = []
    for name in ("rules", "decoders"):
        source = (workspace / name).resolve()
        target = WAZUH_HOME / "etc" / name
        expected = f"{source} {target} none bind 0 0"
        if any(
            line.strip() == expected for line in (snapshot.fstab or "").splitlines()
        ):
            preexisting_fstab_entries.append(str(target))

    group_membership_added = ensure_group_membership(runner, user)

    state.update(
        {
            "workspace": str(workspace),
            "wazuh_home": str(WAZUH_HOME),
            "wazuh_version": installed,
            "provisioning": {
                "wazuh_installed_by_tool": wazuh_installed_by_tool,
                "workspace_venv_created_by_tool": workspace_venv_created_by_tool,
                "group_membership_added": group_membership_added,
                "service_was_active": snapshot.service_was_active,
                "service_was_enabled": snapshot.service_was_enabled,
                "preexisting_mounts": sorted(
                    str(path) for path in snapshot.preexisting_mounts
                ),
                "preexisting_fstab_entries": preexisting_fstab_entries,
                "package_manager_family": getattr(package_manager, "family", None),
                "system_dependencies_installed": list(system_dependencies_installed),
                "repository_before": repository_before,
                "apt_keyring_preexisting": apt_keyring_preexisting,
                "ossec_conf_before": snapshot.ossec_conf,
                "windows_rules_before": snapshot.windows_rules,
                "ossec_backup_preexisting": (snapshot.ossec_backup_preexisting),
                "windows_backup_preexisting": (snapshot.windows_backup_preexisting),
            },
        }
    )

    try:
        stop_wazuh(runner)
        configure_ossec(runner)
        configure_windows_rule_testing(runner)
        configure_bind_mounts(runner, workspace)
        configure_permissions(runner, workspace, user)
        configure_default_acls(runner, workspace)
        validate_wazuh(runner)
        start_wazuh(runner)
        wait_for_logtest(runner)
        save_state(home, state)
    except Exception:
        _rollback_provisioning(runner, workspace, snapshot)
        raise

    return installed
