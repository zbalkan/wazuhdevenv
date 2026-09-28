"""Command-line interface for wazuhdevenv."""

from __future__ import annotations

import argparse
import errno
import logging
import os
import shutil
import sys
from pathlib import Path

from . import __version__
from .corpus import resolve_release, update_corpus
from .coverage import analyze_workspace, format_report
from .errors import ConfigurationError, CorpusError, WazuhDevenvError
from .paths import InvokingUser, managed_home, resolve_workspace
from .provisioning import PackageManager, initialize
from .runner import CommandRunner
from .state import ensure_managed_home, load_state, managed_lock
from .uninstall import format_uninstall_report, uninstall_environment

LOG = logging.getLogger("wazuhdevenv")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wazuhdevenv",
        description="Provision and maintain a local Wazuh rule-development environment.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true")

    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Provision a development workspace")
    init.add_argument("path", nargs="?", help="Workspace path (default: current directory)")
    init.add_argument("--wazuh-version", help="Install or require an exact Wazuh version")
    init.add_argument(
        "--skip-corpus",
        action="store_true",
        help="Do not download the default rule-test corpus",
    )

    update = commands.add_parser("update", help="Install or refresh managed rule-test content")
    update.add_argument(
        "--check",
        action="store_true",
        help="Resolve the corpus for the installed Wazuh version without installing it",
    )

    commands.add_parser(
        "coverage",
        help="Report custom rule coverage from workspace tests",
    )

    commands.add_parser(
        "uninstall",
        help="Remove the managed development environment",
    )

    return parser


def _configure_logging(home: Path, verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    log_path = home / "logs" / "wazuhdevenv.log"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW  # type: ignore
    try:
        fd = os.open(log_path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ConfigurationError(f"log file must not be a symlink: {log_path}") from exc
        raise

    try:
        stream = os.fdopen(fd, "a", encoding="utf-8")
    except Exception:
        os.close(fd)
        raise

    handlers.append(logging.StreamHandler(stream))
    logging.basicConfig(level=level, format="%(levelname)s %(message)s", handlers=handlers)


def _installed_wazuh_version(user: InvokingUser, home: Path) -> str:
    state = load_state(home)
    recorded = state.get("wazuh_version")
    runner = CommandRunner(user)
    actual = PackageManager(runner).installed_version()
    if not actual:
        raise WazuhDevenvError(
            "Wazuh Manager is not installed; reinstall Wazuh Manager before "
            "running 'wazuhdevenv update'"
        )
    if recorded and recorded != actual:
        LOG.warning("Recorded Wazuh version %s differs from installed version %s", recorded, actual)
    return actual


def _init_command(args: argparse.Namespace, user: InvokingUser, home: Path) -> int:
    workspace = resolve_workspace(args.path)
    LOG.info("Provisioning workspace: %s", workspace)
    version = initialize(
        workspace,
        home,
        user,
        wazuh_version=args.wazuh_version,
    )
    LOG.info("Wazuh Manager ready: %s", version)
    if not args.skip_corpus:
        try:
            corpus = update_corpus(home, version)
        except CorpusError as exc:
            raise CorpusError(
                "Wazuh initialization completed, but rule-test corpus installation failed. "
                f"{exc}. Do not run 'init' again; after correcting the reported problem, "
                "run 'wazuhdevenv update'."
            ) from exc
        LOG.info("Managed rule-test corpus ready: %s", corpus)
    return 0


def _update_command(args: argparse.Namespace, user: InvokingUser, home: Path) -> int:
    version = _installed_wazuh_version(user, home)
    if args.check:
        release = resolve_release(version)
        print(release.version)
        return 0
    installed = update_corpus(home, version)
    LOG.info("Managed rule-test corpus ready: %s", installed)
    return 0


def _coverage_command(home: Path) -> int:
    state = load_state(home)
    workspace_value = state.get("workspace")
    if not isinstance(workspace_value, str):
        raise WazuhDevenvError(
            "workspace is not initialized; run 'wazuhdevenv init' first"
        )

    result = analyze_workspace(Path(workspace_value))
    print(format_report(result))
    return 0


def _uninstall_command(user: InvokingUser, home: Path) -> int:
    result = uninstall_environment(home, user)
    shutil.rmtree(home)
    print(format_uninstall_report(result, home))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging_ready = False

    try:
        if os.geteuid() == 0:  # type: ignore
            raise ConfigurationError(
                "run wazuhdevenv as the developer, not as root; "
                "the tool invokes sudo only for system changes"
            )
        user = InvokingUser.current()
        home = managed_home(user)
        with managed_lock(home):
            ensure_managed_home(home)
            _configure_logging(home, args.verbose)
            logging_ready = True

            if args.command == "init":
                return _init_command(args, user, home)
            if args.command == "update":
                return _update_command(args, user, home)
            if args.command == "coverage":
                return _coverage_command(home)
            if args.command == "uninstall":
                return _uninstall_command(user, home)
    except (WazuhDevenvError, ValueError, OSError, RuntimeError) as exc:
        if logging_ready:
            LOG.error("%s", exc)
        else:
            print(f"wazuhdevenv: {exc}", file=sys.stderr)
        return 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
