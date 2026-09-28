"""Safe subprocess execution with narrow privilege elevation."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

from .errors import CommandError
from .paths import InvokingUser

TRUSTED_EXEC_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
TRUSTED_PRIVILEGED_EXEC_ROOTS = (
    Path("/usr/bin"),
    Path("/usr/sbin"),
    Path("/bin"),
    Path("/sbin"),
    Path("/var/ossec/bin"),
)


class CommandRunner:
    def __init__(self, user: InvokingUser) -> None:
        self.user = user

    @staticmethod
    def _require(executable: str) -> str:
        resolved = shutil.which(executable)
        if not resolved:
            raise CommandError(f"required command not found: {executable}")
        return resolved

    @staticmethod
    def trusted_which(executable: str) -> str | None:
        """Resolve a bare command using the same PATH used for privileged execution."""
        return shutil.which(executable, path=TRUSTED_EXEC_PATH)

    @staticmethod
    def _require_trusted(executable: str) -> str:
        if os.path.isabs(executable):
            path = Path(executable)
            if not any(path.parent == root for root in TRUSTED_PRIVILEGED_EXEC_ROOTS):
                raise CommandError(
                    f"privileged executable is outside trusted roots: {executable}"
                )
            return executable
        if "/" in executable:
            raise CommandError(
                f"privileged command must be an absolute path or bare command name: {executable}"
            )
        resolved = CommandRunner.trusted_which(executable)
        if not resolved:
            raise CommandError(f"required privileged command not found: {executable}")
        return resolved

    def command(self, args: Sequence[str], *, privileged: bool = False) -> list[str]:
        if not args:
            raise ValueError("command must not be empty")
        executable = (
            self._require_trusted(args[0]) if privileged else self._require(args[0])
        )
        command = [executable, *args[1:]]
        if privileged:
            sudo = self._require_trusted("sudo")
            return [sudo, "--", *command]
        return command

    def run(
        self,
        args: Sequence[str],
        *,
        privileged: bool = False,
        check: bool = True,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = self.command(args, privileged=privileged)
        result = subprocess.run(command, check=False, text=True, env=env)
        if check and result.returncode != 0:
            raise CommandError(
                f"command failed ({result.returncode}): {' '.join(command)}"
            )
        return result

    def capture(self, args: Sequence[str], *, privileged: bool = False) -> str:
        command = self.command(args, privileged=privileged)
        result = subprocess.run(command, check=False, text=True, capture_output=True)
        if result.returncode != 0:
            detail = result.stderr.strip()
            suffix = f": {detail}" if detail else ""
            raise CommandError(
                f"command failed ({result.returncode}): {' '.join(command)}{suffix}"
            )
        return result.stdout

    def run_as_user(
        self,
        args: Sequence[str],
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self.run(args, check=check)

    def capture_as_user(self, args: Sequence[str]) -> str:
        return self.capture(args)
