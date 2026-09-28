from pathlib import Path

import pytest

from wazuhdevenv.errors import ConfigurationError  # type: ignore
from wazuhdevenv.state import (  # type: ignore
    ensure_managed_home,
    load_state,
    managed_lock,
    managed_lock_path,
    save_state,
)


def test_managed_home_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "managed"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ConfigurationError, match="managed home must not be a symlink"):
        ensure_managed_home(link)


def test_managed_subdirectory_rejects_symlink(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    home.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    (home / "cache").symlink_to(target, target_is_directory=True)

    with pytest.raises(ConfigurationError, match="managed state directory must not be a symlink"):
        ensure_managed_home(home)


def test_state_file_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "external.json"
    target.write_text('{"schema_version": 1}\n', encoding="utf-8")
    (tmp_path / "state.json").symlink_to(target)

    with pytest.raises(ConfigurationError, match="state file must not be a symlink"):
        load_state(tmp_path)


def test_lock_file_rejects_symlink(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    target = tmp_path / "external.lock"
    target.touch()
    managed_lock_path(home).symlink_to(target)

    with pytest.raises(ConfigurationError, match="lock file must not be a symlink"), managed_lock(home):
            pass


def test_managed_lock_prevents_second_writer(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    with managed_lock(home), pytest.raises(RuntimeError, match="another wazuhdevenv operation"), managed_lock(home):
                pass


def test_managed_lock_survives_managed_home_deletion(tmp_path: Path) -> None:
    home = tmp_path / "managed"
    home.mkdir()
    lock_path = managed_lock_path(home)

    with managed_lock(home):
        home.rmdir()
        assert lock_path.exists()
        with pytest.raises(RuntimeError, match="another wazuhdevenv operation"), managed_lock(home):
                pass

    assert lock_path.exists()


def test_state_round_trip(tmp_path: Path) -> None:
    save_state(tmp_path, {"workspace": "/tmp/workspace"})

    assert load_state(tmp_path) == {
        "schema_version": 1,
        "workspace": "/tmp/workspace",
    }


@pytest.mark.parametrize("schema", [2, True, False, 1.0, "1"])
def test_save_state_rejects_unsupported_schema(
    tmp_path: Path,
    schema: object,
) -> None:
    with pytest.raises(ValueError, match="unsupported state schema version"):
        save_state(tmp_path, {"schema_version": schema})

    assert not (tmp_path / "state.json").exists()


@pytest.mark.parametrize("schema_json", ["2", "true", "false", "1.0", "\"1\""])
def test_load_state_rejects_unsupported_schema(
    tmp_path: Path,
    schema_json: str,
) -> None:
    (tmp_path / "state.json").write_text(
        f'{{"schema_version": {schema_json}}}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unsupported state file"):
        load_state(tmp_path)
