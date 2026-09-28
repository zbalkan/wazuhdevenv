from __future__ import annotations

import hashlib
import json
import os
import stat
import warnings
import zipfile
from pathlib import Path
from typing import Self

import pytest

from wazuhdevenv import corpus  # type: ignore
from wazuhdevenv.corpus import CorpusRelease  # type: ignore
from wazuhdevenv.errors import CorpusError  # type: ignore


def _manifest(version: str) -> dict[str, object]:
    return {
        "version": version,
        "upstream": {
            "repository": "https://github.com/wazuh/wazuh",
            "commit": "e" * 40,
            "path": "ruleset/testing/tests",
        },
    }


def _release_metadata(version: str, manifest_url: str) -> dict[str, object]:
    return {
        "draft": False,
        "prerelease": False,
        "assets": [
            {"name": "manifest.json", "browser_download_url": manifest_url},
            {
                "name": f"wazuh-rule-tests-{version}.zip",
                "browser_download_url": f"archive-{version}",
            },
            {
                "name": f"wazuh-rule-tests-{version}.zip.sha256",
                "browser_download_url": f"checksum-{version}",
            },
        ],
    }


def _build_archive(
    tmp_path: Path,
    manifest: dict[str, object],
    payload: str = "pass\n",
) -> bytes:
    path = tmp_path / f"{manifest['version']}.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("tests/test_payload.py", payload)
    return path.read_bytes()


@pytest.mark.parametrize("name", ["/etc/passwd", "../escape", "tests/../../escape"])
def test_archive_paths_cannot_escape_root(name: str) -> None:
    with pytest.raises(CorpusError, match="unsafe archive path"):
        corpus._validate_member(zipfile.ZipInfo(name))


def test_symlink_archive_member_is_rejected() -> None:
    info = zipfile.ZipInfo("tests/link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16

    with pytest.raises(CorpusError, match="unsupported archive entry"):
        corpus._validate_member(info)


def test_duplicate_archive_destinations_are_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "duplicate.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(archive, "w") as target:
            target.writestr("tests/test_example.py", "first")
            target.writestr("tests/test_example.py", "second")

    with pytest.raises(CorpusError, match="duplicate archive destination"):
        corpus._safe_extract(archive, tmp_path / "out")


def test_checksum_validation(tmp_path: Path) -> None:
    archive = tmp_path / "corpus.zip"
    archive.write_bytes(b"content")
    expected = hashlib.sha256(b"content").hexdigest()

    assert corpus._verify_checksum(archive, expected) == expected

    with pytest.raises(CorpusError, match="corpus checksum mismatch"):
        corpus._verify_checksum(archive, "0" * 64)

    with pytest.raises(CorpusError, match="invalid SHA-256"):
        corpus._verify_checksum(archive, "")


class FakeResponse:
    def __init__(self, content: bytes) -> None:
        self.content = content

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.content


def test_public_download_does_not_send_github_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[object] = []
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")

    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        del timeout
        requests.append(request)
        return FakeResponse(b"asset")

    monkeypatch.setattr(corpus.urllib.request, "urlopen", fake_urlopen)

    assert corpus._request("https://github.com/example/file.zip") == b"asset"
    request = requests[0]
    assert isinstance(request, corpus.urllib.request.Request)
    assert request.get_header("Authorization") is None


def test_authenticated_requests_are_limited_to_github_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[object] = []
    monkeypatch.setenv("GITHUB_TOKEN", "secret-token")

    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        del timeout
        requests.append(request)
        return FakeResponse(b"[]")

    monkeypatch.setattr(corpus.urllib.request, "urlopen", fake_urlopen)

    assert corpus._request(
        "https://api.github.com/repos/example/releases",
        authenticated=True,
    ) == b"[]"
    request = requests[0]
    assert isinstance(request, corpus.urllib.request.Request)
    assert request.get_header("Authorization") == "Bearer secret-token"

    with pytest.raises(CorpusError, match="restricted to api.github.com"):
        corpus._request(
            "https://github.com/example/file.zip",
            authenticated=True,
        )


def test_resolve_release_selects_exact_wazuh_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    releases = [
        _release_metadata("4.14.8", "manifest-4.14.8"),
        {**_release_metadata("4.14.7", "draft-manifest"), "draft": True},
        _release_metadata("4.14.7", "manifest-4.14.7"),
    ]
    manifests = {
        "manifest-4.14.8": _manifest("4.14.8"),
        "manifest-4.14.7": _manifest("4.14.7"),
    }

    def request(url: str, *, authenticated: bool = False) -> bytes:
        del authenticated
        if url == corpus.RELEASES_API:
            return json.dumps(releases).encode()
        return json.dumps(manifests[url]).encode()

    monkeypatch.setattr(corpus, "_request", request)

    assert corpus.resolve_release("4.14.7").version == "4.14.7"


def test_resolve_release_rejects_newer_corpus_for_older_wazuh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    releases = [_release_metadata("4.14.8", "manifest-4.14.8")]
    manifest = _manifest("4.14.8")

    def request(url: str, *, authenticated: bool = False) -> bytes:
        del authenticated
        if url == corpus.RELEASES_API:
            return json.dumps(releases).encode()
        return json.dumps(manifest).encode()

    monkeypatch.setattr(corpus, "_request", request)

    with pytest.raises(CorpusError, match="exactly matches Wazuh 4.14.7"):
        corpus.resolve_release("4.14.7")


def test_resolve_release_rejects_invalid_wazuh_version() -> None:
    with pytest.raises(CorpusError, match="invalid Wazuh version"):
        corpus.resolve_release("not-a-version")


def test_install_release_activates_verified_corpus(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    (home / "cache").mkdir(parents=True)
    (home / "corpora").mkdir()
    (home / "state.json").write_text(
        json.dumps({"schema_version": 1, "wazuh_version": "4.14.7"}) + "\n",
        encoding="utf-8",
    )
    manifest = _manifest("4.14.7")
    archive = _build_archive(tmp_path, manifest, "new\n")
    payloads = {
        "archive": archive,
        "checksum": hashlib.sha256(archive).hexdigest().encode(),
    }
    monkeypatch.setattr(corpus, "_request", lambda url, **kwargs: payloads[url])

    corpus.install_release(
        home,
        CorpusRelease(manifest, "manifest", "archive", "checksum"),
    )

    current = home / "current-corpus"
    assert current.is_symlink()
    assert (current / "tests/test_payload.py").read_text(encoding="utf-8") == "new\n"
    assert json.loads((current / "manifest.json").read_text(encoding="utf-8")) == manifest

    state = json.loads((home / "state.json").read_text(encoding="utf-8"))
    assert state["active_corpus"] == "4.14.7"
    assert state["wazuh_version"] == "4.14.7"
    assert "wazuhtester_version" not in state


def test_install_release_rejects_mismatched_embedded_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    (home / "cache").mkdir(parents=True)
    (home / "corpora").mkdir()
    release_manifest = _manifest("4.14.7")
    embedded_manifest = _manifest("4.14.8")
    archive = _build_archive(tmp_path, embedded_manifest)
    payloads = {
        "archive": archive,
        "checksum": hashlib.sha256(archive).hexdigest().encode(),
    }
    monkeypatch.setattr(corpus, "_request", lambda url, **kwargs: payloads[url])

    with pytest.raises(CorpusError, match="manifests differ"):
        corpus.install_release(
            home,
            CorpusRelease(release_manifest, "manifest", "archive", "checksum"),
        )

    assert not os.path.lexists(home / "current-corpus")


def test_failed_state_write_restores_previous_pointer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    (home / "cache").mkdir(parents=True)
    corpora = home / "corpora"
    corpora.mkdir()

    previous = corpora / "previous"
    (previous / "tests").mkdir(parents=True)
    (previous / "manifest.json").write_text("{}\n", encoding="utf-8")
    (home / "current-corpus").symlink_to("corpora/previous")

    manifest = _manifest("4.14.7")
    archive = _build_archive(tmp_path, manifest)
    payloads = {
        "archive": archive,
        "checksum": hashlib.sha256(archive).hexdigest().encode(),
    }
    monkeypatch.setattr(corpus, "_request", lambda url, **kwargs: payloads[url])
    monkeypatch.setattr(
        corpus,
        "save_state",
        lambda *args: (_ for _ in ()).throw(RuntimeError("state failure")),
    )

    with pytest.raises(RuntimeError, match="state failure"):
        corpus.install_release(
            home,
            CorpusRelease(manifest, "manifest", "archive", "checksum"),
        )

    assert os.readlink(home / "current-corpus") == "corpora/previous"


def test_update_corpus_skips_active_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    current = home / "corpora/current"
    (current / "tests").mkdir(parents=True)
    (current / "manifest.json").write_text("{}\n", encoding="utf-8")
    (home / "current-corpus").symlink_to("corpora/current")
    (home / "state.json").write_text(
        json.dumps({"schema_version": 1, "active_corpus": "4.14.7"}) + "\n",
        encoding="utf-8",
    )

    release = CorpusRelease(_manifest("4.14.7"), "manifest", "archive", "checksum")
    monkeypatch.setattr(corpus, "resolve_release", lambda *args: release)
    monkeypatch.setattr(
        corpus,
        "install_release",
        lambda *args: (_ for _ in ()).throw(AssertionError("must not reinstall")),
    )

    assert corpus.update_corpus(home, "4.14.7") == "4.14.7"


def test_update_corpus_normalizes_non_utf8_release_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(corpus, "_request", lambda *args, **kwargs: b"\xff")

    with pytest.raises(CorpusError, match="invalid release metadata"):
        corpus.update_corpus(home, "4.14.7")


@pytest.mark.parametrize(
    "error",
    [
        zipfile.BadZipFile("bad zip"),
        json.JSONDecodeError("bad manifest", "{", 0),
        UnicodeDecodeError("ascii", b"\xff", 0, 1, "invalid byte"),
        OSError("I/O failure"),
    ],
)
def test_update_corpus_normalizes_expected_install_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    release = CorpusRelease(
        _manifest("4.14.7"),
        "manifest",
        "archive",
        "checksum",
    )
    monkeypatch.setattr(corpus, "resolve_release", lambda *args: release)

    def fail_install(*args: object) -> None:
        raise error

    monkeypatch.setattr(corpus, "install_release", fail_install)

    with pytest.raises(CorpusError, match="failed to install rule-test corpus"):
        corpus.update_corpus(home, "4.14.7")
