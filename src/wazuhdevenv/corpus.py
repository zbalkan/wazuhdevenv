"""Discovery, verification, and atomic installation of rule-test corpora."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .errors import CorpusError
from .state import load_state, save_state

RELEASES_API = "https://api.github.com/repos/zbalkan/wazuh-rule-tests/releases?per_page=100"
USER_AGENT = "wazuhdevenv"
VERSION = re.compile(r"^\d+\.\d+\.\d+$")


@dataclass(frozen=True)
class CorpusRelease:
    manifest: dict[str, object]
    manifest_url: str
    archive_url: str
    checksum_url: str

    @property
    def version(self) -> str:
        return str(self.manifest["version"])


def _request(url: str, *, authenticated: bool = False) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    if authenticated:
        if not url.startswith("https://api.github.com/"):
            raise CorpusError("authenticated downloads are restricted to api.github.com")
        headers["Accept"] = "application/vnd.github+json"
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CorpusError(f"failed to download {url}: {exc}") from exc


def _asset_url(release: dict[str, object], name: str) -> str | None:
    for asset in release.get("assets", []):  # type: ignore
        if isinstance(asset, dict) and asset.get("name") == name:
            url = asset.get("browser_download_url")
            return str(url) if url else None
    return None


def resolve_release(wazuh_version: str) -> CorpusRelease:
    if not VERSION.fullmatch(wazuh_version):
        raise CorpusError(f"invalid Wazuh version: {wazuh_version}")

    try:
        releases = json.loads(_request(RELEASES_API, authenticated=True))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CorpusError("GitHub returned invalid release metadata") from exc
    if not isinstance(releases, list):
        raise CorpusError("unexpected GitHub release response")

    inspected_manifests = 0
    version_mismatches = 0
    invalid_manifests = 0

    for release in releases:
        if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
            continue

        manifest_url = _asset_url(release, "manifest.json")
        if not manifest_url:
            continue

        try:
            manifest = json.loads(_request(manifest_url))
        except (json.JSONDecodeError, UnicodeDecodeError, CorpusError):
            invalid_manifests += 1
            continue
        if not isinstance(manifest, dict):
            invalid_manifests += 1
            continue

        inspected_manifests += 1
        version = manifest.get("version")
        if not isinstance(version, str) or not VERSION.fullmatch(version):
            invalid_manifests += 1
            continue
        if version != wazuh_version:
            version_mismatches += 1
            continue

        archive_url = _asset_url(release, f"wazuh-rule-tests-{version}.zip")
        checksum_url = _asset_url(release, f"wazuh-rule-tests-{version}.zip.sha256")
        if archive_url and checksum_url:
            return CorpusRelease(manifest, manifest_url, archive_url, checksum_url)

        invalid_manifests += 1

    raise CorpusError(
        f"no released rule-test corpus exactly matches Wazuh {wazuh_version}; "
        f"inspected {inspected_manifests} manifests; "
        f"version mismatches={version_mismatches}, invalid releases={invalid_manifests}"
    )


def _verify_checksum(archive: Path, checksum_text: str) -> str:
    fields = checksum_text.strip().split()
    if not fields:
        raise CorpusError("invalid SHA-256 checksum asset")
    expected = fields[0].lower()
    if len(expected) != 64 or any(ch not in "0123456789abcdef" for ch in expected):
        raise CorpusError("invalid SHA-256 checksum asset")
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != expected:
        raise CorpusError(f"corpus checksum mismatch: expected {expected}, got {actual}")
    return actual


def _validate_member(info: zipfile.ZipInfo) -> None:
    path = PurePosixPath(info.filename)
    if path.is_absolute() or ".." in path.parts:
        raise CorpusError(f"unsafe archive path: {info.filename}")
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise CorpusError(f"unsupported archive entry: {info.filename}")


def _safe_extract(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as source:
        seen: set[PurePosixPath] = set()
        for info in source.infolist():
            _validate_member(info)
            normalized = PurePosixPath(info.filename)
            if normalized in seen:
                raise CorpusError(f"duplicate archive destination: {info.filename}")
            seen.add(normalized)
        source.extractall(destination)


def _write_bytes(path: Path, content: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_symlink(link: Path, target: str) -> None:
    temporary = link.parent / f".{link.name}.{secrets.token_hex(8)}"
    try:
        os.symlink(target, temporary)
        os.replace(temporary, link)
    finally:
        temporary.unlink(missing_ok=True)


def install_release(home: Path, release: CorpusRelease) -> None:
    cache = home / "cache"
    corpora = home / "corpora"
    for directory in (cache, corpora):
        if directory.is_symlink():
            raise CorpusError(f"managed corpus directory must not be a symlink: {directory}")
        directory.mkdir(parents=True, exist_ok=True)

    archive = cache / f"wazuh-rule-tests-{release.version}.zip"
    _write_bytes(archive, _request(release.archive_url))
    digest = _verify_checksum(
        archive,
        _request(release.checksum_url).decode("ascii", errors="strict"),
    )

    release_root = Path(
        tempfile.mkdtemp(
            prefix=f"{release.version}-{digest[:12]}.",
            dir=corpora,
        )
    )
    current = home / "current-corpus"
    old_target = os.readlink(current) if current.is_symlink() else None
    if os.path.lexists(current) and not current.is_symlink():
        shutil.rmtree(release_root, ignore_errors=True)
        raise CorpusError(f"current corpus pointer must be a symlink: {current}")

    pointer_swapped = False
    try:
        _safe_extract(archive, release_root)
        embedded_path = release_root / "manifest.json"
        tests_path = release_root / "tests"
        if not embedded_path.is_file() or not tests_path.is_dir():
            raise CorpusError("corpus archive must contain manifest.json and tests/")

        embedded = json.loads(embedded_path.read_text(encoding="utf-8"))
        if embedded != release.manifest:
            raise CorpusError("standalone and embedded corpus manifests differ")

        _atomic_symlink(current, os.path.relpath(release_root, home))
        pointer_swapped = True

        state = load_state(home)
        state.update(
            {
                "active_corpus": release.version,
                "corpus_installed_at": datetime.now(timezone.utc)
                .replace(microsecond=0)
                .isoformat(),
            }
        )
        save_state(home, state)
    except Exception:
        if pointer_swapped:
            if old_target is None:
                current.unlink(missing_ok=True)
            else:
                _atomic_symlink(current, old_target)
        shutil.rmtree(release_root, ignore_errors=True)
        raise


def update_corpus(home: Path, wazuh_version: str) -> str:
    release = resolve_release(wazuh_version)

    state = load_state(home)
    current = home / "current-corpus"
    if (
        state.get("active_corpus") == release.version
        and (current / "tests").is_dir()
        and (current / "manifest.json").is_file()
    ):
        return release.version

    try:
        install_release(home, release)
    except CorpusError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError, zipfile.BadZipFile, OSError) as exc:
        raise CorpusError(f"failed to install rule-test corpus: {exc}") from exc
    return release.version
