#!/usr/bin/env python3
"""Distribution-only guard for arenberg-engineering/engra-releases.

Fails closed: an unexpected file, a parse error, a tool error or a suspected
secret all exit non-zero. Inventories come from exact sources, never from
``ls``/``find`` output or loose globs:

  repo                                 the git index (``git ls-files -z``)
  assets  --version V --dir D [--print0 OUT]
                                       the exact release set for version V,
                                       computed from V; every file is opened and
                                       checked, archives member by member
  release --version V --json FILE      asset names of a published release, from
                                       the GitHub API JSON
  selftest                             proves that the known bypasses fail

Rules:
  * names are matched with ``re.fullmatch`` against an ASCII-only allowlist,
    so names with newlines, control characters, unicode lookalikes, leading
    dashes, path separators or extra suffixes are rejected;
  * archives must hold the exact top-level files ``engra-V-<platform>/{engra|engra.exe,
    LICENSE.txt, TERMS.md, THIRD_PARTY_NOTICES.txt}``, plus optional PyInstaller
    ``--onedir`` runtime files strictly under ``engra-V-<platform>/_internal/...``
    with ASCII-only path segments (no dotfiles, ``..``, absolute paths, hardlinks,
    or ``.py``/key/script suffixes; relative symlinks in ``.tar.gz`` must stay
    confined inside ``_internal/``, and nested ``.zip`` members such as
    ``base_library.zip`` are unpacked in memory and checked);
  * every file, archive member, and nested ``.zip`` member is scanned for
    credential patterns and internal endpoints.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import posixpath
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

PLATFORMS = ("macos-arm64", "macos-x64", "linux-x64", "linux-arm64", "windows-x64")
TAR_PLATFORMS = PLATFORMS[:4]
LEGAL = ("LICENSE.txt", "TERMS.md")
SINGLES = (
    "LICENSE.txt",
    "TERMS.md",
    "SHA256SUMS",
    "signing-status.json",
    "build-info.json",
)
VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII)
_COMMIT_SHA_RE = re.compile(r"[0-9a-f]{40}", re.ASCII)
_HEX64_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
# ASCII [A-Za-z0-9._-] segments, never starting with '.' or '-' (rejects '.', '..', dotfiles, leading '-').
_INTERNAL_SEG_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*", re.ASCII)
_FORBIDDEN_INTERNAL_SUFFIXES = (
    ".py",
    ".pyc",
    ".pyo",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".kdbx",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
)
_FORBIDDEN_NESTED_ZIP_SUFFIXES = (
    ".py",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".kdbx",
    ".env",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".zip",
)
_MAX_NESTED_ZIP_BYTES = 64 * 1024 * 1024

# Files the repository itself may track (exact paths).
REPO_ALLOWED = frozenset(
    {
        "README.md",
        "LICENSE.txt",
        "TERMS.md",
        ".github/dependabot.yml",
        ".github/workflows/publish.yml",
        ".github/workflows/publish-desktop.yml",
        ".github/workflows/content-check.yml",
        "scripts/check_distribution.py",
        "scripts/supersede-release.sh",
    }
)
# This file defines the patterns below, so it is the one file not scanned.
SELF = "scripts/check_distribution.py"

# A strict superset of the rules in the former check-release-assets.sh and
# content-check.yml (no word boundaries, so nothing they caught slips past).
_SECRET_PATTERNS: tuple[tuple[str, bytes], ...] = (
    ("private key", rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ("Stripe secret/restricted key", rb"[sr]k_(?:live|test)_[0-9A-Za-z]{10,}"),
    ("AWS access key id", rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ("GitHub token", rb"gh[pousr]_[A-Za-z0-9]{30,}"),
    ("GitHub fine-grained token", rb"github_pat_[A-Za-z0-9_]{40,}"),
    ("Google API key", rb"AIza[0-9A-Za-z_\-]{35}"),
    ("Slack token", rb"xox[abprs]-[0-9A-Za-z\-]{10,}"),
    ("GCP service-account JSON", rb'"type"\s*:\s*"service_account"'),
    ("private_key_id field", rb'"private_key_id"\s*:'),
    ("Cloud Run URL", rb"[a-z0-9-]+\.run\.app"),
    ("internal host", rb"[a-z0-9.-]+\.internal\b"),
    ("GCE metadata endpoint", rb"metadata\.google\.internal"),
    ("internal project name", rb"engra-prod"),
    ("loopback URL", rb"127\.0\.0\.1:[0-9]{2,5}/"),
)
SECRETS = tuple((label, re.compile(rx)) for label, rx in _SECRET_PATTERNS)


class Reject(Exception):
    pass


def expected_assets(version: str) -> list[str]:
    if not VERSION_RE.fullmatch(version):
        raise Reject(f"bad version {version!r}")
    names = [f"engra-{version}-{p}.tar.gz" for p in TAR_PLATFORMS]
    names.append(f"engra-{version}-windows-x64.zip")
    for p in PLATFORMS:
        names += [
            f"engra-{version}-{p}.cdx.json",
            f"engra-{version}-{p}.spdx.json",
            f"THIRD_PARTY_NOTICES-{p}.txt",
        ]
    return sorted([*names, *SINGLES])


def scan_bytes(label: str, data: bytes) -> None:
    for what, rx in SECRETS:
        if rx.search(data):
            raise Reject(f"{label}: contains a {what}")


def _valid_internal_rel(rel: str) -> bool:
    if not rel or not rel.isascii():
        return False
    return all(_INTERNAL_SEG_RE.fullmatch(seg) is not None for seg in rel.split("/"))


def _check_member_name(
    archive: str, name: str, root: str, exe: str, *, is_dir: bool = False
) -> bool:
    if not name or not name.isascii():
        raise Reject(f"{archive}: unexpected member {name!r}")
    internal_prefix = f"{root}/_internal/"
    if is_dir:
        trimmed = name.removesuffix("/")
        if trimmed in (root, f"{root}/_internal"):
            return False
        if trimmed.startswith(internal_prefix) and _valid_internal_rel(
            trimmed[len(internal_prefix) :]
        ):
            return False
        raise Reject(f"{archive}: unexpected directory {name!r}")

    top_allowed = {f"{root}/{n}" for n in (exe, *LEGAL, "THIRD_PARTY_NOTICES.txt")}
    if name in top_allowed:
        return True
    if name.startswith(internal_prefix):
        rel = name[len(internal_prefix) :]
        if not _valid_internal_rel(rel):
            raise Reject(f"{archive}: unexpected member {name!r}")
        if rel.lower().endswith(_FORBIDDEN_INTERNAL_SUFFIXES):
            raise Reject(f"{archive}: forbidden runtime member {name!r}")
        return False
    raise Reject(f"{archive}: unexpected member {name!r}")


def _check_tar_symlink(archive: str, member: tarfile.TarInfo, root: str) -> None:
    linkname = member.linkname
    if (
        not linkname
        or not linkname.isascii()
        or linkname.startswith("/")
        or any(ch in linkname for ch in ("\x00", "\n", "\r", "\\"))
    ):
        raise Reject(
            f"{archive}: invalid symlink target {linkname!r} for {member.name!r}"
        )
    segs = linkname.split("/")
    if not all(
        seg == ".." or _INTERNAL_SEG_RE.fullmatch(seg) is not None for seg in segs
    ):
        raise Reject(
            f"{archive}: invalid symlink target {linkname!r} for {member.name!r}"
        )
    internal_root = f"{root}/_internal"
    internal_prefix = f"{internal_root}/"
    cur = posixpath.dirname(member.name)
    for seg in segs:
        cur = posixpath.normpath(posixpath.join(cur, seg))
        if cur != internal_root and not cur.startswith(internal_prefix):
            raise Reject(
                f"{archive}: symlink {member.name!r} -> {linkname!r} escapes _internal/"
            )
    resolved = posixpath.normpath(
        posixpath.join(posixpath.dirname(member.name), linkname)
    )
    if not resolved.startswith(internal_prefix):
        raise Reject(
            f"{archive}: symlink {member.name!r} -> {linkname!r} escapes _internal/"
        )
    if resolved.lower().endswith(_FORBIDDEN_INTERNAL_SUFFIXES):
        raise Reject(
            f"{archive}: symlink {member.name!r} -> {linkname!r} targets forbidden suffix"
        )
    scan_bytes(f"{archive}:{member.name}", linkname.encode("ascii"))


def _check_nested_zip(label: str, data: bytes) -> None:
    try:
        zf_ctx = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise Reject(f"{label}: invalid nested zip: {exc}") from exc
    total_size = 0
    seen_inner: set[str] = set()
    with zf_ctx as zf:
        for info in zf.infolist():
            name = info.filename
            if not name or not name.isascii():
                raise Reject(f"{label}: invalid nested member {name!r}")
            if info.flag_bits & 0x1:
                raise Reject(f"{label}: encrypted nested member {name!r}")
            mode = (info.external_attr >> 16) & 0o170000
            if info.is_dir():
                if mode not in (0, 0o040000):
                    raise Reject(f"{label}: {name!r} is not a regular directory")
                rel = name[:-1]
                if not _valid_internal_rel(rel) or rel in seen_inner:
                    raise Reject(f"{label}: unexpected nested directory {name!r}")
                seen_inner.add(rel)
                continue
            if mode not in (0, 0o100000):
                raise Reject(f"{label}: {name!r} is not a regular file")
            if not _valid_internal_rel(name) or name in seen_inner:
                raise Reject(f"{label}: unexpected nested member {name!r}")
            if name.lower().endswith(_FORBIDDEN_NESTED_ZIP_SUFFIXES):
                raise Reject(f"{label}: forbidden nested member {name!r}")
            if (
                info.file_size < 0
                or total_size + info.file_size > _MAX_NESTED_ZIP_BYTES
            ):
                raise Reject(
                    f"{label}: nested zip exceeds {_MAX_NESTED_ZIP_BYTES} bytes"
                )
            seen_inner.add(name)
            remaining = _MAX_NESTED_ZIP_BYTES - total_size
            with zf.open(info, "r") as fp:
                raw = fp.read(remaining + 1)
            if len(raw) > remaining:
                raise Reject(
                    f"{label}: nested zip exceeds {_MAX_NESTED_ZIP_BYTES} bytes"
                )
            total_size += max(info.file_size, len(raw))
            scan_bytes(f"{label}:{name}", raw)


def check_archive(path: Path, version: str, platform: str) -> None:
    root = f"engra-{version}-{platform}"
    exe = "engra.exe" if platform.startswith("windows") else "engra"
    want = {f"{root}/{n}" for n in (exe, *LEGAL, "THIRD_PARTY_NOTICES.txt")}
    seen_top: set[str] = set()
    seen_paths: set[str] = set()
    if path.name.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:
                    raise Reject(f"{path.name}: encrypted member {info.filename!r}")
                is_dir = info.is_dir()
                is_top = _check_member_name(
                    path.name, info.filename, root, exe, is_dir=is_dir
                )
                norm = info.filename[:-1] if is_dir else info.filename
                if norm in seen_paths:
                    raise Reject(f"{path.name}: duplicate member {info.filename!r}")
                seen_paths.add(norm)
                mode = (info.external_attr >> 16) & 0o170000
                if is_dir:
                    if mode not in (0, 0o040000):
                        raise Reject(
                            f"{path.name}: {info.filename!r} is not a regular directory"
                        )
                    continue
                if mode not in (0, 0o100000):
                    raise Reject(
                        f"{path.name}: {info.filename!r} is not a regular file"
                    )
                if is_top:
                    seen_top.add(info.filename)
                data = zf.read(info)
                label = f"{path.name}:{info.filename}"
                scan_bytes(label, data)
                if not is_top and info.filename.lower().endswith(".zip"):
                    _check_nested_zip(label, data)
    else:
        with tarfile.open(path, mode="r:gz") as tf:
            for member in tf.getmembers():
                is_dir = member.isdir()
                is_top = _check_member_name(
                    path.name, member.name, root, exe, is_dir=is_dir
                )
                norm = (
                    member.name[:-1]
                    if is_dir and member.name.endswith("/")
                    else member.name
                )
                if norm in seen_paths:
                    raise Reject(f"{path.name}: duplicate member {member.name!r}")
                seen_paths.add(norm)
                if is_dir:
                    continue
                if member.issym():
                    if is_top:
                        raise Reject(
                            f"{path.name}: {member.name!r} is not a regular file"
                        )
                    _check_tar_symlink(path.name, member, root)
                    continue
                if member.islnk() or not member.isfile():
                    raise Reject(f"{path.name}: {member.name!r} is not a regular file")
                if is_top:
                    seen_top.add(member.name)
                fh = tf.extractfile(member)
                if fh is None:
                    raise Reject(f"{path.name}: cannot read {member.name!r}")
                data = fh.read()
                label = f"{path.name}:{member.name}"
                scan_bytes(label, data)
                if not is_top and member.name.lower().endswith(".zip"):
                    _check_nested_zip(label, data)
    if not want.issubset(seen_top) or seen_top != want:
        raise Reject(f"{path.name}: members {sorted(seen_top)} != {sorted(want)}")


def check_build_info(data: bytes, version: str, expected_names: list[str]) -> None:
    try:
        info = json.loads(data)
    except Exception as exc:
        raise Reject(f"build-info.json: invalid JSON: {exc}") from exc
    if not isinstance(info, dict):
        raise Reject("build-info.json: root must be a JSON object")
    if info.get("version") != version:
        raise Reject(f"build-info.json: version {info.get('version')!r} != {version!r}")
    expected_tag = f"v{version}"
    if info.get("tag") != expected_tag:
        raise Reject(f"build-info.json: tag {info.get('tag')!r} != {expected_tag!r}")
    commit = info.get("source_commit")
    if not isinstance(commit, str) or not _COMMIT_SHA_RE.fullmatch(commit):
        raise Reject(f"build-info.json: invalid 40-hex source_commit {commit!r}")
    logo_sha = info.get("logo_png_64_sha256")
    if not isinstance(logo_sha, str) or not _HEX64_RE.fullmatch(logo_sha):
        raise Reject(f"build-info.json: invalid 64-hex logo_png_64_sha256 {logo_sha!r}")
    if not isinstance(info.get("release"), bool):
        raise Reject("build-info.json: release field must be a boolean")
    assets = info.get("assets")
    if (
        not isinstance(assets, list)
        or sorted(assets) != expected_names
        or assets != expected_names
    ):
        raise Reject(f"build-info.json: assets {assets!r} != {expected_names!r}")


def check_assets(version: str, directory: Path) -> list[str]:
    names = expected_assets(version)
    for name in names:
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise Reject(f"missing or not a regular file: {name}")
        if name.endswith((".tar.gz", ".zip")):
            platform = name[len(f"engra-{version}-") :].split(".", 1)[0]
            check_archive(path, version, platform)
        else:
            data = path.read_bytes()
            if name.endswith(".json"):
                json.loads(data)  # must parse; a parse error fails closed
            if name == "build-info.json":
                check_build_info(data, version, names)
            scan_bytes(name, data)
    return names


def check_release_json(version: str, json_path: Path) -> None:
    release = json.loads(json_path.read_text(encoding="utf-8"))
    names = [a["name"] for a in release["assets"]]
    if len(names) != len(set(names)):
        raise Reject("duplicate asset names in the release")
    expected = set(expected_assets(version))
    extra = sorted(set(names) - expected)
    missing = sorted(expected - set(names))
    if extra or missing:
        raise Reject(f"release assets differ: extra={extra!r} missing={missing!r}")


def check_repo(root: Path) -> None:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--"],
        check=True,
        capture_output=True,
    ).stdout
    paths = [p.decode("utf-8", errors="strict") for p in out.split(b"\0") if p]
    bad = [p for p in paths if p not in REPO_ALLOWED]
    if bad:
        raise Reject(f"not allowed in the distribution repository: {bad!r}")
    for rel in paths:
        if rel == SELF:
            continue
        scan_bytes(rel, (root / rel).read_bytes())


# ── Desktop distribution checks ──────────────────────────────────────────────


def _desktop_product_spec(product: str = "code") -> tuple[str, str, str]:
    norm = product.strip().lower()
    if norm == "code":
        return "Engra", "desktop-v", "engra-desktop"
    if norm == "one":
        return "Engra_One", "one-desktop-v", "engra-one-desktop"
    raise Reject(f"unsupported desktop product {product!r}")


def expected_desktop_assets(version: str, *, product: str = "code") -> list[str]:
    if not VERSION_RE.fullmatch(version):
        raise Reject(f"bad version {version!r}")
    prefix, _, _ = _desktop_product_spec(product)
    return sorted(
        [
            f"{prefix}_{version}_aarch64.dmg",
            f"{prefix}_{version}_aarch64.app.tar.gz",
            f"{prefix}_{version}_aarch64.app.tar.gz.sig",
            f"{prefix}_{version}_x64.dmg",
            f"{prefix}_{version}_x64.app.tar.gz",
            f"{prefix}_{version}_x64.app.tar.gz.sig",
            f"{prefix}_{version}_x64-setup.exe",
            f"{prefix}_{version}_x64-setup.exe.sig",
            f"{prefix}_{version}_x64_en-US.msi",
            f"{prefix}_{version}_amd64.deb",
            f"{prefix}-{version}-1.x86_64.rpm",
            f"{prefix}_{version}_amd64.AppImage",
            f"{prefix}_{version}_amd64.AppImage.sig",
            "latest.json",
            "SHA256SUMS",
            "signing-status.json",
            "build-info.json",
        ]
    )


UPDATER_FILENAMES = {
    "darwin-aarch64": "{prefix}_{version}_aarch64.app.tar.gz",
    "darwin-x86_64": "{prefix}_{version}_x64.app.tar.gz",
    "windows-x86_64": "{prefix}_{version}_x64-setup.exe",
    "linux-x86_64": "{prefix}_{version}_amd64.AppImage",
}
_SHA256SUMS_LINE_RE = re.compile(r"^([0-9a-f]{64})  \*?([A-Za-z0-9._-]+)$", re.ASCII)


def check_desktop_build_info(
    data: bytes, version: str, *, product: str = "code"
) -> None:
    _, tag_prefix, expected_product = _desktop_product_spec(product)
    try:
        info = json.loads(data)
    except Exception as exc:
        raise Reject(f"build-info.json: invalid JSON: {exc}") from exc
    if not isinstance(info, dict):
        raise Reject("build-info.json: root must be a JSON object")
    if info.get("product") != expected_product:
        raise Reject(
            f"build-info.json: product {info.get('product')!r} != {expected_product!r}"
        )
    if info.get("version") != version:
        raise Reject(f"build-info.json: version {info.get('version')!r} != {version!r}")
    expected_tag = f"{tag_prefix}{version}"
    if info.get("tag") != expected_tag:
        raise Reject(f"build-info.json: tag {info.get('tag')!r} != {expected_tag!r}")
    commit = info.get("source_commit")
    if not isinstance(commit, str) or not _COMMIT_SHA_RE.fullmatch(commit):
        raise Reject(f"build-info.json: invalid 40-hex source_commit {commit!r}")
    if info.get("release") is not True:
        raise Reject("build-info.json release must be true")
    if info.get("distribution") != "arenberg-engineering/engra-releases":
        raise Reject(
            f"build-info.json: distribution {info.get('distribution')!r} != 'arenberg-engineering/engra-releases'"
        )


def check_desktop_latest_manifest(
    data: bytes, version: str, *, product: str = "code"
) -> None:
    prefix, tag_prefix, _ = _desktop_product_spec(product)
    try:
        info = json.loads(data)
    except Exception as exc:
        raise Reject(f"latest.json: invalid JSON: {exc}") from exc
    if not isinstance(info, dict):
        raise Reject("latest.json: root must be a JSON object")
    if info.get("version") != version:
        raise Reject(f"latest.json: version {info.get('version')!r} != {version!r}")
    platforms = info.get("platforms")
    if not isinstance(platforms, dict):
        raise Reject("latest.json: platforms must be a JSON object")
    expected_targets = {
        "darwin-aarch64",
        "darwin-x86_64",
        "windows-x86_64",
        "linux-x86_64",
    }
    if set(platforms.keys()) != expected_targets:
        raise Reject(
            f"latest.json: platforms {set(platforms.keys())!r} != {expected_targets!r}"
        )
    for target, p_info in platforms.items():
        if not isinstance(p_info, dict):
            raise Reject(f"latest.json: platforms[{target!r}] must be a JSON object")
        url = p_info.get("url")
        expected_fn = UPDATER_FILENAMES[target].format(prefix=prefix, version=version)
        expected_url = f"https://github.com/arenberg-engineering/engra-releases/releases/download/{tag_prefix}{version}/{expected_fn}"
        if url != expected_url:
            raise Reject(
                f"latest.json: platforms[{target!r}].url {url!r} != {expected_url!r}"
            )
        sig = p_info.get("signature")
        if not isinstance(sig, str) or not sig.strip():
            raise Reject(
                f"latest.json: platforms[{target!r}].signature must be a non-empty string"
            )


def check_desktop_signing_status(
    data: bytes, version: str, *, product: str = "code"
) -> None:
    _, tag_prefix, _ = _desktop_product_spec(product)
    try:
        info = json.loads(data)
    except Exception as exc:
        raise Reject(f"signing-status.json: invalid JSON: {exc}") from exc
    if not isinstance(info, dict):
        raise Reject("signing-status.json: root must be a JSON object")
    if info.get("version") != version:
        raise Reject(
            f"signing-status.json: version {info.get('version')!r} != {version!r}"
        )
    expected_tag = f"{tag_prefix}{version}"
    if info.get("tag") != expected_tag:
        raise Reject(
            f"signing-status.json: tag {info.get('tag')!r} != {expected_tag!r}"
        )
    if info.get("updater_ed25519_key_id") != "08F3E169207691F4":
        raise Reject(
            f"signing-status.json: updater_ed25519_key_id {info.get('updater_ed25519_key_id')!r} != '08F3E169207691F4'"
        )
    targets = info.get("updater_signed_targets")
    expected_targets = [
        "darwin-aarch64",
        "darwin-x86_64",
        "linux-x86_64",
        "windows-x86_64",
    ]
    if not isinstance(targets, list) or sorted(targets) != expected_targets:
        raise Reject(
            f"signing-status.json: updater_signed_targets {targets!r} != {expected_targets!r}"
        )
    platforms = info.get("platforms")
    if not isinstance(platforms, dict):
        raise Reject("signing-status.json: platforms must be a JSON object")
    for mac_p in ("macos-arm64", "macos-x64"):
        st = platforms.get(mac_p)
        if (
            not isinstance(st, dict)
            or st.get("signed") is not True
            or st.get("notarized") is not True
        ):
            raise Reject(
                f"signing-status.json: {mac_p} must be signed=True and notarized=True (got {st!r})"
            )


def check_desktop_sha256sums(
    directory: Path, version: str, *, product: str = "code"
) -> None:
    prefix, _, _ = _desktop_product_spec(product)
    sums_path = directory / "SHA256SUMS"
    if not sums_path.is_file() or sums_path.is_symlink():
        raise Reject("missing or not a regular file: SHA256SUMS")
    lines = [
        ln.strip()
        for ln in sums_path.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    if not lines:
        raise Reject("SHA256SUMS is empty")

    allowed = set(expected_desktop_assets(version, product=product)) - {"SHA256SUMS"}
    listed: dict[str, str] = {}
    for ln in lines:
        m = _SHA256SUMS_LINE_RE.fullmatch(ln)
        if not m:
            raise Reject(f"invalid SHA256SUMS line format: {ln!r}")
        digest, name = m.group(1), m.group(2)
        if name not in allowed:
            raise Reject(f"SHA256SUMS lists unexpected file {name!r}")
        if name in listed:
            raise Reject(f"duplicate entry in SHA256SUMS: {name!r}")
        listed[name] = digest

    v_parts = [int(p) for p in version.split(".")]
    v_tuple = (v_parts[0], v_parts[1], v_parts[2])

    baseline_10 = {
        f"{prefix}_{version}_aarch64.dmg",
        f"{prefix}_{version}_aarch64.app.tar.gz",
        f"{prefix}_{version}_x64.dmg",
        f"{prefix}_{version}_x64.app.tar.gz",
        f"{prefix}_{version}_x64-setup.exe",
        f"{prefix}_{version}_x64_en-US.msi",
        f"{prefix}_{version}_amd64.deb",
        f"{prefix}-{version}-1.x86_64.rpm",
        f"{prefix}_{version}_amd64.AppImage",
        "latest.json",
    }

    if v_tuple >= (0, 4, 67) or product == "one":
        if set(listed.keys()) != allowed:
            missing = sorted(allowed - set(listed.keys()))
            raise Reject(f"SHA256SUMS incomplete for v{version}: missing {missing!r}")
    else:
        if not baseline_10.issubset(set(listed.keys())):
            missing = sorted(baseline_10 - set(listed.keys()))
            raise Reject(
                f"SHA256SUMS incomplete for v{version}: missing baseline {missing!r}"
            )

    for name, expected_hash in listed.items():
        file_path = directory / name
        if not file_path.is_file():
            raise Reject(f"file listed in SHA256SUMS not found: {name}")
        h = hashlib.sha256()
        with file_path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        actual_hash = h.hexdigest()
        if actual_hash != expected_hash:
            raise Reject(
                f"SHA-256 hash mismatch for {name}: {actual_hash} != {expected_hash}"
            )


def check_desktop_assets(
    version: str,
    directory: Path,
    *,
    forbid_handle: str | None = None,
    product: str = "code",
) -> list[str]:
    names = expected_desktop_assets(version, product=product)
    notes_path = directory / "RELEASE_NOTES.md"
    if not notes_path.is_file() or notes_path.is_symlink():
        raise Reject("missing or not a regular file: RELEASE_NOTES.md")
    notes_data = notes_path.read_bytes()
    scan_bytes("RELEASE_NOTES.md", notes_data)

    text_files: list[str] = ["RELEASE_NOTES.md"]

    for name in names:
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise Reject(f"missing or not a regular file: {name}")
        data = path.read_bytes()
        if name.endswith((".json", ".md", ".txt", ".sig")) or name == "SHA256SUMS":
            text_files.append(name)
            scan_bytes(name, data)
        if name == "build-info.json":
            check_desktop_build_info(data, version, product=product)
        elif name == "latest.json":
            check_desktop_latest_manifest(data, version, product=product)
        elif name == "signing-status.json":
            check_desktop_signing_status(data, version, product=product)
        elif name.endswith(".sig"):
            if not data.strip():
                raise Reject(f"{name}: empty signature file")

    check_desktop_sha256sums(directory, version, product=product)

    if forbid_handle:
        handle_lower = forbid_handle.strip().lower()
        if handle_lower:
            handle_bytes = handle_lower.encode("utf-8")
            for tf_name in text_files:
                tf_data = (directory / tf_name).read_bytes().lower()
                if handle_bytes in tf_data:
                    raise Reject(
                        f"{tf_name}: contains forbidden source repository owner handle"
                    )

    return names


def check_desktop_release_json(
    version: str, json_path: Path, *, product: str = "code"
) -> None:
    _, tag_prefix, _ = _desktop_product_spec(product)
    try:
        release = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise Reject(f"desktop release JSON: invalid JSON: {exc}") from exc
    if not isinstance(release, dict):
        raise Reject("desktop release JSON: root must be a JSON object")

    expected_tag = f"{tag_prefix}{version}"
    tag_name = release.get("tag_name")
    if tag_name != expected_tag:
        raise Reject(f"desktop release tag_name {tag_name!r} != {expected_tag!r}")

    if release.get("draft") is not False:
        raise Reject(
            f"desktop release draft is not False (got {release.get('draft')!r})"
        )

    if release.get("prerelease") is not False:
        raise Reject(
            f"desktop release prerelease is not False (got {release.get('prerelease')!r})"
        )

    author = release.get("author") or {}
    author_login = author.get("login")
    if author_login != "github-actions[bot]":
        raise Reject(
            f"desktop release author {author_login!r} != 'github-actions[bot]'"
        )

    assets = release.get("assets")
    if not isinstance(assets, list):
        raise Reject("desktop release JSON: assets must be a list")

    names = [a.get("name") for a in assets if isinstance(a, dict)]
    if len(names) != len(set(names)):
        raise Reject("duplicate asset names in the desktop release")

    for a in assets:
        uploader = (a.get("uploader") or {}).get("login")
        if uploader != "github-actions[bot]":
            raise Reject(
                f"desktop release asset {a.get('name')!r} uploader {uploader!r} != 'github-actions[bot]'"
            )

    expected = set(expected_desktop_assets(version, product=product))
    extra = sorted(set(names) - expected)
    missing = sorted(expected - set(names))
    if extra or missing:
        raise Reject(
            f"desktop release assets differ: extra={extra!r} missing={missing!r}"
        )


# ── self-test ────────────────────────────────────────────────────────────────


def _build_base_library_zip(
    extra: dict[str, bytes] | None = None, *, deflated: bool = False
) -> bytes:
    buf = io.BytesIO()
    comp = zipfile.ZIP_DEFLATED if deflated else zipfile.ZIP_STORED
    with zipfile.ZipFile(buf, "w", compression=comp) as zf:
        zf.writestr("encodings/__init__.pyc", b"\xa7\r\r\nbytecode")
        zf.writestr("_collections_abc.pyc", b"\xa7\r\r\nbytecode")
        for k, v in (extra or {}).items():
            zf.writestr(k, v)
    return buf.getvalue()


def _write_valid_bundle(d: Path, version: str, *, onedir: bool = False) -> None:
    expected = expected_assets(version)
    for name in expected:
        if name == "build-info.json":
            (d / name).write_text(
                json.dumps(
                    {
                        "version": version,
                        "tag": f"v{version}",
                        "source_commit": "0123456789abcdef0123456789abcdef01234567",
                        "logo_png_64_sha256": "77a1e6a3b30ff30a26ad4484c9375812e57b7720e4e7bac39b95d7aa10229168",
                        "release": True,
                        "assets": expected,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        elif name.endswith(".json"):
            (d / name).write_text("{}", encoding="utf-8")
        elif not name.endswith((".tar.gz", ".zip")):
            (d / name).write_text("ok\n", encoding="utf-8")
    base_lib = _build_base_library_zip()
    for p in PLATFORMS:
        root = f"engra-{version}-{p}"
        exe = "engra.exe" if p.startswith("windows") else "engra"
        files: dict[str, bytes] = {
            exe: b"\x7fELF binary",
            "LICENSE.txt": b"l",
            "TERMS.md": b"t",
            "THIRD_PARTY_NOTICES.txt": b"n",
        }
        if onedir:
            files["_internal/certifi/cacert.pem"] = (
                b"-----BEGIN CERTIFICATE-----\nMIIB\n"
            )
            files["_internal/base_library.zip"] = base_lib
            if p.startswith("windows"):
                files["_internal/python311.dll"] = b"MZdll"
                files["_internal/_asyncio.pyd"] = b"MZpyd"
            elif p.startswith("macos"):
                files["_internal/libpython3.11.dylib"] = b"\xcf\xfa\xed\xfedylib"
                files["_internal/Python.framework/Versions/3.11/Python"] = b"macho"
                files["_internal/_cffi_backend.cpython-311-darwin.so"] = b"macho"
            else:
                files["_internal/libpython3.11.so.1.0"] = b"\x7fELFso"
                files["_internal/_cffi_backend.cpython-311-linux.so"] = b"\x7fELFso"
        if p.startswith("windows"):
            with zipfile.ZipFile(d / f"{root}.zip", "w") as zf:
                for n, data in files.items():
                    zf.writestr(f"{root}/{n}", data)
        else:
            with tarfile.open(d / f"{root}.tar.gz", "w:gz") as tf:
                if onedir:
                    for dir_rel in ("", "/_internal", "/_internal/certifi"):
                        dinfo = tarfile.TarInfo(f"{root}{dir_rel}")
                        dinfo.type = tarfile.DIRTYPE
                        dinfo.mode = 0o755
                        tf.addfile(dinfo)
                for n, data in files.items():
                    info = tarfile.TarInfo(f"{root}/{n}")
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))
                if onedir and p.startswith("macos"):
                    for link_rel, target in (
                        ("_internal/Python", "Python.framework/Versions/3.11/Python"),
                        (
                            "_internal/Python.framework/Versions/Current",
                            "3.11",
                        ),
                        (
                            "_internal/Python.framework/Python",
                            "Versions/Current/Python",
                        ),
                    ):
                        sinfo = tarfile.TarInfo(f"{root}/{link_rel}")
                        sinfo.type = tarfile.SYMTYPE
                        sinfo.linkname = target
                        tf.addfile(sinfo)


def _write_valid_desktop_bundle(
    d: Path, version: str, *, full_sums: bool = True, product: str = "code"
) -> None:
    prefix, tag_prefix, expected_product = _desktop_product_spec(product)
    expected = expected_desktop_assets(version, product=product)
    pub_date = "2026-11-25T12:00:00Z"
    expires_at = "2026-12-09T12:00:00Z"
    (d / "RELEASE_NOTES.md").write_text(
        f"# {prefix} Desktop v{version}\n\nNotes.\n", encoding="utf-8"
    )
    for name in expected:
        if name == "SHA256SUMS":
            continue
        elif name == "build-info.json":
            (d / name).write_text(
                json.dumps(
                    {
                        "product": expected_product,
                        "version": version,
                        "tag": f"{tag_prefix}{version}",
                        "source_commit": "0123456789abcdef0123456789abcdef01234567",
                        "release": True,
                        "built_at": pub_date,
                        "distribution": "arenberg-engineering/engra-releases",
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        elif name == "latest.json":
            (d / name).write_text(
                json.dumps(
                    {
                        "version": version,
                        "notes": "Engra Desktop",
                        "pub_date": pub_date,
                        "expires_at": expires_at,
                        "min_security_floor": "0.4.38",
                        "channel": "stable",
                        "platforms": {
                            "darwin-aarch64": {
                                "url": f"https://github.com/arenberg-engineering/engra-releases/releases/download/{tag_prefix}{version}/{prefix}_{version}_aarch64.app.tar.gz",
                                "signature": "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZwo=",
                            },
                            "darwin-x86_64": {
                                "url": f"https://github.com/arenberg-engineering/engra-releases/releases/download/{tag_prefix}{version}/{prefix}_{version}_x64.app.tar.gz",
                                "signature": "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZwo=",
                            },
                            "windows-x86_64": {
                                "url": f"https://github.com/arenberg-engineering/engra-releases/releases/download/{tag_prefix}{version}/{prefix}_{version}_x64-setup.exe",
                                "signature": "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZwo=",
                            },
                            "linux-x86_64": {
                                "url": f"https://github.com/arenberg-engineering/engra-releases/releases/download/{tag_prefix}{version}/{prefix}_{version}_amd64.AppImage",
                                "signature": "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZwo=",
                            },
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        elif name == "signing-status.json":
            (d / name).write_text(
                json.dumps(
                    {
                        "version": version,
                        "tag": f"{tag_prefix}{version}",
                        "updater_ed25519_key_id": "08F3E169207691F4",
                        "updater_signed_targets": [
                            "darwin-aarch64",
                            "darwin-x86_64",
                            "linux-x86_64",
                            "windows-x86_64",
                        ],
                        "platforms": {
                            "macos-arm64": {"signed": True, "notarized": True},
                            "macos-x64": {"signed": True, "notarized": True},
                            "windows-x64": {"signed": False, "notarized": False},
                            "linux-x64": {"signed": False, "notarized": False},
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
        elif name.endswith(".sig"):
            (d / name).write_text(
                "untrusted comment: minisign signature\nsig\ntrusted comment: version:0.4.66\nglobalsig\n",
                encoding="utf-8",
            )
        else:
            (d / name).write_bytes(b"installer binary stub\n")

    baseline_10 = [
        f"{prefix}_{version}_aarch64.dmg",
        f"{prefix}_{version}_aarch64.app.tar.gz",
        f"{prefix}_{version}_x64.dmg",
        f"{prefix}_{version}_x64.app.tar.gz",
        f"{prefix}_{version}_x64-setup.exe",
        f"{prefix}_{version}_x64_en-US.msi",
        f"{prefix}_{version}_amd64.deb",
        f"{prefix}-{version}-1.x86_64.rpm",
        f"{prefix}_{version}_amd64.AppImage",
        "latest.json",
    ]
    target_names = (
        [n for n in expected if n != "SHA256SUMS"] if full_sums else baseline_10
    )
    sum_lines = []
    for n in sorted(target_names):
        h = hashlib.sha256((d / n).read_bytes()).hexdigest()
        sum_lines.append(f"{h}  {n}")
    (d / "SHA256SUMS").write_text("\n".join(sum_lines) + "\n", encoding="utf-8")


def selftest() -> None:
    version = "0.2.0"
    fake_stripe = "sk_" + "live_" + "A1b2C3d4E5f6G7h8"  # built at runtime

    def must_fail(label: str, fn: object) -> None:
        try:
            fn()  # type: ignore[operator]
        except (
            Reject,
            OSError,
            ValueError,
            KeyError,
            tarfile.TarError,
            zipfile.BadZipFile,
        ) as exc:
            print(f"[selftest] rejected as expected: {label}: {exc}")
            return
        raise SystemExit(f"[selftest] FAIL: {label} was accepted")

    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        _write_valid_bundle(d, version)
        check_assets(version, d)
        print("[selftest] valid --onefile bundle accepted")

        # 1. A filename with an embedded newline (and other parser tricks).
        for name in (
            f"engra-{version}-macos-arm64.tar.gz\nevil.py",
            f"-engra-{version}-macos-arm64.tar.gz",
            f"engra-{version}-macos-arm64.tar.gz.py",
        ):
            rel = {
                "assets": [{"name": n} for n in expected_assets(version)]
                + [{"name": name}]
            }
            (d / "rel.json").write_text(json.dumps(rel))
            must_fail(
                f"release asset {name!r}",
                lambda: check_release_json(version, d / "rel.json"),
            )
        # 2. An allowlist bypass via a lookalike name (Cyrillic 'о' in macos).
        lookalike = f"engra-{version}-macоs-arm64.tar.gz"
        names = [
            n
            for n in expected_assets(version)
            if n != f"engra-{version}-macos-arm64.tar.gz"
        ]
        rel = {"assets": [{"name": n} for n in [*names, lookalike]]}
        (d / "rel.json").write_text(json.dumps(rel))
        must_fail(
            "unicode lookalike asset name",
            lambda: check_release_json(version, d / "rel.json"),
        )

        # 3. A disallowed file hidden inside a zip, and inside a tar.gz.
        good_zip = (d / f"engra-{version}-windows-x64.zip").read_bytes()
        with zipfile.ZipFile(d / f"engra-{version}-windows-x64.zip", "a") as zf:
            zf.writestr(f"engra-{version}-windows-x64/backend/app.py", b"print('src')")
        must_fail("hidden .py inside the zip", lambda: check_assets(version, d))
        (d / f"engra-{version}-windows-x64.zip").write_bytes(good_zip)
        tar_path = d / f"engra-{version}-linux-x64.tar.gz"
        good_tar = tar_path.read_bytes()
        with tarfile.open(tar_path, "w:gz") as tf:
            for n, data in {
                "engra": b"bin",
                "LICENSE.txt": b"l",
                "TERMS.md": b"t",
                "THIRD_PARTY_NOTICES.txt": b"n",
                ".env": b"SECRET=1",
            }.items():
                info = tarfile.TarInfo(f"engra-{version}-linux-x64/{n}")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        must_fail("hidden .env inside the tar.gz", lambda: check_assets(version, d))
        tar_path.write_bytes(good_tar)

        # 4. A secret inside an allowed archive member.
        with zipfile.ZipFile(d / f"engra-{version}-windows-x64.zip", "w") as zf:
            root = f"engra-{version}-windows-x64"
            zf.writestr(f"{root}/engra.exe", b"bin")
            zf.writestr(f"{root}/LICENSE.txt", b"l")
            zf.writestr(f"{root}/TERMS.md", ("key " + fake_stripe).encode())
            zf.writestr(f"{root}/THIRD_PARTY_NOTICES.txt", b"n")
        must_fail("secret inside an archive member", lambda: check_assets(version, d))
        (d / f"engra-{version}-windows-x64.zip").write_bytes(good_zip)

        # 5. A fake sk_live_ string in the README of the repository.
        repo = d / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (repo / "README.md").write_text(f"Use {fake_stripe} to pay.\n")
        subprocess.run(["git", "-C", str(repo), "add", "--", "README.md"], check=True)
        must_fail("sk_live_ in README.md", lambda: check_repo(repo))
        # 6. A tracked filename with an embedded newline in the repository.
        (repo / "README.md").write_text("clean\n")
        odd = repo / "notes\nREADME.md"
        odd.write_text("x")
        subprocess.run(["git", "-C", str(repo), "add", "--", odd.name], check=True)
        must_fail("tracked filename with a newline", lambda: check_repo(repo))
        # 7. A GCP service-account key committed as JSON.
        subprocess.run(
            ["git", "-C", str(repo), "rm", "-q", "--cached", "--", odd.name], check=True
        )
        sa = '{"type": "service_account", "private_key_id": "x"}'
        (repo / "TERMS.md").write_text(sa)
        subprocess.run(["git", "-C", str(repo), "add", "--", "TERMS.md"], check=True)
        must_fail("service-account JSON in TERMS.md", lambda: check_repo(repo))
        # 8. Rule parity with the former shell check: every pattern it had
        #    (and the narrower-looking variants) is still caught, including
        #    inside a longer word.
        samples = {
            "private key": "-----BEGIN " + "RSA PRIVATE KEY-----",
            "github": "x" + "ghp_" + "a" * 36,
            "github pat": "github_pat_" + "b" * 50,
            "aws": "x" + "AKIA" + "ABCDEFGHIJKLMNOP" + "Q",
            "google": "x" + "AIza" + "c" * 35,
            "slack": "xox" + "b-" + "1234567890ab",
            "stripe": "x" + "sk_" + "live_" + "d" * 12,
            "cloud run": "https://svc-123" + ".run.app/x",
            "internal": "db.corp" + ".internal",
            "metadata": "metadata.google" + ".internal",
            "project": "engra" + "-prod",
            "loopback": "http://127.0.0.1" + ":8099/v1",
        }
        for label, text in samples.items():
            must_fail(
                f"pattern parity: {label}",
                lambda t=text: scan_bytes("sample", t.encode()),
            )

        # 9. The real CI entrypoints, run as CI runs them, exit non-zero on a
        #    deliberately bad tree and a deliberately bad bundle.
        script = str(Path(__file__).resolve())
        bad_repo = d / "bad-repo"
        bad_repo.mkdir()
        subprocess.run(["git", "init", "-q", str(bad_repo)], check=True)
        (bad_repo / "README.md").write_text("ok\n")
        (bad_repo / "server.py").write_text("import os\n")
        subprocess.run(["git", "-C", str(bad_repo), "add", "--", "."], check=True)
        rc = subprocess.run(
            [sys.executable, script, "repo"], cwd=bad_repo, check=False
        ).returncode
        if rc == 0:
            raise SystemExit(
                "[selftest] FAIL: `repo` entrypoint accepted a tree with server.py"
            )
        print(f"[selftest] `repo` entrypoint exits {rc} on a bad tree")
        (d / "SHA256SUMS").unlink()
        rc = subprocess.run(
            [sys.executable, script, "assets", "--version", version, "--dir", str(d)],
            check=False,
        ).returncode
        if rc == 0:
            raise SystemExit(
                "[selftest] FAIL: `assets` entrypoint accepted a bundle missing SHA256SUMS"
            )
        print(f"[selftest] `assets` entrypoint exits {rc} on a bad bundle")
        (d / "broken.json").write_text("{not json")
        rc = subprocess.run(
            [
                sys.executable,
                script,
                "release",
                "--version",
                version,
                "--json",
                str(d / "broken.json"),
            ],
            check=False,
        ).returncode
        if rc == 0:
            raise SystemExit(
                "[selftest] FAIL: `release` entrypoint accepted unparsable JSON"
            )
        print(f"[selftest] `release` entrypoint exits {rc} on unparsable JSON")

        # 10. PyInstaller --onedir bundle acceptance and bypass rejections.
        onedir_v = "0.2.1"
        od = d / "onedir"
        od.mkdir()
        _write_valid_bundle(od, onedir_v, onedir=True)
        check_assets(onedir_v, od)
        print("[selftest] valid --onedir bundle accepted")

        win_zip = od / f"engra-{onedir_v}-windows-x64.zip"
        good_win_zip = win_zip.read_bytes()
        mac_tar = od / f"engra-{onedir_v}-macos-arm64.tar.gz"
        good_mac_tar = mac_tar.read_bytes()
        win_root = f"engra-{onedir_v}-windows-x64"
        mac_root = f"engra-{onedir_v}-macos-arm64"

        def _write_mac_tar_extra(
            extra_files: dict[str, bytes] | None = None,
            extra_links: list[tuple[str, str, bytes]] | None = None,
        ) -> None:
            with tarfile.open(mac_tar, "w:gz") as tf:
                for n, data in {
                    "engra": b"macho",
                    "LICENSE.txt": b"l",
                    "TERMS.md": b"t",
                    "THIRD_PARTY_NOTICES.txt": b"n",
                    "_internal/libpython3.11.dylib": b"dylib",
                    "_internal/base_library.zip": _build_base_library_zip(),
                    **(extra_files or {}),
                }.items():
                    info = tarfile.TarInfo(f"{mac_root}/{n}")
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))
                for rel_name, target, ltype in extra_links or []:
                    sinfo = tarfile.TarInfo(f"{mac_root}/{rel_name}")
                    sinfo.type = ltype
                    sinfo.linkname = target
                    tf.addfile(sinfo)

        # (b) .py source file inside _internal/ -> rejected.
        with zipfile.ZipFile(win_zip, "a") as zf:
            zf.writestr(f"{win_root}/_internal/leak.py", b"print('leak')\n")
        must_fail(".py inside _internal/", lambda: check_assets(onedir_v, od))
        win_zip.write_bytes(good_win_zip)

        # (c) .env dotfile inside _internal/ -> rejected.
        _write_mac_tar_extra(extra_files={"_internal/.env": b"KEY=1\n"})
        must_fail(".env dotfile inside _internal/", lambda: check_assets(onedir_v, od))
        mac_tar.write_bytes(good_mac_tar)

        # (d) Secret inside _internal/ regular file -> rejected.
        _write_mac_tar_extra(
            extra_files={"_internal/config.json": ("x " + fake_stripe).encode()}
        )
        must_fail("secret inside _internal/ file", lambda: check_assets(onedir_v, od))
        mac_tar.write_bytes(good_mac_tar)

        # (e) Secret or .py or traversal hidden inside nested _internal/base_library.zip -> rejected.
        _write_mac_tar_extra(
            extra_files={
                "_internal/base_library.zip": _build_base_library_zip(
                    {"pkg/secret.pyc": (("tok=" + fake_stripe + "\n") * 8).encode()},
                    deflated=True,
                )
            }
        )
        must_fail(
            "secret inside nested base_library.zip", lambda: check_assets(onedir_v, od)
        )
        _write_mac_tar_extra(
            extra_files={
                "_internal/base_library.zip": _build_base_library_zip(
                    {"pkg/mod.py": b"x = 1\n"}
                )
            }
        )
        must_fail(
            ".py inside nested base_library.zip", lambda: check_assets(onedir_v, od)
        )
        _write_mac_tar_extra(
            extra_files={
                "_internal/base_library.zip": _build_base_library_zip(
                    {"../escape.pyc": b"\xa7\r\r\n"}
                )
            }
        )
        must_fail(
            ".. traversal inside nested base_library.zip",
            lambda: check_assets(onedir_v, od),
        )
        mac_tar.write_bytes(good_mac_tar)

        # (f) Symlink at top level ({root}/evil and {root}/engra) -> rejected.
        _write_mac_tar_extra(
            extra_links=[("evil", "_internal/libpython3.11.dylib", tarfile.SYMTYPE)]
        )
        must_fail("symlink at top level (evil)", lambda: check_assets(onedir_v, od))
        with tarfile.open(mac_tar, "w:gz") as tf:
            for n, data in {
                "LICENSE.txt": b"l",
                "TERMS.md": b"t",
                "THIRD_PARTY_NOTICES.txt": b"n",
                "_internal/engra_bin": b"macho",
            }.items():
                info = tarfile.TarInfo(f"{mac_root}/{n}")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            sinfo = tarfile.TarInfo(f"{mac_root}/engra")
            sinfo.type = tarfile.SYMTYPE
            sinfo.linkname = "_internal/engra_bin"
            tf.addfile(sinfo)
        must_fail("top-level exe as symlink", lambda: check_assets(onedir_v, od))
        mac_tar.write_bytes(good_mac_tar)

        # (g) Symlink inside _internal/ escaping _internal/ (relative, absolute, or out-and-back) -> rejected.
        for bad_target in (
            "../../etc/passwd",
            "/etc/passwd",
            "../engra",
            f"../../{mac_root}/_internal/libpython3.11.dylib",
        ):
            _write_mac_tar_extra(
                extra_links=[("_internal/escape", bad_target, tarfile.SYMTYPE)]
            )
            must_fail(
                f"escaping _internal/ symlink ({bad_target})",
                lambda: check_assets(onedir_v, od),
            )
        _write_mac_tar_extra(
            extra_links=[
                (
                    "_internal/hardlink",
                    f"{mac_root}/_internal/libpython3.11.dylib",
                    tarfile.LNKTYPE,
                )
            ]
        )
        must_fail("hardlink inside _internal/", lambda: check_assets(onedir_v, od))
        mac_tar.write_bytes(good_mac_tar)

        # (h) Symlink entry inside Windows .zip -> rejected.
        with zipfile.ZipFile(win_zip, "a") as zf:
            zinfo = zipfile.ZipInfo(f"{win_root}/_internal/sym")
            zinfo.create_system = 3
            zinfo.external_attr = 0o120777 << 16
            zf.writestr(zinfo, "python311.dll")
        must_fail("symlink inside Windows .zip", lambda: check_assets(onedir_v, od))
        win_zip.write_bytes(good_win_zip)

        # 11. build-info.json presence, schema, commit-hash, and asset-set integrity.
        bi_path = od / "build-info.json"
        good_bi = bi_path.read_bytes()
        bi_path.unlink()
        must_fail("missing build-info.json", lambda: check_assets(onedir_v, od))
        for bad_label, bad_patch in (
            ("wrong version", {"version": "9.9.9"}),
            ("wrong tag", {"tag": "v9.9.9"}),
            ("non-40-hex source_commit", {"source_commit": "development"}),
            (
                "missing asset in build-info.json",
                {"assets": expected_assets(onedir_v)[:-1]},
            ),
        ):
            patched = json.loads(good_bi)
            patched.update(bad_patch)
            bi_path.write_text(json.dumps(patched), encoding="utf-8")
            must_fail(
                f"build-info.json ({bad_label})", lambda: check_assets(onedir_v, od)
            )
        bi_path.write_bytes(good_bi)
        check_assets(onedir_v, od)
        # 12. Desktop bundle and release validation checks.
        # (a) Minisign public key endianness check.
        pinned_pub_b64 = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDA4RjNFMTY5MjA3NjkxRjQKUldUMGtYWWdhZUh6Q05YTmhSUHF2V1JqMHJLby85WjdodDE5WmxWUDRjcmdUQnNJVi80UWlNREwK"
        pub_text = base64.b64decode(pinned_pub_b64).decode("utf-8")
        pub_raw = base64.b64decode(pub_text.splitlines()[1].strip())
        keynum = pub_raw[2:10]
        if keynum[::-1].hex().upper() != "08F3E169207691F4":
            raise SystemExit(
                f"[selftest] Minisign little-endian Key ID mismatch: {keynum[::-1].hex().upper()} != 08F3E169207691F4"
            )
        print("[selftest] Minisign little-endian Key ID verified (08F3E169207691F4)")

        # (b) Valid v0.4.66 10-entry bundle accepted.
        v66 = "0.4.66"
        dd66 = d / "desktop66"
        dd66.mkdir()
        _write_valid_desktop_bundle(dd66, v66, full_sums=False)
        check_desktop_assets(v66, dd66, forbid_handle="someone")
        print("[selftest] valid v0.4.66 10-entry desktop bundle accepted")

        # (c) Valid v0.4.67 16-entry bundle accepted.
        desk_v = "0.4.67"
        dd = d / "desktop"
        dd.mkdir()
        _write_valid_desktop_bundle(dd, desk_v, full_sums=True)
        check_desktop_assets(desk_v, dd, forbid_handle="someone")
        print("[selftest] valid v0.4.67 16-entry desktop bundle accepted")

        # (d) v0.4.67 bundle with 10-entry SHA256SUMS -> rejected (16-entry required).
        dd67_incomplete = d / "desktop67_incomplete"
        dd67_incomplete.mkdir()
        _write_valid_desktop_bundle(dd67_incomplete, desk_v, full_sums=False)
        must_fail(
            "incomplete SHA256SUMS for v0.4.67+",
            lambda: check_desktop_assets(desk_v, dd67_incomplete),
        )

        # (e) Path traversal in SHA256SUMS -> rejected.
        good_sums = (dd / "SHA256SUMS").read_bytes()
        (dd / "SHA256SUMS").write_text(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  ../evil\n",
            encoding="utf-8",
        )
        must_fail(
            "path traversal in SHA256SUMS",
            lambda: check_desktop_assets(desk_v, dd),
        )
        (dd / "SHA256SUMS").write_bytes(good_sums)

        # (f) Checksum mismatch in SHA256SUMS -> rejected.
        (dd / "SHA256SUMS").write_text(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  latest.json\n",
            encoding="utf-8",
        )
        must_fail(
            "checksum mismatch in SHA256SUMS",
            lambda: check_desktop_assets(desk_v, dd),
        )
        (dd / "SHA256SUMS").write_bytes(good_sums)

        # (g) Missing RELEASE_NOTES.md -> rejected.
        (dd / "RELEASE_NOTES.md").unlink()
        must_fail(
            "missing RELEASE_NOTES.md in desktop bundle",
            lambda: check_desktop_assets(desk_v, dd),
        )
        (dd / "RELEASE_NOTES.md").write_text("# Notes\n", encoding="utf-8")

        # (h) Secret in RELEASE_NOTES.md -> rejected.
        (dd / "RELEASE_NOTES.md").write_text(f"Key: {fake_stripe}\n", encoding="utf-8")
        must_fail(
            "secret in RELEASE_NOTES.md",
            lambda: check_desktop_assets(desk_v, dd),
        )
        (dd / "RELEASE_NOTES.md").write_text("# Notes\n", encoding="utf-8")

        # (i) Secret in latest.json -> rejected.
        good_latest = (dd / "latest.json").read_bytes()
        (dd / "latest.json").write_text(
            json.dumps({"version": desk_v, "notes": fake_stripe}),
            encoding="utf-8",
        )
        must_fail(
            "secret in latest.json",
            lambda: check_desktop_assets(desk_v, dd),
        )
        (dd / "latest.json").write_bytes(good_latest)

        # (j) Wrong platform URL in latest.json -> rejected.
        bad_latest_url = json.loads(good_latest)
        bad_latest_url["platforms"]["darwin-aarch64"]["url"] = (
            "https://evil.com/Engra.dmg"
        )
        (dd / "latest.json").write_text(json.dumps(bad_latest_url), encoding="utf-8")
        must_fail(
            "wrong platform URL in latest.json",
            lambda: check_desktop_assets(desk_v, dd),
        )
        (dd / "latest.json").write_bytes(good_latest)

        # (k) Forbidden handle in build-info.json -> rejected when forbid_handle passed.
        good_bi_desk = (dd / "build-info.json").read_bytes()
        bad_bi = json.loads(good_bi_desk)
        bad_bi["maintainer"] = "forbidden_user"
        (dd / "build-info.json").write_text(json.dumps(bad_bi), encoding="utf-8")
        must_fail(
            "forbidden handle in build-info.json",
            lambda: check_desktop_assets(desk_v, dd, forbid_handle="forbidden_user"),
        )
        (dd / "build-info.json").write_bytes(good_bi_desk)

        # (l) Invalid product in build-info.json -> rejected.
        bad_bi = json.loads(good_bi_desk)
        bad_bi["product"] = "engra-cli"
        (dd / "build-info.json").write_text(json.dumps(bad_bi), encoding="utf-8")
        must_fail(
            "wrong product in desktop build-info.json",
            lambda: check_desktop_assets(desk_v, dd),
        )
        (dd / "build-info.json").write_bytes(good_bi_desk)

        # (m) release: False in build-info.json -> rejected.
        bad_bi = json.loads(good_bi_desk)
        bad_bi["release"] = False
        (dd / "build-info.json").write_text(json.dumps(bad_bi), encoding="utf-8")
        must_fail(
            "release: False in desktop build-info.json",
            lambda: check_desktop_assets(desk_v, dd),
        )
        (dd / "build-info.json").write_bytes(good_bi_desk)

        # (n) Unsigned macOS in signing-status.json -> rejected.
        good_ss = (dd / "signing-status.json").read_bytes()
        bad_ss = json.loads(good_ss)
        bad_ss["platforms"]["macos-arm64"]["signed"] = False
        (dd / "signing-status.json").write_text(json.dumps(bad_ss), encoding="utf-8")
        must_fail(
            "unsigned macOS in signing-status.json",
            lambda: check_desktop_assets(desk_v, dd),
        )
        (dd / "signing-status.json").write_bytes(good_ss)

        # (o) Missing target platform in latest.json -> rejected.
        bad_latest = json.loads(good_latest)
        del bad_latest["platforms"]["darwin-aarch64"]
        (dd / "latest.json").write_text(json.dumps(bad_latest), encoding="utf-8")
        must_fail(
            "missing platform target in latest.json",
            lambda: check_desktop_assets(desk_v, dd),
        )
        (dd / "latest.json").write_bytes(good_latest)

        # (p) Empty signature file -> rejected.
        sig_file = dd / f"Engra_{desk_v}_aarch64.app.tar.gz.sig"
        good_sig = sig_file.read_bytes()
        sig_file.write_text("   \n", encoding="utf-8")
        must_fail(
            "empty signature file",
            lambda: check_desktop_assets(desk_v, dd),
        )
        sig_file.write_bytes(good_sig)

        # (q) Valid desktop release JSON -> accepted.
        expected_desk = expected_desktop_assets(desk_v)
        valid_rel = {
            "tag_name": f"desktop-v{desk_v}",
            "draft": False,
            "prerelease": False,
            "author": {"login": "github-actions[bot]"},
            "assets": [
                {"name": n, "uploader": {"login": "github-actions[bot]"}}
                for n in expected_desk
            ],
        }
        (dd / "rel.json").write_text(json.dumps(valid_rel), encoding="utf-8")
        check_desktop_release_json(desk_v, dd / "rel.json")
        print("[selftest] valid desktop release JSON accepted")

        # (r) Release JSON with wrong tag / draft / prerelease / author / uploader / extra / missing.
        for bad_label, bad_rel_patch in (
            ("wrong tag", {"tag_name": f"v{desk_v}"}),
            ("draft release", {"draft": True}),
            ("prerelease", {"prerelease": True}),
            ("human author", {"author": {"login": "someone"}}),
            (
                "human uploader",
                {
                    "assets": [
                        {"name": expected_desk[0], "uploader": {"login": "someone"}}
                    ]
                    + [
                        {"name": n, "uploader": {"login": "github-actions[bot]"}}
                        for n in expected_desk[1:]
                    ]
                },
            ),
            (
                "missing asset",
                {
                    "assets": [
                        {"name": n, "uploader": {"login": "github-actions[bot]"}}
                        for n in expected_desk[:-1]
                    ]
                },
            ),
            (
                "extra asset",
                {
                    "assets": [
                        {"name": n, "uploader": {"login": "github-actions[bot]"}}
                        for n in [*expected_desk, "extra.dmg"]
                    ]
                },
            ),
        ):
            patched_rel = dict(valid_rel)
            patched_rel.update(bad_rel_patch)
            (dd / "bad_rel.json").write_text(json.dumps(patched_rel), encoding="utf-8")
            must_fail(
                f"desktop release JSON ({bad_label})",
                lambda: check_desktop_release_json(desk_v, dd / "bad_rel.json"),
            )

        # (s) Valid Engra One Desktop bundle & release JSON -> accepted, cross-product rejected.
        one_v = "0.4.71"
        dd_one = d / "one_desktop"
        dd_one.mkdir()
        _write_valid_desktop_bundle(dd_one, one_v, full_sums=True, product="one")
        check_desktop_assets(one_v, dd_one, forbid_handle="someone", product="one")
        must_fail(
            "one-desktop bundle checked as code product",
            lambda: check_desktop_assets(one_v, dd_one, product="code"),
        )
        expected_one = expected_desktop_assets(one_v, product="one")
        valid_one_rel = {
            "tag_name": f"one-desktop-v{one_v}",
            "draft": False,
            "prerelease": False,
            "author": {"login": "github-actions[bot]"},
            "assets": [
                {"name": n, "uploader": {"login": "github-actions[bot]"}}
                for n in expected_one
            ],
        }
        (dd_one / "rel.json").write_text(json.dumps(valid_one_rel), encoding="utf-8")
        check_desktop_release_json(one_v, dd_one / "rel.json", product="one")
        must_fail(
            "one-desktop release JSON checked as code product",
            lambda: check_desktop_release_json(
                one_v, dd_one / "rel.json", product="code"
            ),
        )
        print("[selftest] valid Engra One Desktop bundle & release JSON accepted")
    print("[selftest] OK")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check_distribution")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("repo")
    a = sub.add_parser("assets")
    a.add_argument("--version", required=True)
    a.add_argument("--dir", required=True)
    a.add_argument("--print0", help="write the NUL-separated asset paths here")
    r = sub.add_parser("release")
    r.add_argument("--version", required=True)
    r.add_argument("--json", required=True)
    da = sub.add_parser("desktop-assets")
    da.add_argument("--version", required=True)
    da.add_argument("--dir", required=True)
    da.add_argument("--print0", help="write the NUL-separated asset paths here")
    da.add_argument("--forbid-handle", help="forbidden source repository owner handle")
    da.add_argument("--product", choices=("code", "one"), default="code")
    dr = sub.add_parser("desktop-release")
    dr.add_argument("--version", required=True)
    dr.add_argument("--json", required=True)
    dr.add_argument("--product", choices=("code", "one"), default="code")
    sub.add_parser("selftest")
    args = parser.parse_args(argv)
    try:
        if args.command == "repo":
            check_repo(Path.cwd())
            print("[check] repository holds distribution files only, no secrets")
        elif args.command == "assets":
            directory = Path(args.dir)
            names = check_assets(args.version, directory)
            if args.print0:
                Path(args.print0).write_bytes(
                    b"".join(str(directory / n).encode() + b"\0" for n in names)
                )
            print(f"[check] {len(names)} release assets for {args.version} are clean")
        elif args.command == "release":
            check_release_json(args.version, Path(args.json))
            print(
                f"[check] published release holds exactly the {args.version} asset set"
            )
        elif args.command == "desktop-assets":
            directory = Path(args.dir)
            names = check_desktop_assets(
                args.version,
                directory,
                forbid_handle=args.forbid_handle,
                product=args.product,
            )
            if args.print0:
                Path(args.print0).write_bytes(
                    b"".join(str(directory / n).encode() + b"\0" for n in names)
                )
            print(
                f"[check] {len(names)} desktop release assets ({args.product}) for {args.version} are clean"
            )
        elif args.command == "desktop-release":
            check_desktop_release_json(
                args.version, Path(args.json), product=args.product
            )
            print(
                f"[check] published desktop release ({args.product}) holds exactly the {args.version} asset set"
            )
        else:
            selftest()
    except Reject as exc:
        print(f"::error::[check] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - fail closed on any parse or tool error
        print(f"::error::[check] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
