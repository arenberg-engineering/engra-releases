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
  * archives must hold exactly ``engra-V-<platform>/{engra|engra.exe,
    LICENSE.txt, TERMS.md, THIRD_PARTY_NOTICES.txt}``: no other members, links,
    absolute paths or ``..``; so ``.py`` source, ``.env``, keys and ``.pem``
    files cannot hide inside;
  * every file and archive member is scanned for credential patterns and
    internal endpoints.
"""

from __future__ import annotations

import argparse
import io
import json
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
SINGLES = ("LICENSE.txt", "TERMS.md", "SHA256SUMS", "signing-status.json")
VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII)

# Files the repository itself may track (exact paths).
REPO_ALLOWED = frozenset(
    {
        "README.md",
        "LICENSE.txt",
        "TERMS.md",
        ".github/dependabot.yml",
        ".github/workflows/publish.yml",
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


def _check_member_name(archive: str, name: str, root: str, exe: str) -> None:
    allowed = {
        root + "/",
        root,
        *(f"{root}/{n}" for n in (exe, *LEGAL, "THIRD_PARTY_NOTICES.txt")),
    }
    if name not in allowed:
        raise Reject(f"{archive}: unexpected member {name!r}")


def check_archive(path: Path, version: str, platform: str) -> None:
    root = f"engra-{version}-{platform}"
    exe = "engra.exe" if platform.startswith("windows") else "engra"
    want = {f"{root}/{n}" for n in (exe, *LEGAL, "THIRD_PARTY_NOTICES.txt")}
    seen: set[str] = set()
    if path.name.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                _check_member_name(path.name, info.filename, root, exe)
                if info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0o170000
                if mode not in (0, 0o100000):
                    raise Reject(
                        f"{path.name}: {info.filename!r} is not a regular file"
                    )
                seen.add(info.filename)
                scan_bytes(f"{path.name}:{info.filename}", zf.read(info))
    else:
        with tarfile.open(path, mode="r:gz") as tf:
            for member in tf.getmembers():
                _check_member_name(path.name, member.name, root, exe)
                if member.isdir():
                    continue
                if not member.isfile():
                    raise Reject(f"{path.name}: {member.name!r} is not a regular file")
                seen.add(member.name)
                fh = tf.extractfile(member)
                if fh is None:
                    raise Reject(f"{path.name}: cannot read {member.name!r}")
                scan_bytes(f"{path.name}:{member.name}", fh.read())
    if seen != want:
        raise Reject(f"{path.name}: members {sorted(seen)} != {sorted(want)}")


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


# ── self-test ────────────────────────────────────────────────────────────────


def _write_valid_bundle(d: Path, version: str) -> None:
    for name in expected_assets(version):
        if name.endswith(".json"):
            (d / name).write_text("{}", encoding="utf-8")
        elif not name.endswith((".tar.gz", ".zip")):
            (d / name).write_text("ok\n", encoding="utf-8")
    for p in PLATFORMS:
        root = f"engra-{version}-{p}"
        exe = "engra.exe" if p.startswith("windows") else "engra"
        files = {
            exe: b"\x7fELF binary",
            "LICENSE.txt": b"l",
            "TERMS.md": b"t",
            "THIRD_PARTY_NOTICES.txt": b"n",
        }
        if p.startswith("windows"):
            with zipfile.ZipFile(d / f"{root}.zip", "w") as zf:
                for n, data in files.items():
                    zf.writestr(f"{root}/{n}", data)
        else:
            with tarfile.open(d / f"{root}.tar.gz", "w:gz") as tf:
                for n, data in files.items():
                    info = tarfile.TarInfo(f"{root}/{n}")
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))


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
        print("[selftest] valid bundle accepted")

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
            must_fail(f"pattern parity: {label}", lambda t=text: scan_bytes("sample", t.encode()))

        # 9. The real CI entrypoints, run as CI runs them, exit non-zero on a
        #    deliberately bad tree and a deliberately bad bundle.
        script = str(Path(__file__).resolve())
        bad_repo = d / "bad-repo"
        bad_repo.mkdir()
        subprocess.run(["git", "init", "-q", str(bad_repo)], check=True)
        (bad_repo / "README.md").write_text("ok\n")
        (bad_repo / "server.py").write_text("import os\n")
        subprocess.run(["git", "-C", str(bad_repo), "add", "--", "."], check=True)
        rc = subprocess.run([sys.executable, script, "repo"], cwd=bad_repo, check=False).returncode
        if rc == 0:
            raise SystemExit("[selftest] FAIL: `repo` entrypoint accepted a tree with server.py")
        print(f"[selftest] `repo` entrypoint exits {rc} on a bad tree")
        (d / "SHA256SUMS").unlink()
        rc = subprocess.run(
            [sys.executable, script, "assets", "--version", version, "--dir", str(d)],
            check=False,
        ).returncode
        if rc == 0:
            raise SystemExit("[selftest] FAIL: `assets` entrypoint accepted a bundle missing SHA256SUMS")
        print(f"[selftest] `assets` entrypoint exits {rc} on a bad bundle")
        (d / "broken.json").write_text("{not json")
        rc = subprocess.run(
            [sys.executable, script, "release", "--version", version, "--json", str(d / "broken.json")],
            check=False,
        ).returncode
        if rc == 0:
            raise SystemExit("[selftest] FAIL: `release` entrypoint accepted unparsable JSON")
        print(f"[selftest] `release` entrypoint exits {rc} on unparsable JSON")
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
