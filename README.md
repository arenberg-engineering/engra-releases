# Engra Releases

Official distribution of the Engra CLI: signed release archives, checksums,
SBOMs, license files and provenance. CI builds, signs and tests every release
here. The [`publish`](.github/workflows/publish.yml) workflow publishes it
after a maintainer approves.

This repository holds distribution material only. The
[`content-check`](.github/workflows/content-check.yml) workflow fails on
anything else.

## License

The Engra CLI is proprietary software of Arenberg AG. See
[LICENSE.txt](LICENSE.txt) and the Engra CLI Terms of Use,
[TERMS.md](TERMS.md) (**DRAFT**, pending owner and legal review). Each
release lists its open-source components and their licenses in
`THIRD_PARTY_NOTICES-<platform>.txt`. Run `engra legal --third-party` to see
them.

## Install

### macOS and Linux (Homebrew)

```bash
brew install arenberg-engineering/tap/engra
engra --version
```

The fully qualified name taps `arenberg-engineering/tap` and trusts the
formula, as Homebrew 6 requires for third-party taps. Update with
`brew upgrade engra`.

### Linux without Homebrew

```bash
VERSION=0.2.1
ARCH=x64                     # or arm64
BASE=https://github.com/arenberg-engineering/engra-releases/releases/download/v$VERSION
curl -fLO "$BASE/engra-$VERSION-linux-$ARCH.tar.gz"
curl -fLO "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf "engra-$VERSION-linux-$ARCH.tar.gz"
mkdir -p ~/.local/lib ~/.local/bin
rm -rf ~/.local/lib/engra
mv "engra-$VERSION-linux-$ARCH" ~/.local/lib/engra
ln -sf ~/.local/lib/engra/engra ~/.local/bin/engra
```

Keep the extracted directory (including `_internal/`) intact in
`~/.local/lib/engra` and ensure `~/.local/bin` is on your `PATH`. The Linux
builds need glibc 2.35 or newer.

### Windows

1. Download `engra-<version>-windows-x64.zip` and `SHA256SUMS` from the
   [latest release](https://github.com/arenberg-engineering/engra-releases/releases/latest).
2. Check the zip's hash:
   `(Get-FileHash .\engra-<version>-windows-x64.zip -Algorithm SHA256).Hash.ToLower()`.
   It must match the zip's line in `SHA256SUMS`.
3. Unpack it. The archive holds the folder `engra-<version>-windows-x64\`,
   which contains `engra.exe`. Put that folder on your `PATH`, then run
   `engra --version`.

Each release's notes say whether the Windows build is Authenticode-signed.

## Check a download

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing        # sha256sum on Linux
gh attestation verify engra-<version>-macos-arm64.tar.gz --repo arenberg-engineering/engra-releases
tar -xzf engra-<version>-macos-arm64.tar.gz
spctl --assess --type install -vvv engra-<version>-macos-arm64/engra   # Notarized Developer ID
```

## Uninstall

```bash
engra logout                 # revokes the session and removes saved tokens
brew uninstall engra
brew untap arenberg-engineering/tap
rm -rf ~/.local/lib/engra ~/.local/bin/engra   # if installed manually on Linux
rm -rf ~/.config/engra ~/.engra   # optional: settings and doctor records
```
