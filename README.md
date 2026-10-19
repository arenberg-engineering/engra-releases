# Engra Releases

Official release distribution for the Engra CLI: signed binaries, checksums,
SBOMs and provenance. Every release here is built, signed and tested by CI,
then published by the [`publish`](.github/workflows/publish.yml) workflow after
a maintainer approves it.

## Install

### macOS and Linux (Homebrew)

```bash
brew tap arenberg-engineering/tap
brew install engra
engra --version
```

Update with `brew upgrade engra`.

### Linux without Homebrew

```bash
VERSION=0.2.0
ARCH=x64                     # or arm64
BASE=https://github.com/arenberg-engineering/engra-releases/releases/download/v$VERSION
curl -fLO "$BASE/engra-$VERSION-linux-$ARCH"
curl -fLO "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
install -m 755 "engra-$VERSION-linux-$ARCH" ~/.local/bin/engra
```

The Linux builds need glibc 2.35 or newer.

### Windows

1. Download `engra-<version>-windows-x64.zip` and `SHA256SUMS` from the
   [latest release](https://github.com/arenberg-engineering/engra-releases/releases/latest).
2. Check the hash:
   `(Get-FileHash .\engra-<version>-windows-x64.zip -Algorithm SHA256).Hash.ToLower()`
   must match its line in `SHA256SUMS`.
3. Unpack it to a folder on your `PATH`, for example
   `%LOCALAPPDATA%\Programs\engra`, and run `engra --version`.

Each release's notes say whether the Windows build is Authenticode-signed.

## Check a download

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing        # sha256sum on Linux
gh attestation verify engra-<version>-macos-arm64 --repo arenberg-engineering/engra-releases
spctl --assess --type install -vvv engra-<version>-macos-arm64   # macOS: Notarized Developer ID
```

Each platform has a CycloneDX (`.cdx.json`) and an SPDX (`.spdx.json`) SBOM.

## Uninstall

```bash
engra logout                 # removes saved tokens from the OS keychain
brew uninstall engra
brew untap arenberg-engineering/tap
rm -rf ~/.config/engra       # optional: configuration and link state
```
