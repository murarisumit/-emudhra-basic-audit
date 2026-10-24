# eMudhra CA audit

A small Go command-line checker for developer tools affected by the eMudhra/emSign intermediate CA compromise. It uses only Go's standard library. The default mode is read-only; `--fix` asks Homebrew (macOS) or winget (Windows) to upgrade supported package-manager-managed tools.

The fixed versions are based on the [incident advisory](https://emudhra.we-have-a-problem.com/). The advisory changes as vendors release patches, so review it before sharing builds broadly.

## Run a release binary

- macOS Apple silicon: `./emudhra-audit-macos-arm64`
- macOS Intel: `./emudhra-audit-macos-amd64`
- Windows x64 PowerShell: `./emudhra-audit-windows-amd64.exe`

Add `--fix` to attempt supported package-manager updates. Add `--json` for machine-readable output. On macOS, make the downloaded file executable with `chmod +x <binary>` if needed. On Windows, run from PowerShell; winget must be installed and available on PATH.

The audit checks detected Go, Node.js, uv, Bun, pip, Python `certifi` through common Python launchers, and (on macOS) Homebrew `ca-certificates`. For Java, it uses `keytool` to inspect the default `cacerts` store for the two affected root aliases; Java version alone is not treated as proof of remediation. If the keystore password is not the default or inspection fails, it reports `REVIEW`. Oracle guidance says to remove the affected roots or enable revocation checking even when using a patched JDK.

`--fix` only updates package-manager-managed Go, Node.js, uv, Bun and Homebrew `ca-certificates`. Pip and certifi findings are reported for manual remediation. It does not inspect project lockfiles, containers, CI images, vendored certificate bundles, custom Java trust stores, Windows' system trust store, or every Python environment. An `OK` means only the inspected installation/store passed.

## Build and verify

Install the build tools with Homebrew:

```sh
brew bundle --file Brewfile
```

Then:

```sh
just check
just build
```

Cross-compilation produces macOS ARM64, macOS x86-64, and Windows x86-64 binaries under `dist/`.

## Updating thresholds

Check the advisory before editing versions in `main.go`. Add/update tests in `main_test.go`, then run `just check` and `just build`.
