Subject: Action requested: check developer tools for the eMudhra/emSign CA compromise

Hi everyone,

A security advisory reports that compromised eMudhra/emSign intermediate CA keys may be trusted by affected versions of several developer tools and certificate bundles. Please check your workstation and update affected software promptly. Review the advisory for the full package list and current fixed versions: https://emudhra.we-have-a-problem.com/

Run the provided checker for your platform. Use the read-only mode first to review findings. To let it update supported package-manager-managed tools, run it with `--fix`:

- macOS Apple silicon: `./emudhra-audit-macos-arm64 --fix`
- macOS Intel: `./emudhra-audit-macos-amd64 --fix`
- Windows x64 PowerShell: `.\emudhra-audit-windows-amd64.exe --fix`

The checker detects Go, Node.js, `uv`, Bun, `pip`, Python `certifi` via common Python launchers, and (on macOS) Homebrew `ca-certificates`. It also uses `keytool` to inspect the default Java `cacerts` store for affected root aliases. The `--fix` option attempts updates for detected Go, Node.js, `uv`, Bun, and Homebrew `ca-certificates` installations managed by Homebrew or winget. It reports pip and certifi findings but does not update those packages or arbitrary project dependencies. Java trust-store findings require manual remediation; Oracle guidance recommends removing affected roots or enabling revocation checking, including on patched JDKs.

If it reports `REVIEW`, an update failure, or no version for a tool you use, follow your platform or package-manager update process and verify the fixed version in the advisory. This workstation check does not scan project lockfiles, containers, CI images, vendored CA bundles, custom Java trust stores, Windows’ system trust store, or every Python environment. Teams owning those should check and rebuild/redeploy affected artifacts as appropriate.

The checker is read-only without `--fix`. Homebrew or winget must be available, and the relevant tool must be managed by it, for the automatic upgrade to apply.

Thanks,
Security Team
