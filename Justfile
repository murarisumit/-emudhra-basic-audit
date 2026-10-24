set shell := ["bash", "-euo", "pipefail", "-c"]

# Run focused checks and report what each one verifies
test:
    @if go test -run '^TestCompareVersionsOrdersNumericVersionParts$$' ./... >/dev/null; then echo "PASS: Older package versions are recognized as older than fixed versions."; else echo "FAILED: version ordering"; go test -run '^TestCompareVersionsOrdersNumericVersionParts$$' ./...; exit 1; fi
    @if go test -run '^TestAssessGoFixedVersionsAcrossSupportedBranches$$' ./... >/dev/null; then echo "PASS: Go fixed versions are checked for both supported release branches (1.26 and 1.27)."; else echo "FAILED: Go security-version checks"; go test -run '^TestAssessGoFixedVersionsAcrossSupportedBranches$$' ./...; exit 1; fi
    @if go test -run '^TestAssessUVAgainstFixedThreshold$$' ./... >/dev/null; then echo "PASS: uv versions below 0.13.5 are flagged; 0.13.5 and newer pass."; else echo "FAILED: uv security-version check"; go test -run '^TestAssessUVAgainstFixedThreshold$$' ./...; exit 1; fi
    @if go test -run '^TestAssessNodeFixedVersionsAcrossSupportedBranches$$' ./... >/dev/null; then echo "PASS: Node.js 22, 24, and 26 branches are checked against their fixed versions."; else echo "FAILED: Node.js security-version checks"; go test -run '^TestAssessNodeFixedVersionsAcrossSupportedBranches$$' ./...; exit 1; fi
    @if go test -run '^TestCertifiVersionIsReadAndChecked$$' ./... >/dev/null; then echo "PASS: certifi versions before 2026.10.19 are flagged."; else echo "FAILED: Python certifi check"; go test -run '^TestCertifiVersionIsReadAndChecked$$' ./...; exit 1; fi
    @if go test -run '^TestHomebrewCACertificatesFixedRevision$$' ./... >/dev/null; then echo "PASS: Homebrew ca-certificates revisions before 2026-09-25_1 are flagged."; else echo "FAILED: Homebrew ca-certificates check"; go test -run '^TestHomebrewCACertificatesFixedRevision$$' ./...; exit 1; fi
    @if go test -run '^TestJavaTrustStoreChecksAffectedAliases$$' ./... >/dev/null; then echo "PASS: Java trust stores are flagged when affected eMudhra or AAA root aliases remain."; else echo "FAILED: Java trust-store check"; go test -run '^TestJavaTrustStoreChecksAffectedAliases$$' ./...; exit 1; fi
    @echo "All audit validations passed."

# Validate formatting, static analysis, and package behavior
check:
    @echo "Checking Go source formatting..."
    test -z "$(gofmt -l *.go)"
    @echo "PASS: Go files are formatted."
    @echo "Checking for common Go code issues..."
    go vet ./...
    @echo "PASS: Static analysis found no issues."
    @just test

# Build binaries for the supported workstation platforms
build:
    @echo "Building macOS Apple silicon, macOS Intel, and Windows x64 binaries..."
    mkdir -p dist
    GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o dist/emudhra-audit-macos-arm64 .
    GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/emudhra-audit-macos-amd64 .
    GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/emudhra-audit-windows-amd64.exe .
    @echo "PASS: All three platform binaries were built."

# Run a read-only audit of this machine
run:
    @echo "Checking detected local tool versions (read-only)..."
    go run .
