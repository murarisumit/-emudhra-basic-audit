// emudhra-audit checks supported developer tools for versions affected by the
// eMudhra/emSign CA compromise. It uses only Go's standard library.
// By default it is read-only. Pass --fix to upgrade detected Homebrew or
// winget-managed Go, Node.js, or uv installations.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const advisory = "https://emudhra.we-have-a-problem.com/"

type result struct {
	Name      string   `json:"name"`
	Installed string   `json:"installed"`
	Fixed     []string `json:"fixed"`
	Status    string   `json:"status"`
	Manager   string   `json:"manager,omitempty"`
	ID        string   `json:"id,omitempty"`
}

func command(name string, args ...string) (string, bool) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

func which(name string) bool { _, err := exec.LookPath(name); return err == nil }

func nums(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.SplitN(v, "-", 2)
	out := make([]int, 0, 4)
	for _, p := range strings.Split(parts[0], ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

func cmp(a, b string) int {
	x, y := nums(a), nums(b)
	for i := 0; i < len(x) || i < len(y); i++ {
		var p, q int
		if i < len(x) {
			p = x[i]
		}
		if i < len(y) {
			q = y[i]
		}
		if p < q {
			return -1
		}
		if p > q {
			return 1
		}
	}
	return 0
}

func assess(name, v string, fixed []string, manager, id string) result {
	r := result{Name: name, Installed: strings.TrimSpace(v), Fixed: fixed, Manager: manager, ID: id, Status: "REVIEW"}
	if len(nums(v)) == 0 {
		return r
	}
	applicable := make([]string, 0, len(fixed))
	for _, f := range fixed {
		if len(fixed) == 1 || (len(nums(v)) > 1 && strings.Split(v, ".")[0] == strings.Split(f, ".")[0] && strings.Split(v, ".")[1] == strings.Split(f, ".")[1]) {
			applicable = append(applicable, f)
		}
	}
	if len(applicable) == 0 {
		minVersion := ""
		for _, f := range fixed {
			if minVersion == "" || cmp(f, minVersion) < 0 {
				minVersion = f
			}
		}
		if minVersion != "" && cmp(v, minVersion) < 0 {
			r.Status = "UPDATE NEEDED"
		}
		return r
	}
	for _, f := range applicable {
		if cmp(v, f) < 0 {
			r.Status = "UPDATE NEEDED"
			return r
		}
	}
	r.Status = "OK"
	return r
}

func assessHomebrewCerts(version string) result {
	fixed := "2026-09-25_1"
	status := "REVIEW"
	dateVersion := strings.ReplaceAll(strings.ReplaceAll(version, "-", "."), "_", ".")
	if len(nums(dateVersion)) >= 3 {
		status = "OK"
		if version < fixed {
			status = "UPDATE NEEDED"
		}
	}
	return result{Name: "Homebrew ca-certificates", Installed: version, Fixed: []string{fixed}, Status: status, Manager: "brew", ID: "ca-certificates"}
}

func parseCertifiVersion(output string) string {
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "Version") {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func javaTrustStoreFinding(output string, ok bool) result {
	base := result{Name: "Java cacerts", Fixed: []string{"remove affected CA aliases or enable revocation checking per Oracle guidance"}}
	if !ok {
		base.Installed = "could not inspect Java trust store"
		base.Status = "REVIEW"
		return base
	}
	lower := strings.ToLower(output)
	var aliases []string
	if strings.Contains(lower, "emsigneccrootcag3 [jdk]") || strings.Contains(lower, "emsign ecc root ca - g3") {
		aliases = append(aliases, "emSign ECC Root CA - G3")
	}
	if strings.Contains(lower, "comodoaaaca [jdk]") || strings.Contains(lower, "aaa certificate services") {
		aliases = append(aliases, "AAA Certificate Services")
	}
	if len(aliases) > 0 {
		base.Installed = "affected root alias present: " + strings.Join(aliases, ", ")
		base.Status = "UPDATE NEEDED"
	} else {
		base.Installed = "neither affected root alias found in inspected trust store"
		base.Status = "OK"
	}
	return base
}

func main() {
	fix := flag.Bool("fix", false, "upgrade supported detected packages (Homebrew on macOS, winget on Windows)")
	jsonOut := flag.Bool("json", false, "print results as JSON")
	flag.Parse()
	var rows []result
	add := func(name, cmd string, args []string, pattern func(string) string, fixed []string, id string) {
		if !which(cmd) {
			return
		}
		out, ok := command(cmd, args...)
		if !ok {
			return
		}
		v := pattern(out)
		if v != "" {
			rows = append(rows, assess(name, v, fixed, "", id))
		}
	}
	add("Go", "go", []string{"version"}, func(s string) string {
		f := strings.Fields(s)
		if len(f) > 2 {
			return strings.TrimPrefix(f[2], "go")
		}
		return ""
	}, []string{"1.27.3", "1.26.10"}, "GoLang.Go")
	add("Node.js", "node", []string{"--version"}, func(s string) string { return strings.TrimPrefix(s, "v") }, []string{"22.23.4", "24.22.1", "26.12.1"}, "OpenJS.NodeJS")
	add("uv", "uv", []string{"--version"}, func(s string) string {
		f := strings.Fields(s)
		if len(f) > 1 {
			return f[1]
		}
		return ""
	}, []string{"0.13.5"}, "astral-sh.uv")
	add("Bun", "bun", []string{"--version"}, func(s string) string { return strings.TrimPrefix(s, "v") }, []string{"1.4.4"}, "Oven-sh.Bun")
	for _, p := range []string{"pip3", "pip"} {
		add(p, p, []string{"--version"}, func(s string) string {
			f := strings.Fields(s)
			if len(f) > 1 {
				return f[1]
			}
			return ""
		}, []string{"26.2.2"}, "")
	}
	// Check certifi separately in each common Python launcher/environment found
	// on PATH. This avoids assuming a particular venv or Python installation.
	pythonCandidates := []struct {
		command string
		args    []string
	}{
		{"python3", []string{"-m", "pip", "show", "certifi"}},
		{"python", []string{"-m", "pip", "show", "certifi"}},
		{"py", []string{"-3", "-m", "pip", "show", "certifi"}},
	}
	for _, candidate := range pythonCandidates {
		if !which(candidate.command) {
			continue
		}
		out, ok := command(candidate.command, candidate.args...)
		if !ok {
			continue
		}
		v := parseCertifiVersion(out)
		if v != "" {
			rows = append(rows, assess("Python certifi ("+candidate.command+")", v, []string{"2026.10.19"}, "", ""))
		}
	}

	// Check Homebrew's certificate package on macOS. Formula revisions use a
	// date-like version; an unknown format is reported for manual review.
	if runtime.GOOS == "darwin" && which("brew") {
		if out, ok := command("brew", "list", "--versions", "ca-certificates"); ok && out != "" {
			f := strings.Fields(out)
			if len(f) > 1 {
				v := f[len(f)-1]
				rows = append(rows, assessHomebrewCerts(v))
			}
		}
	}

	// A Java version alone is not enough: Oracle's guidance requires checking
	// the trust store even for patched JDKs. Inspect the active keytool cacerts.
	javaHomes := map[string]string{}
	if home := os.Getenv("JAVA_HOME"); home != "" {
		keytool := filepath.Join(home, "bin", "keytool")
		if runtime.GOOS == "windows" {
			keytool += ".exe"
		}
		javaHomes[keytool] = home
	}
	if keytool, err := exec.LookPath("keytool"); err == nil {
		javaHomes[keytool] = "PATH Java"
	}
	for keytool, home := range javaHomes {
		out, ok := command(keytool, "-list", "-cacerts", "-storepass", "changeit")
		finding := javaTrustStoreFinding(out, ok)
		finding.Name += " (" + home + ")"
		rows = append(rows, finding)
	}
	if which("java") && len(javaHomes) == 0 {
		rows = append(rows, javaTrustStoreFinding("", false))
	}

	// Tag findings managed by a supported package manager, enabling --fix.
	for i := range rows {
		if rows[i].Status != "UPDATE NEEDED" {
			continue
		}
		if runtime.GOOS == "darwin" && which("brew") {
			formula := map[string]string{"Go": "go", "Node.js": "node", "uv": "uv", "Bun": "bun", "Homebrew ca-certificates": "ca-certificates"}[rows[i].Name]
			if formula != "" {
				out, ok := command("brew", "list", "--versions", formula)
				if ok && out != "" {
					rows[i].Manager = "brew"
					rows[i].ID = formula
				}
			}
		} else if runtime.GOOS == "windows" && which("winget") && rows[i].ID != "" {
			rows[i].Manager = "winget"
		}
	}

	if *fix {
		for i := range rows {
			r := &rows[i]
			if r.Status != "UPDATE NEEDED" {
				continue
			}
			var out string
			var ok bool
			switch r.Manager {
			case "brew":
				out, ok = command("brew", "upgrade", r.ID)
			case "winget":
				out, ok = command("winget", "upgrade", "--id", r.ID, "--exact", "--accept-source-agreements", "--accept-package-agreements")
			default:
				continue
			}
			if ok {
				r.Status = "UPDATE COMMAND SUCCEEDED"
			} else {
				r.Status = "UPDATE FAILED"
				if out != "" {
					fmt.Fprintln(os.Stderr, out)
				}
			}
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"host": host(), "platform": runtime.GOOS, "advisory": advisory, "fix_mode": *fix, "results": rows})
	} else {
		fmt.Printf("eMudhra/emSign package audit — %s (%s/%s)\nAdvisory: %s\n\n", host(), runtime.GOOS, runtime.GOARCH, advisory)
		if len(rows) == 0 {
			fmt.Println("No supported package versions were detected. This does not establish that the system is unaffected.")
		}
		for _, r := range rows {
			fmt.Printf("%-23s %-24s installed %-14s fixed %s\n", r.Status, r.Name, r.Installed, strings.Join(r.Fixed, ", "))
		}
		if *fix {
			fmt.Println("\nOnly update commands supported by Homebrew or winget were run. Review remaining findings manually.")
		} else {
			fmt.Println("\nRead-only mode. Add --fix to upgrade detected Homebrew/winget-managed Go, Node.js, uv, Bun, and Homebrew ca-certificates packages.")
		}
		fmt.Println("This quick check does not scan project lockfiles, containers, vendored bundles, custom Java trust stores, Windows' system trust store, or every language environment.")
	}
	for _, r := range rows {
		if r.Status == "UPDATE NEEDED" || r.Status == "UPDATE FAILED" {
			os.Exit(1)
		}
	}
}

func host() string { h, _ := os.Hostname(); return h }
