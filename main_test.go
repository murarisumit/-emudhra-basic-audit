package main

import "testing"

func TestCompareVersionsOrdersNumericVersionParts(t *testing.T) {
	cases := []struct {
		name, a, b string
		want       int
	}{
		{"older_patch_is_less", "1.27.2", "1.27.3", -1},
		{"same_version_is_equal", "1.27.3", "1.27.3", 0},
		{"newer_minor_is_greater", "1.28.0", "1.27.3", 1},
		{"optional_v_prefix_is_ignored", "v26.12.0", "26.12.1", -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cmp(tc.a, tc.b); got != tc.want {
				t.Errorf("cmp(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestAssessGoFixedVersionsAcrossSupportedBranches(t *testing.T) {
	fixed := []string{"1.27.3", "1.26.10"}
	cases := []struct {
		name, version, status string
	}{
		{"old_patch_on_latest_branch", "1.27.2", "UPDATE NEEDED"},
		{"old_patch_on_previous_branch", "1.26.9", "UPDATE NEEDED"},
		{"fixed_latest_branch", "1.27.3", "OK"},
		{"fixed_previous_branch", "1.26.10", "OK"},
		{"unsupported_older_branch_needs_update", "1.25.9", "UPDATE NEEDED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := assess("Go", tc.version, fixed, "", "").Status; got != tc.status {
				t.Errorf("assess(%q) = %q, want %q", tc.version, got, tc.status)
			}
		})
	}
}

func TestAssessUVAgainstFixedThreshold(t *testing.T) {
	cases := []struct {
		name, version, want string
	}{
		{"below_fixed_version", "0.13.4", "UPDATE NEEDED"},
		{"at_fixed_version", "0.13.5", "OK"},
		{"above_fixed_version", "0.13.6", "OK"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := assess("uv", tc.version, []string{"0.13.5"}, "", "").Status; got != tc.want {
				t.Errorf("assess uv %s = %q, want %q", tc.version, got, tc.want)
			}
		})
	}
}

func TestAssessNodeFixedVersionsAcrossSupportedBranches(t *testing.T) {
	fixed := []string{"22.23.4", "24.22.1", "26.12.1"}
	cases := []struct {
		name, version, want string
	}{
		{"Node_22_below_fixed", "22.23.3", "UPDATE NEEDED"},
		{"Node_24_at_fixed", "24.22.1", "OK"},
		{"Node_26_below_fixed", "26.12.0", "UPDATE NEEDED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := assess("Node.js", tc.version, fixed, "", "").Status; got != tc.want {
				t.Errorf("Node.js %s = %q, want %q", tc.version, got, tc.want)
			}
		})
	}
}

func TestCertifiVersionIsReadAndChecked(t *testing.T) {
	output := "Name: certifi\nVersion: 2026.10.18\nLocation: /example/site-packages\n"
	version := parseCertifiVersion(output)
	if version != "2026.10.18" {
		t.Fatalf("parsed certifi version = %q, want 2026.10.18", version)
	}
	if got := assess("Python certifi", version, []string{"2026.10.19"}, "", "").Status; got != "UPDATE NEEDED" {
		t.Errorf("old certifi status = %q, want UPDATE NEEDED", got)
	}
	if got := assess("Python certifi", "2026.10.19", []string{"2026.10.19"}, "", "").Status; got != "OK" {
		t.Errorf("fixed certifi status = %q, want OK", got)
	}
}

func TestHomebrewCACertificatesFixedRevision(t *testing.T) {
	cases := []struct {
		version, want string
	}{
		{"2026-09-25_0", "UPDATE NEEDED"},
		{"2026-09-25_1", "OK"},
		{"2026-10-20", "OK"},
	}
	for _, tc := range cases {
		if got := assessHomebrewCerts(tc.version).Status; got != tc.want {
			t.Errorf("Homebrew ca-certificates %s = %q, want %q", tc.version, got, tc.want)
		}
	}
}

func TestJavaTrustStoreChecksAffectedAliases(t *testing.T) {
	cases := []struct {
		name, output, want string
		ok                 bool
	}{
		{"affected_emSign_root_is_flagged", "emsigneccrootcag3 [jdk], Oct 1, 2026, trustedCertEntry", "UPDATE NEEDED", true},
		{"affected_AAA_root_is_flagged", "comodoaaaca [jdk], Oct 1, 2026, trustedCertEntry", "UPDATE NEEDED", true},
		{"neither_affected_alias_is_found", "digicert_global_root_g2 [jdk], trustedCertEntry", "OK", true},
		{"failed_keytool_inspection_requires_review", "", "REVIEW", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := javaTrustStoreFinding(tc.output, tc.ok).Status; got != tc.want {
				t.Errorf("Java trust store status = %q, want %q", got, tc.want)
			}
		})
	}
}
