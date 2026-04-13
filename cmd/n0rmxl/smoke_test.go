package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	cfgpkg "github.com/n0rmxl/n0rmxl/internal/config"
	"github.com/n0rmxl/n0rmxl/internal/installer"
)

func TestRunSmokePreflightFailsMinToolsThreshold(t *testing.T) {
	cfg := cfgpkg.DefaultConfig()
	report, err := runSmokePreflight(context.Background(), cfg, "example.com", []int{0}, false, 10000)
	if err == nil {
		t.Fatal("expected min-tools threshold to fail")
	}
	if report == nil || report.TotalRegisteredTools == 0 {
		t.Fatal("expected preflight report with registered tool count")
	}
	if !strings.Contains(err.Error(), "below required minimum") {
		t.Fatalf("expected threshold error, got %v", err)
	}
}

func TestSummarizeInstallerStatusSkipsSystemToolsOnNonLinux(t *testing.T) {
	jobs := []*installer.ToolJob{
		{Name: "apt", Category: "system"},
		{Name: "httpx", Category: "go"},
	}
	status := map[string]bool{
		"apt":   false,
		"httpx": true,
	}

	expected, installed, missing := summarizeInstallerStatus(jobs, status)
	if runtime.GOOS == "linux" {
		if expected != 2 || installed != 1 || len(missing) != 1 || missing[0] != "apt" {
			t.Fatalf("unexpected linux summary expected=%d installed=%d missing=%v", expected, installed, missing)
		}
		return
	}

	if expected != 1 || installed != 1 {
		t.Fatalf("unexpected non-linux summary expected=%d installed=%d", expected, installed)
	}
	if len(missing) != 0 {
		t.Fatalf("expected no missing tools on non-linux after system-tool skip, got %v", missing)
	}
}

func TestFindMissingWordlistsDeduplicatesPaths(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists.txt")
	missingPath := filepath.Join(dir, "missing.txt")
	if err := os.WriteFile(existing, []byte("ok"), 0o600); err != nil {
		t.Fatalf("failed to create existing wordlist fixture: %v", err)
	}

	cfg := &cfgpkg.Config{
		Wordlists: cfgpkg.Wordlists{
			DNSLarge:  existing,
			DNSMedium: existing,
			DNSSmall:  missingPath,
		},
	}

	missing := findMissingWordlists(cfg)
	if len(missing) != 1 {
		t.Fatalf("expected one missing path after deduplication, got %v", missing)
	}
	if missing[0] != missingPath {
		t.Fatalf("expected missing path %q, got %q", missingPath, missing[0])
	}
}

func TestIsBinarySatisfiedAliasFromInstallerStatus(t *testing.T) {
	status := map[string]bool{"kiterunner": true}
	if !isBinarySatisfied("kr", "", status) {
		t.Fatal("expected kr alias to resolve via kiterunner status")
	}
	if isBinarySatisfied("definitely-not-a-real-binary", "", map[string]bool{}) {
		t.Fatal("expected unknown binary without aliases to be unsatisfied")
	}
}

func TestSmokeReadinessErrorIgnoresCatalogMissingTools(t *testing.T) {
	report := &smokePreflightReport{
		MissingTools:        []string{"optional-tool"},
		PayloadLibraryReady: true,
	}
	if err := smokeReadinessError(report); err != nil {
		t.Fatalf("expected missing installer catalog tools alone not to fail strict readiness, got %v", err)
	}
}

func TestSmokeReadinessErrorIgnoresOptionalPhaseBinaries(t *testing.T) {
	report := &smokePreflightReport{
		MissingPhaseBinaries:         []string{"phase 4 tool=kr binary=kr"},
		MissingRequiredPhaseBinaries: nil,
		PayloadLibraryReady:          true,
	}
	if err := smokeReadinessError(report); err != nil {
		t.Fatalf("expected optional missing phase binaries not to fail strict readiness, got %v", err)
	}
}

func TestSmokeReadinessErrorFailsRequiredPhaseBinaries(t *testing.T) {
	report := &smokePreflightReport{
		MissingPhaseBinaries:         []string{"phase 0 tool=subfinder binary=subfinder"},
		MissingRequiredPhaseBinaries: []string{"phase 0 tool=subfinder binary=subfinder"},
		PayloadLibraryReady:          true,
	}
	if err := smokeReadinessError(report); err == nil {
		t.Fatal("expected missing required phase binaries to fail strict readiness")
	}
}

func TestFindMissingWordlistsForPhasesSkipsUnusedPhaseSet(t *testing.T) {
	cfg := cfgpkg.DefaultConfig()
	cfg.Wordlists.DNSLarge = filepath.Join(t.TempDir(), "does-not-exist.txt")

	missing := findMissingWordlistsForPhases(cfg, []int{0})
	if len(missing) != 0 {
		t.Fatalf("expected phase 0 smoke to skip wordlist checks, got %v", missing)
	}
}

func TestFindMissingWordlistsForPhasesEnforcesNeededPhases(t *testing.T) {
	cfg := cfgpkg.DefaultConfig()
	cfg.Wordlists.DNSLarge = filepath.Join(t.TempDir(), "missing-dns.txt")

	missing := findMissingWordlistsForPhases(cfg, []int{2})
	if len(missing) == 0 {
		t.Fatal("expected phase 2 smoke to require wordlist assets")
	}
}

func TestFindMissingScriptDependenciesForPhasesSkipsUnusedPhaseSet(t *testing.T) {
	cfg := cfgpkg.DefaultConfig()
	cfg.Tools.GitClones = filepath.Join(t.TempDir(), "missing-tools")

	missing := findMissingScriptDependenciesForPhases(cfg, []int{0})
	if len(missing) != 0 {
		t.Fatalf("expected phase 0 smoke to skip script dependency checks, got %v", missing)
	}
}

func TestFindMissingScriptDependenciesForPhasesEnforcesNeededPhases(t *testing.T) {
	cfg := cfgpkg.DefaultConfig()
	cfg.Tools.GitClones = filepath.Join(t.TempDir(), "missing-tools")

	missing := findMissingScriptDependenciesForPhases(cfg, []int{4})
	if len(missing) == 0 {
		t.Fatal("expected phase 4 smoke to require script dependencies")
	}
}
