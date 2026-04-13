package installer

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/n0rmxl/n0rmxl/internal/config"
)

func TestRegisterPayloadLibrariesAddsJob(t *testing.T) {
	inst := NewInstaller(config.DefaultConfig())
	RegisterPayloadLibraries(inst)

	found := false
	for _, job := range inst.Jobs() {
		if job.Name == "payloads-all-the-things" {
			found = true
			if job.Category != "wordlist" {
				t.Fatalf("expected wordlist category, got %q", job.Category)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected payloads-all-the-things installer job to be registered")
	}
}

func TestSyncGitRepositoryRejectsEmptyPath(t *testing.T) {
	err := syncGitRepository(context.Background(), payloadsAllTheThingsRepo, "")
	if err == nil {
		t.Fatal("expected error for empty target path")
	}
}

func TestPayloadLibraryPath(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Tools.GitClones = filepath.Join(t.TempDir(), "tools")

	path := PayloadLibraryPath(cfg)
	if path == "" {
		t.Fatal("expected non-empty payload library path")
	}
	if filepath.Base(path) != "PayloadsAllTheThings" {
		t.Fatalf("expected payload path to end with PayloadsAllTheThings, got %q", path)
	}
}

func TestPayloadLibraryStatus(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Tools.GitClones = filepath.Join(t.TempDir(), "tools")

	path, ready := PayloadLibraryStatus(cfg)
	if ready {
		t.Fatal("expected payload library to be absent initially")
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("failed to create payload path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "README.md"), []byte("ready"), 0o644); err != nil {
		t.Fatalf("failed to create payload marker: %v", err)
	}

	_, ready = PayloadLibraryStatus(cfg)
	if !ready {
		t.Fatal("expected payload library to be ready after README marker")
	}
}
