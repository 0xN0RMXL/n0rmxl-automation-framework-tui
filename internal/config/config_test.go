package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected default config")
	}
	if strings.TrimSpace(cfg.Version) == "" {
		t.Fatal("expected default config version to be set")
	}
}

func TestConfigEnsureDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.EnsureDefaults()

	if strings.TrimSpace(cfg.Wordlists.DNSLarge) == "" {
		t.Fatal("expected dns large wordlist path to be set")
	}
	if strings.TrimSpace(cfg.Wordlists.Params) == "" {
		t.Fatal("expected params wordlist path to be set")
	}
	if strings.TrimSpace(cfg.Wordlists.Resolvers) == "" {
		t.Fatal("expected resolvers wordlist path to be set")
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.VaultPath = ""

	warnings := cfg.Validate()
	found := false
	for _, warning := range warnings {
		if warning == "vault_path should not be empty" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected vault path warning, got %v", warnings)
	}
}

func TestConfigSaveLoad(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("N0RMXL_CONFIG", configPath)

	cfg := DefaultConfig()
	cfg.WorkspaceRoot = filepath.ToSlash(filepath.Join(t.TempDir(), "bounty"))
	cfg.StealthProfile = "aggressive"

	if err := cfg.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.WorkspaceRoot != cfg.WorkspaceRoot {
		t.Fatalf("expected workspace root %q, got %q", cfg.WorkspaceRoot, loaded.WorkspaceRoot)
	}
	if loaded.StealthProfile != cfg.StealthProfile {
		t.Fatalf("expected stealth profile %q, got %q", cfg.StealthProfile, loaded.StealthProfile)
	}
}
