package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVaultCreateAndUnlock(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.enc")
	vault := NewVault(vaultPath)

	if err := vault.Create("correct horse battery staple"); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	other := NewVault(vaultPath)
	if err := other.Unlock("correct horse battery staple"); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	if other.IsLocked() {
		t.Fatal("expected unlocked vault")
	}
	if len(other.List()) != 0 {
		t.Fatalf("expected empty vault, got %v", other.List())
	}
}

func TestVaultSetAndGet(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.enc")
	vault := NewVault(vaultPath)
	if err := vault.Create("password123"); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if err := vault.Set("github_token", "ghp_test"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	other := NewVault(vaultPath)
	if err := other.Unlock("password123"); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	value, ok := other.Get("github_token")
	if !ok {
		t.Fatal("expected stored key to be present")
	}
	if value != "ghp_test" {
		t.Fatalf("expected stored value ghp_test, got %q", value)
	}
}

func TestVaultWrongPassword(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.enc")
	vault := NewVault(vaultPath)
	if err := vault.Create("secret-pass"); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	other := NewVault(vaultPath)
	if err := other.Unlock("wrong-pass"); err == nil {
		t.Fatal("expected unlock with wrong password to fail")
	}
}

func TestVaultLockClearsData(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.enc")
	vault := NewVault(vaultPath)
	if err := vault.Create("secret-pass"); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if err := vault.Set("virustotal", "vt-test"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	vault.Lock()
	if _, ok := vault.Get("virustotal"); ok {
		t.Fatal("expected Get to fail after Lock")
	}
	if !vault.IsLocked() {
		t.Fatal("expected vault to be locked")
	}
}

func TestVaultInjectToEnv(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "vault.enc")
	vault := NewVault(vaultPath)
	if err := vault.Create("secret-pass"); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if err := vault.Set("virustotal", "vt-test"); err != nil {
		t.Fatalf("Set virustotal failed: %v", err)
	}
	if err := vault.Set("securitytrails", "st-test"); err != nil {
		t.Fatalf("Set securitytrails failed: %v", err)
	}

	t.Setenv("VT_API_KEY", "")
	t.Setenv("SECURITYTRAILS_KEY", "")

	if err := vault.InjectToEnv(); err != nil {
		t.Fatalf("InjectToEnv failed: %v", err)
	}
	if got := os.Getenv("VT_API_KEY"); got != "vt-test" {
		t.Fatalf("expected VT_API_KEY to be injected, got %q", got)
	}
	if got := os.Getenv("SECURITYTRAILS_KEY"); got != "st-test" {
		t.Fatalf("expected SECURITYTRAILS_KEY to be injected, got %q", got)
	}
}
