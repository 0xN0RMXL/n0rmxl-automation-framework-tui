package engine

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

func TestMergeAndDedup(t *testing.T) {
	dir := t.TempDir()
	inputA := filepath.Join(dir, "a.txt")
	inputB := filepath.Join(dir, "b.txt")
	output := filepath.Join(dir, "merged.txt")

	if err := os.WriteFile(inputA, []byte("beta\nalpha\n"), 0o600); err != nil {
		t.Fatalf("write inputA failed: %v", err)
	}
	if err := os.WriteFile(inputB, []byte("alpha\ngamma\n"), 0o600); err != nil {
		t.Fatalf("write inputB failed: %v", err)
	}

	manager := NewOutputManager(models.Workspace{})
	count, err := manager.MergeAndDedup([]string{inputA, inputB}, output)
	if err != nil {
		t.Fatalf("MergeAndDedup failed: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 merged lines, got %d", count)
	}

	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output failed: %v", err)
	}
	got := strings.Fields(string(raw))
	want := []string{"alpha", "beta", "gamma"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestAppendUnique(t *testing.T) {
	file := filepath.Join(t.TempDir(), "unique.txt")
	manager := NewOutputManager(models.Workspace{})

	for _, line := range []string{"alpha", "alpha", "beta"} {
		if err := manager.AppendUnique(file, line); err != nil {
			t.Fatalf("AppendUnique failed: %v", err)
		}
	}

	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read output failed: %v", err)
	}
	lines := strings.Fields(string(raw))
	if !reflect.DeepEqual(lines, []string{"alpha", "beta"}) {
		t.Fatalf("expected [alpha beta], got %v", lines)
	}
}

func TestScopeFilter(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "urls.txt")
	output := filepath.Join(dir, "scoped.txt")
	content := strings.Join([]string{
		"https://api.example.com/users",
		"https://cdn.example.com/app.js",
		"https://outside.test/admin",
	}, "\n")
	if err := os.WriteFile(input, []byte(content), 0o600); err != nil {
		t.Fatalf("write input failed: %v", err)
	}

	scope := &config.Scope{Wildcards: []string{"*.example.com"}}
	manager := NewOutputManager(models.Workspace{})
	count, err := manager.ScopeFilter(input, output, scope)
	if err != nil {
		t.Fatalf("ScopeFilter failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 scoped lines, got %d", count)
	}
}

