package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScopeIsInScope(t *testing.T) {
	scope := &Scope{
		Wildcards:  []string{"*.example.com"},
		Explicit:   []string{"api.partner.net"},
		OutOfScope: []string{"admin.example.com"},
	}

	if !scope.IsInScope("app.example.com") {
		t.Fatal("expected wildcard host to be in scope")
	}
	if !scope.IsInScope("https://api.partner.net/login") {
		t.Fatal("expected explicit host to be in scope")
	}
	if scope.IsInScope("admin.example.com") {
		t.Fatal("expected out-of-scope host to be excluded")
	}
}

func TestScopeFilterFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	output := filepath.Join(dir, "output.txt")
	content := strings.Join([]string{
		"app.example.com",
		"admin.example.com",
		"https://api.example.com/v1/users",
		"outside.test",
		"app.example.com",
		"",
	}, "\n")
	if err := os.WriteFile(input, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write input file: %v", err)
	}

	scope := &Scope{
		Wildcards:  []string{"*.example.com"},
		OutOfScope: []string{"admin.example.com"},
	}
	count, err := scope.FilterFile(input, output)
	if err != nil {
		t.Fatalf("FilterFile failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 kept lines, got %d", count)
	}

	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}
	lines := strings.Fields(string(raw))
	if len(lines) != 2 {
		t.Fatalf("expected 2 output lines, got %v", lines)
	}
	if lines[0] != "app.example.com" || lines[1] != "api.example.com" {
		t.Fatalf("unexpected filtered output: %v", lines)
	}
}

func TestScopeIPRange(t *testing.T) {
	scope := &Scope{IPRanges: []string{"10.10.0.0/16"}}
	if !scope.IsInScope("10.10.42.9") {
		t.Fatal("expected IP inside CIDR to be in scope")
	}
	if scope.IsInScope("10.11.42.9") {
		t.Fatal("expected IP outside CIDR to be out of scope")
	}
}
