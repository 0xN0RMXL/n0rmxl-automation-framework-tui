package screenshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewScreenshotterUsesDefaultDir(t *testing.T) {
	s := NewScreenshotter("")
	if s == nil {
		t.Fatal("expected screenshotter instance")
	}
	if !strings.Contains(filepath.ToSlash(s.outputDir), "screenshots") {
		t.Fatalf("expected default screenshots dir, got %q", s.outputDir)
	}
}

func TestScreenshotterUnavailable(t *testing.T) {
	s := NewScreenshotter(t.TempDir())
	s.gowitness = "definitely-not-installed-gowitness"

	if _, err := s.Screenshot("https://example.com"); err == nil {
		t.Fatal("expected unavailable binary error")
	}
}

func TestLatestPNGSelectsNewest(t *testing.T) {
	dir := t.TempDir()
	older := filepath.Join(dir, "older.png")
	newer := filepath.Join(dir, "newer.png")
	if err := os.WriteFile(older, []byte("a"), 0o600); err != nil {
		t.Fatalf("failed to create older fixture: %v", err)
	}
	if err := os.WriteFile(newer, []byte("b"), 0o600); err != nil {
		t.Fatalf("failed to create newer fixture: %v", err)
	}
	oldTime := time.Now().Add(-2 * time.Minute)
	newTime := time.Now().Add(-1 * time.Minute)
	if err := os.Chtimes(older, oldTime, oldTime); err != nil {
		t.Fatalf("failed to set older mtime: %v", err)
	}
	if err := os.Chtimes(newer, newTime, newTime); err != nil {
		t.Fatalf("failed to set newer mtime: %v", err)
	}

	got := latestPNG(dir)
	if filepath.Clean(got) != filepath.Clean(newer) {
		t.Fatalf("expected newest png %q, got %q", newer, got)
	}
}

func TestLatestPNGEmptyRoot(t *testing.T) {
	if got := latestPNG(""); got != "" {
		t.Fatalf("expected empty path for empty root, got %q", got)
	}
}
