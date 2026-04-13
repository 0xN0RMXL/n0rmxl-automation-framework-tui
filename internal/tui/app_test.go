package tui

import (
	"testing"

	"github.com/n0rmxl/n0rmxl/internal/tui/screens"
)

func TestSplashNavigateInstallerStartsInstallerFlow(t *testing.T) {
	model := NewAppModel()
	updated, cmd := model.Update(screens.SplashNavigateMsg{Action: screens.ActionInstaller})
	next := updated.(AppModel)

	if next.screen != ScreenInstaller {
		t.Fatalf("expected installer screen, got %v", next.screen)
	}
	if cmd == nil {
		t.Fatal("expected installer navigation to return init command")
	}
	if msg := cmd(); msg == nil {
		t.Fatal("expected installer init command to emit a message")
	}
}

func TestNavigateToInstallerStartsInstallerFlow(t *testing.T) {
	model := NewAppModel()
	updated, cmd := model.Update(NavigateTo{Screen: ScreenInstaller})
	next := updated.(AppModel)

	if next.screen != ScreenInstaller {
		t.Fatalf("expected installer screen, got %v", next.screen)
	}
	if cmd == nil {
		t.Fatal("expected installer navigation command")
	}
	if msg := cmd(); msg == nil {
		t.Fatal("expected installer navigation command to emit a message")
	}
}
