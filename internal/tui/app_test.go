package tui

import (
	"testing"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/screens"
	tea "github.com/charmbracelet/bubbletea"
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

func TestBackToSplashMessageNavigatesToSplash(t *testing.T) {
	model := NewAppModel()
	updated, cmd := model.Update(NavigateTo{Screen: ScreenSettings})
	if cmd != nil {
		_ = cmd()
	}

	updated, cmd = updated.(AppModel).Update(screens.BackToSplashMsg{})
	next := updated.(AppModel)
	if next.screen != ScreenSplash {
		t.Fatalf("expected splash screen, got %v", next.screen)
	}
	if cmd != nil {
		_ = cmd()
	}
}

func TestBackToPhaseMenuMessageUsesTargetContext(t *testing.T) {
	model := NewAppModel()
	target := models.Target{Domain: "example.com", WorkspaceDir: "/tmp/example"}
	model.target = &target

	updated, cmd := model.Update(screens.BackToPhaseMenuMsg{})
	next := updated.(AppModel)
	if next.screen != ScreenPhaseMenu {
		t.Fatalf("expected phase menu screen, got %v", next.screen)
	}
	if cmd == nil {
		t.Fatal("expected phase menu refresh command")
	}
}

func TestCtrlCQuitsGlobally(t *testing.T) {
	model := NewAppModel()
	updated, cmd := model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	_ = updated.(AppModel)
	if cmd == nil {
		t.Fatal("expected quit command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("expected ctrl+c to emit tea.QuitMsg")
	}
}
