package screens

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestInstallerStartCmdEmitsStartMessage(t *testing.T) {
	cmd := installerStartCmd()
	if cmd == nil {
		t.Fatal("expected installerStartCmd to return a command")
	}
	if _, ok := cmd().(installerStartMsg); !ok {
		t.Fatal("expected installerStartCmd to emit installerStartMsg")
	}
}

func TestInstallerInitUsesStartMessage(t *testing.T) {
	m := NewInstallerModel()
	cmd := m.Init()
	if cmd == nil {
		t.Fatal("expected installer Init command")
	}
	if _, ok := cmd().(installerStartMsg); !ok {
		t.Fatal("expected installer Init to emit installerStartMsg")
	}
}

func TestInstallerUpdateStartMessageSetsRunningState(t *testing.T) {
	m := NewInstallerModel()
	updated, cmd := m.Update(installerStartMsg{})
	next := updated.(InstallerModel)

	if !next.running {
		t.Fatal("expected installer model to enter running state")
	}
	if next.done {
		t.Fatal("expected installer model not to be marked done at start")
	}
	if cmd == nil {
		t.Fatal("expected start update to return execution command batch")
	}
}

func TestInstallerBackKeyCancelsAndNavigates(t *testing.T) {
	m := NewInstallerModel()
	m.running = true
	canceled := false
	m.cancelRun = func() { canceled = true }

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	next := updated.(InstallerModel)

	if !canceled {
		t.Fatal("expected running installer to be canceled on q")
	}
	if next.running {
		t.Fatal("expected running state to be cleared on q")
	}
	if !next.done {
		t.Fatal("expected installer model to be marked done on q")
	}
	if cmd == nil {
		t.Fatal("expected back navigation command")
	}
	if _, ok := cmd().(BackToSplashMsg); !ok {
		t.Fatal("expected back command to emit BackToSplashMsg")
	}
}
