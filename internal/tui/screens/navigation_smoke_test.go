package screens

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func runCmdAndCollect(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	msg := cmd()
	if msg == nil {
		return nil
	}

	messages := []tea.Msg{msg}
	if batch, ok := msg.(tea.BatchMsg); ok {
		messages = messages[:0]
		for _, sub := range batch {
			if sub == nil {
				continue
			}
			subMsg := sub()
			if subMsg != nil {
				messages = append(messages, subMsg)
			}
		}
	}

	return messages
}

func hasBackToSplash(messages []tea.Msg) bool {
	for _, msg := range messages {
		if _, ok := msg.(BackToSplashMsg); ok {
			return true
		}
	}
	return false
}

func hasBackToPhaseMenu(messages []tea.Msg) bool {
	for _, msg := range messages {
		if _, ok := msg.(BackToPhaseMenuMsg); ok {
			return true
		}
	}
	return false
}

func TestPhaseMenuBackKeys(t *testing.T) {
	m := NewPhaseMenuModel("example.com", "")
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	_ = updated.(PhaseMenuModel)
	if !hasBackToSplash(runCmdAndCollect(cmd)) {
		t.Fatal("expected q to emit BackToSplashMsg from phase menu")
	}
}

func TestCampaignBackKeys(t *testing.T) {
	m := NewCampaignModel()
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	_ = updated.(CampaignModel)
	if !hasBackToSplash(runCmdAndCollect(cmd)) {
		t.Fatal("expected q to emit BackToSplashMsg from campaign")
	}
}

func TestDashboardBackKeys(t *testing.T) {
	m := NewDashboardModel()
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	_ = updated.(DashboardModel)
	if !hasBackToPhaseMenu(runCmdAndCollect(cmd)) {
		t.Fatal("expected q to emit BackToPhaseMenuMsg from dashboard")
	}
}

func TestSettingsBackKeys(t *testing.T) {
	m := NewSettingsModel()
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	_ = updated.(SettingsModel)
	if !hasBackToSplash(runCmdAndCollect(cmd)) {
		t.Fatal("expected q to emit BackToSplashMsg from settings")
	}
}

func TestTargetInputBackFromFirstStep(t *testing.T) {
	m := NewTargetInputModel()
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	next := updated.(TargetInputModel)
	if next.step != stepDomain {
		t.Fatalf("expected to remain on domain step, got %d", next.step)
	}
	if !hasBackToSplash(runCmdAndCollect(cmd)) {
		t.Fatal("expected q to emit BackToSplashMsg from first target step")
	}
}

func TestTargetInputBackFromLaterStep(t *testing.T) {
	m := NewTargetInputModel()
	m.step = stepScope
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	next := updated.(TargetInputModel)
	if next.step != stepDomain {
		t.Fatalf("expected q to step back to domain, got %d", next.step)
	}
	if cmd != nil {
		t.Fatal("expected no navigation command when stepping back within target wizard")
	}
}

func TestReportViewerBackKeys(t *testing.T) {
	m := NewReportViewerModel("")
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	_ = updated.(ReportViewerModel)
	if !hasBackToPhaseMenu(runCmdAndCollect(cmd)) {
		t.Fatal("expected q to emit BackToPhaseMenuMsg from report viewer")
	}
}

func TestExploitWizardBackKeys(t *testing.T) {
	m := NewExploitWizardModel()
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	_ = updated.(ExploitWizardModel)
	if !hasBackToPhaseMenu(runCmdAndCollect(cmd)) {
		t.Fatal("expected q to emit BackToPhaseMenuMsg from exploit wizard")
	}
}

func TestExploitWizardEscInFindingsReturnsClasses(t *testing.T) {
	m := NewExploitWizardModel()
	m.mode = "findings"
	m.findingIndex = 1
	m.stepIndex = 2

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	next := updated.(ExploitWizardModel)
	if next.mode != "classes" {
		t.Fatalf("expected esc in findings to switch to classes, got %s", next.mode)
	}
	if cmd != nil {
		t.Fatal("expected no app navigation command when esc switches wizard mode")
	}
}

func TestExploitWizardEscInClassesExits(t *testing.T) {
	m := NewExploitWizardModel()
	m.mode = "classes"

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	_ = updated.(ExploitWizardModel)
	if !hasBackToPhaseMenu(runCmdAndCollect(cmd)) {
		t.Fatal("expected esc in classes to emit BackToPhaseMenuMsg")
	}
}

func TestPhaseRunnerBackFlowStopsThenExits(t *testing.T) {
	m := NewPhaseRunnerModel()
	m.runDone = false
	m.stopped = false

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	next := updated.(PhaseRunnerModel)
	if !next.stopped {
		t.Fatal("expected first q to stop the phase runner")
	}
	if cmd != nil {
		t.Fatal("expected first q to stay on phase runner without navigation")
	}

	updated, cmd = next.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	_ = updated.(PhaseRunnerModel)
	if !hasBackToPhaseMenu(runCmdAndCollect(cmd)) {
		t.Fatal("expected second q to emit BackToPhaseMenuMsg")
	}
}
