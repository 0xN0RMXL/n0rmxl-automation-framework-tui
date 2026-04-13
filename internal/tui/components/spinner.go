package components

import (
	"fmt"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
)

type SpinnerModel struct {
	spinner spinner.Model
	label   string
}

func NewSpinner(label string) SpinnerModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = theme.BoldText.Foreground(theme.Accent)
	return SpinnerModel{spinner: s, label: label}
}

func (m SpinnerModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m SpinnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.spinner, cmd = m.spinner.Update(msg)
	return m, cmd
}

func (m SpinnerModel) View() string {
	if m.label == "" {
		return m.spinner.View()
	}
	return fmt.Sprintf("%s %s", m.spinner.View(), theme.BaseText.Render(m.label))
}

func (m *SpinnerModel) SetLabel(label string) {
	m.label = label
}

func (m *SpinnerModel) SetStyle(style spinner.Spinner) {
	m.spinner.Spinner = style
}

