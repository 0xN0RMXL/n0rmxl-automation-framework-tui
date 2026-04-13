package components

import (
	"fmt"
	"math"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
)

type ProgressModel struct {
	bar     progress.Model
	percent float64
	label   string
	width   int
}

func NewProgressBar(width int) ProgressModel {
	if width <= 0 {
		width = 40
	}
	bar := progress.New(
		progress.WithWidth(width),
		progress.WithoutPercentage(),
	)
	return ProgressModel{bar: bar, width: width}
}

func (m ProgressModel) Init() tea.Cmd {
	return nil
}

func (m ProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	updated, cmd := m.bar.Update(msg)
	if bar, ok := updated.(progress.Model); ok {
		m.bar = bar
	}
	return m, cmd
}

func (m ProgressModel) View() string {
	pct := int(math.Round(m.percent * 100))
	return fmt.Sprintf("[%s] %d%% - %s", m.bar.ViewAs(m.percent), pct, m.label)
}

func (m *ProgressModel) SetPercent(percent float64) {
	if percent < 0 {
		percent = 0
	}
	if percent > 1 {
		percent = 1
	}
	m.percent = percent
}

func (m *ProgressModel) SetLabel(label string) {
	m.label = label
}

func (m *ProgressModel) SetWidth(width int) {
	if width <= 0 {
		return
	}
	m.width = width
	m.bar.Width = width
}
