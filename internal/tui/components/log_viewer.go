package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/n0rmxl/n0rmxl/internal/tui/theme"
)

type LogViewer struct {
	viewport     viewport.Model
	lines        []string
	autoScroll   bool
	currentWidth int
}

func NewLogViewer(width int, height int) LogViewer {
	vp := viewport.New(width, height)
	vp.Style = lipgloss.NewStyle().Foreground(theme.Text).Background(theme.Surface)
	return LogViewer{
		viewport:     vp,
		lines:        make([]string, 0, 64),
		autoScroll:   true,
		currentWidth: width,
	}
}

func (l LogViewer) Init() tea.Cmd {
	return nil
}

func (l LogViewer) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			l.autoScroll = false
		case "G":
			l.autoScroll = true
			l.viewport.GotoBottom()
		}
	}
	var cmd tea.Cmd
	l.viewport, cmd = l.viewport.Update(msg)
	return l, cmd
}

func (l LogViewer) View() string {
	return l.viewport.View()
}

func (l *LogViewer) AppendLine(level string, text string) {
	line := fmt.Sprintf("%s %s", levelPrefix(level), text)
	l.lines = append(l.lines, line)
	l.viewport.SetContent(strings.Join(l.lines, "\n"))
	if l.autoScroll {
		l.viewport.GotoBottom()
	}
}

func (l *LogViewer) SetSize(width int, height int) {
	l.currentWidth = width
	l.viewport.Width = width
	l.viewport.Height = height
	l.viewport.SetContent(strings.Join(l.lines, "\n"))
}

func levelPrefix(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "RUN":
		return lipgloss.NewStyle().Foreground(theme.Accent).Bold(true).Render("[RUN]")
	case "DONE":
		return lipgloss.NewStyle().Foreground(theme.Accent2).Bold(true).Render("[DONE]")
	case "WARN":
		return lipgloss.NewStyle().Foreground(theme.Warning).Bold(true).Render("[WARN]")
	case "CRIT":
		return lipgloss.NewStyle().Foreground(theme.Danger).Bold(true).Render("[CRIT]")
	case "TOOL":
		return lipgloss.NewStyle().Foreground(theme.Subtle).Bold(true).Render("[TOOL]")
	default:
		return lipgloss.NewStyle().Foreground(theme.Muted).Bold(true).Render("[INFO]")
	}
}
