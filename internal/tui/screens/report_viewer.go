package screens

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/n0rmxl/n0rmxl/internal/tui/theme"
)

type reportLoadedMsg struct {
	path    string
	content string
	err     error
}

type reportActionMsg struct {
	message string
	err     error
}

type ReportViewerModel struct {
	width       int
	height      int
	workspace   string
	reportPath  string
	viewport    viewport.Model
	rawContent  string
	lastMessage string
	lastError   string
}

func NewReportViewerModel(reportPath string) ReportViewerModel {
	vp := viewport.New(0, 0)
	vp.SetContent("No report loaded.")
	return ReportViewerModel{
		reportPath: strings.TrimSpace(reportPath),
		viewport:   vp,
	}
}

func (m ReportViewerModel) Init() tea.Cmd {
	return m.ReloadCmd()
}

func (m ReportViewerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.SetSize(msg.Width, msg.Height)
		return m, nil
	case reportLoadedMsg:
		if msg.err != nil {
			m.lastError = msg.err.Error()
			m.lastMessage = ""
			m.rawContent = ""
			m.viewport.SetContent("Report is not available yet.\n\n" + m.lastError)
			return m, nil
		}
		m.lastError = ""
		m.reportPath = msg.path
		m.rawContent = msg.content
		m.renderViewport()
		return m, nil
	case reportActionMsg:
		if msg.err != nil {
			m.lastError = msg.err.Error()
			m.lastMessage = ""
		} else {
			m.lastError = ""
			m.lastMessage = msg.message
		}
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "r", "R":
			return m, m.ReloadCmd()
		case "m", "M":
			m.reportPath = filepath.Join(m.workspace, "reports", "report.md")
			return m, m.ReloadCmd()
		case "h", "H":
			m.reportPath = filepath.Join(m.workspace, "reports", "report.html")
			return m, tea.Batch(m.ReloadCmd(), openReportFileCmd(m.reportPath))
		case "p", "P":
			m.reportPath = filepath.Join(m.workspace, "reports", "report.pdf")
			return m, tea.Batch(m.ReloadCmd(), openReportFileCmd(m.reportPath))
		case "c", "C":
			return m, copyPathCmd(m.reportPath)
		case "o", "O", "enter":
			return m, openReportFileCmd(m.reportPath)
		}
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	return m, cmd
}

func (m ReportViewerModel) View() string {
	title := theme.RenderTitle("REPORT VIEWER", m.width-8)
	pathLine := theme.RenderKeyValue("Path", defaultText(m.reportPath, "n/a"))
	help := theme.MutedText.Render("m markdown  h html  p pdf  o open  c copy path  r reload")

	status := ""
	if m.lastError != "" {
		status = theme.Badge("ERROR", theme.Danger).Render("ERROR") + " " + m.lastError
	} else if m.lastMessage != "" {
		status = theme.Badge("INFO", theme.Accent2).Render("INFO") + " " + m.lastMessage
	}

	body := []string{
		title,
		theme.Divider(),
		pathLine,
		theme.Panel.Width(max(90, m.width-8)).Render(m.viewport.View()),
		help,
	}
	if status != "" {
		body = append(body, status)
	}
	if overlay := renderScreenErrorOverlay(m.lastError); overlay != "" {
		body = append(body, overlay)
	}
	return theme.AppFrame.Render(strings.Join(body, "\n"))
}

func (m *ReportViewerModel) SetSize(width int, height int) {
	m.width = width
	m.height = height
	m.viewport.Width = max(84, width-16)
	m.viewport.Height = max(10, height-16)
	m.renderViewport()
}

func (m *ReportViewerModel) SetWorkspace(workspace string) {
	m.workspace = strings.TrimSpace(workspace)
	if strings.TrimSpace(m.reportPath) == "" && m.workspace != "" {
		m.reportPath = filepath.Join(m.workspace, "reports", "report.md")
	}
}

func (m *ReportViewerModel) SetReportPath(reportPath string) {
	m.reportPath = strings.TrimSpace(reportPath)
}

func (m ReportViewerModel) ReloadCmd() tea.Cmd {
	reportPath := strings.TrimSpace(m.reportPath)
	if reportPath == "" && strings.TrimSpace(m.workspace) != "" {
		reportPath = filepath.Join(m.workspace, "reports", "report.md")
	}
	return func() tea.Msg {
		if strings.TrimSpace(reportPath) == "" {
			return reportLoadedMsg{path: reportPath, err: fmt.Errorf("report path is empty")}
		}
		info, err := os.Stat(reportPath)
		if err != nil {
			return reportLoadedMsg{path: reportPath, err: err}
		}
		if strings.EqualFold(filepath.Ext(reportPath), ".pdf") {
			content := fmt.Sprintf("PDF report ready.\n\nPath: %s\nSize: %d bytes\n\nPress 'o' to open with your system viewer.", reportPath, info.Size())
			return reportLoadedMsg{path: reportPath, content: content, err: nil}
		}
		raw, readErr := os.ReadFile(reportPath)
		if readErr != nil {
			return reportLoadedMsg{path: reportPath, err: readErr}
		}
		return reportLoadedMsg{path: reportPath, content: string(raw), err: nil}
	}
}

func (m *ReportViewerModel) renderViewport() {
	if m.viewport.Width <= 0 {
		return
	}
	content := strings.TrimSpace(m.rawContent)
	if content == "" {
		m.viewport.SetContent("No report content available.")
		return
	}
	if strings.EqualFold(filepath.Ext(m.reportPath), ".md") {
		renderer, err := glamour.NewTermRenderer(
			glamour.WithAutoStyle(),
			glamour.WithWordWrap(max(48, m.viewport.Width-4)),
		)
		if err == nil {
			if rendered, renderErr := renderer.Render(content); renderErr == nil {
				m.viewport.SetContent(rendered)
				m.viewport.GotoTop()
				return
			}
		}
	}
	m.viewport.SetContent(content)
	m.viewport.GotoTop()
}

func openReportFileCmd(path string) tea.Cmd {
	path = strings.TrimSpace(path)
	return func() tea.Msg {
		if path == "" {
			return reportActionMsg{err: fmt.Errorf("path is empty")}
		}
		if _, err := os.Stat(path); err != nil {
			return reportActionMsg{err: err}
		}
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "windows":
			cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
		case "darwin":
			cmd = exec.Command("open", path)
		default:
			cmd = exec.Command("xdg-open", path)
		}
		if err := cmd.Start(); err != nil {
			return reportActionMsg{err: err}
		}
		return reportActionMsg{message: "opened " + path}
	}
}

func copyPathCmd(path string) tea.Cmd {
	path = strings.TrimSpace(path)
	return func() tea.Msg {
		if path == "" {
			return reportActionMsg{err: fmt.Errorf("path is empty")}
		}
		if err := clipboard.WriteAll(path); err != nil {
			return reportActionMsg{err: err}
		}
		return reportActionMsg{message: "copied path to clipboard"}
	}
}
