package screens

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/installer"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/components"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
	tea "github.com/charmbracelet/bubbletea"
)

type installerProgressMsg struct {
	Job installer.ToolJob
}

type installerStartMsg struct{}

type installerDoneMsg struct {
	Err error
}

type InstallerModel struct {
	width    int
	height   int
	cfg      *config.Config
	backend  *installer.Installer
	jobs     map[string]installer.ToolJob
	order    []string
	logs     []string
	progress components.ProgressModel
	running  bool
	done     bool
	errMsg   string
}

func NewInstallerModel() InstallerModel {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.DefaultConfig()
	}
	backend := installer.NewInstaller(cfg)
	backend.RegisterAll()
	jobs := make(map[string]installer.ToolJob)
	order := make([]string, 0, len(backend.Jobs()))
	for _, job := range backend.Jobs() {
		if job == nil {
			continue
		}
		jobs[job.Name] = *job
		order = append(order, job.Name)
	}
	return InstallerModel{
		cfg:      cfg,
		backend:  backend,
		jobs:     jobs,
		order:    order,
		logs:     []string{"[INFO] installer ready"},
		progress: components.NewProgressBar(44),
		running:  false,
		done:     false,
	}
}

func (m InstallerModel) Init() tea.Cmd {
	if m.backend == nil {
		return nil
	}
	return installerStartCmd()
}

func (m InstallerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case installerStartMsg:
		if m.backend == nil || m.running {
			return m, nil
		}
		m.running = true
		m.done = false
		m.errMsg = ""
		m.logs = append(m.logs, "[RUN] installer run started")
		m.updateProgress()
		return m, tea.Batch(startInstallerCmd(m.backend), waitInstallerProgressCmd(m.backend.Progress()))
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		calcWidth := msg.Width - 28
		if calcWidth < 20 {
			calcWidth = 20
		}
		if calcWidth > 70 {
			calcWidth = 70
		}
		m.progress.SetWidth(calcWidth)
		return m, nil
	case installerProgressMsg:
		m.jobs[msg.Job.Name] = msg.Job
		m.logs = append(m.logs, fmt.Sprintf("[%s] %s - %s", strings.ToUpper(string(msg.Job.Status)), msg.Job.Name, msg.Job.Output))
		if len(m.logs) > 12 {
			m.logs = m.logs[len(m.logs)-12:]
		}
		m.updateProgress()
		if m.running && m.backend != nil {
			return m, waitInstallerProgressCmd(m.backend.Progress())
		}
		return m, nil
	case installerDoneMsg:
		m.running = false
		m.done = true
		if msg.Err != nil {
			m.errMsg = msg.Err.Error()
			m.logs = append(m.logs, "[ERROR] installer finished with errors")
		} else {
			m.errMsg = ""
			m.logs = append(m.logs, "[DONE] installer finished")
		}
		m.updateProgress()
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "r", "R":
			if !m.running {
				m.logs = append(m.logs, "[RUN] retrying installer run")
				return m, installerStartCmd()
			}
			return m, nil
		case "s", "S":
			if m.done {
				for name, job := range m.jobs {
					if job.Status == installer.StatusFailed {
						job.Status = installer.StatusSkipped
						job.Output = "manually skipped"
						m.jobs[name] = job
					}
				}
				m.logs = append(m.logs, "[WARN] failed tools marked as skipped")
				m.updateProgress()
			}
			return m, nil
		}
	}
	return m, nil
}

func (m InstallerModel) View() string {
	if m.width > 0 && m.height > 0 && (m.width < 100 || m.height < 30) {
		return theme.Panel.Render("Terminal is too small. Minimum size is 100x30.")
	}

	installed, total := m.countInstalled()
	if total == 0 {
		total = 1
	}
	statusLine := fmt.Sprintf("Overall Progress  %d/%d", installed, total)

	categorySections := []string{
		m.renderCategory("system", "SYSTEM"),
		m.renderCategory("go", "GO TOOLS"),
		m.renderCategory("post-go", "POST-GO"),
		m.renderCategory("binary", "BINARIES"),
		m.renderCategory("python", "PYTHON TOOLS"),
		m.renderCategory("wordlist", "WORDLISTS"),
	}

	logLines := strings.Join(m.logs, "\n")
	if logLines == "" {
		logLines = "[INFO] no installer logs yet"
	}

	state := "running"
	if m.done {
		state = "done"
	}
	if m.errMsg != "" {
		state = "error"
	}

	content := []string{
		theme.BoldText.Render("N0RMXL INSTALLER"),
		theme.RenderKeyValue("State", strings.ToUpper(state)),
		statusLine,
		m.progress.View(),
		theme.Divider(),
		strings.Join(categorySections, "\n\n"),
		theme.Divider(),
		theme.BoldText.Render("LIVE LOG"),
		theme.Panel.Render(logLines),
		theme.MutedText.Render("[R] Retry  [S] Skip Failed  [Q] Back"),
	}
	if m.errMsg != "" {
		content = append(content, renderScreenErrorOverlay(m.errMsg))
	}
	return theme.Panel.Render(strings.Join(content, "\n"))
}

func (m *InstallerModel) SetSize(width int, height int) {
	m.width = width
	m.height = height
	calcWidth := width - 28
	if calcWidth < 20 {
		calcWidth = 20
	}
	if calcWidth > 70 {
		calcWidth = 70
	}
	m.progress.SetWidth(calcWidth)
}

func (m *InstallerModel) updateProgress() {
	installed, total := m.countInstalled()
	if total == 0 {
		m.progress.SetPercent(0)
		m.progress.SetLabel("waiting for jobs")
		return
	}
	m.progress.SetPercent(float64(installed) / float64(total))
	m.progress.SetLabel(fmt.Sprintf("%d/%d jobs", installed, total))
}

func (m InstallerModel) countInstalled() (int, int) {
	installed := 0
	for _, job := range m.jobs {
		if job.Status == installer.StatusDone || job.Status == installer.StatusSkipped {
			installed++
		}
	}
	return installed, len(m.jobs)
}

func (m InstallerModel) renderCategory(category string, title string) string {
	rows := make([]string, 0, 16)
	for _, name := range m.order {
		job, ok := m.jobs[name]
		if !ok || job.Category != category {
			continue
		}
		rows = append(rows, fmt.Sprintf("%s %-20s %s", statusSymbol(job.Status), job.Name, strings.ToUpper(string(job.Status))))
	}
	sort.Strings(rows)
	if len(rows) == 0 {
		rows = append(rows, "(none)")
	}
	if len(rows) > 10 {
		rows = rows[:10]
		rows = append(rows, "...")
	}
	return theme.Panel.Render(theme.BoldText.Render(title) + "\n" + strings.Join(rows, "\n"))
}

func statusSymbol(status installer.InstallStatus) string {
	switch status {
	case installer.StatusRunning:
		return "●"
	case installer.StatusDone:
		return "✓"
	case installer.StatusFailed:
		return "✗"
	case installer.StatusSkipped:
		return "↷"
	default:
		return "○"
	}
}

func startInstallerCmd(inst *installer.Installer) tea.Cmd {
	return func() tea.Msg {
		if inst == nil {
			return installerDoneMsg{Err: fmt.Errorf("installer backend is nil")}
		}
		err := inst.Run(context.Background())
		return installerDoneMsg{Err: err}
	}
}

func installerStartCmd() tea.Cmd {
	return func() tea.Msg {
		return installerStartMsg{}
	}
}

func waitInstallerProgressCmd(progress <-chan installer.ToolJob) tea.Cmd {
	return func() tea.Msg {
		job, ok := <-progress
		if !ok {
			return nil
		}
		return installerProgressMsg{Job: job}
	}
}
