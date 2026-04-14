package screens

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/installer"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/components"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type installerProgressMsg struct {
	Job installer.ToolJob
}

type installerStartMsg struct{}

type installerDoneMsg struct {
	Err error
}

type InstallerModel struct {
	width     int
	height    int
	cfg       *config.Config
	backend   *installer.Installer
	jobs      map[string]installer.ToolJob
	order     []string
	logs      []string
	progress  components.ProgressModel
	running   bool
	done      bool
	errMsg    string
	cancelRun context.CancelFunc
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
		runCtx, cancel := context.WithCancel(context.Background())
		m.cancelRun = cancel
		m.running = true
		m.done = false
		m.errMsg = ""
		m.logs = append(m.logs, "[RUN] installer run started")
		m.updateProgress()
		return m, tea.Batch(startInstallerCmd(runCtx, m.backend), waitInstallerProgressCmd(m.backend.Progress()))
	case tea.WindowSizeMsg:
		m.SetSize(msg.Width, msg.Height)
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
		m.cancelRun = nil
		if errors.Is(msg.Err, context.Canceled) {
			m.errMsg = ""
			m.logs = append(m.logs, "[WARN] installer run canceled")
		} else if msg.Err != nil {
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
		case "q", "Q", "esc":
			if m.running && m.cancelRun != nil {
				m.cancelRun()
				m.logs = append(m.logs, "[WARN] cancel requested; returning to splash")
			}
			m.running = false
			m.done = true
			m.cancelRun = nil
			m.updateProgress()
			return m, func() tea.Msg { return BackToSplashMsg{} }
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
	if m.width > 0 && m.height > 0 && (m.width < minTerminalWidth || m.height < minTerminalHeight) {
		return theme.Panel.Width(screenContentWidth(m.width)).Render(responsiveSizeNotice(m.width, m.height))
	}

	completed, total, active := m.countJobStates()
	if total == 0 {
		total = 1
	}
	statusLine := fmt.Sprintf("Overall Progress  %d/%d", completed, total)
	if active > 0 {
		statusLine += fmt.Sprintf("  (%d active)", active)
	}
	bodyWidth := screenContentWidth(m.width)
	nameColWidth := clampInt(bodyWidth/3, 14, 26)
	maxRows := 10
	if m.height < 34 {
		maxRows = 7
	}
	if m.height < 28 {
		maxRows = 5
	}
	if m.height < 24 {
		maxRows = 3
	}

	categorySections := []string{
		m.renderCategory("system", "SYSTEM", maxRows, nameColWidth),
		m.renderCategory("go", "GO TOOLS", maxRows, nameColWidth),
		m.renderCategory("post-go", "POST-GO", maxRows, nameColWidth),
		m.renderCategory("binary", "BINARIES", maxRows, nameColWidth),
		m.renderCategory("python", "PYTHON TOOLS", maxRows, nameColWidth),
		m.renderCategory("wordlist", "WORDLISTS", maxRows, nameColWidth),
	}

	categoryBlock := strings.Join(categorySections, "\n\n")
	if leftW, rightW, stacked := splitColumns(bodyWidth, 40, 40, 2); !stacked {
		left := strings.Join(categorySections[:3], "\n\n")
		right := strings.Join(categorySections[3:], "\n\n")
		categoryBlock = lipgloss.JoinHorizontal(
			lipgloss.Top,
			lipgloss.NewStyle().Width(leftW).Render(left),
			lipgloss.NewStyle().Width(rightW).Render(right),
		)
	}

	logLines := strings.Join(m.logs, "\n")
	if logLines == "" {
		logLines = "[INFO] no installer logs yet"
	}
	logPanelWidth := clampInt(bodyWidth-4, 20, 220)

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
		categoryBlock,
		theme.Divider(),
		theme.BoldText.Render("LIVE LOG"),
		theme.Panel.Width(logPanelWidth).Render(logLines),
		theme.MutedText.Render("[R] Retry  [S] Skip Failed  [Q/Esc] Back"),
	}
	if m.errMsg != "" {
		content = append(content, renderScreenErrorOverlay(m.errMsg))
	}
	return theme.Panel.Width(bodyWidth).Render(strings.Join(content, "\n"))
}

func (m *InstallerModel) SetSize(width int, height int) {
	m.width = width
	m.height = height
	calcWidth := width - 20
	if calcWidth < 18 {
		calcWidth = 18
	}
	if calcWidth > 120 {
		calcWidth = 120
	}
	m.progress.SetWidth(calcWidth)
}

func (m *InstallerModel) updateProgress() {
	completed, total, active := m.countJobStates()
	if total == 0 {
		m.progress.SetPercent(0)
		m.progress.SetLabel("waiting for jobs")
		return
	}

	percent := float64(completed) / float64(total)
	if active > 0 {
		percent += float64(active) * 0.25 / float64(total)
		if percent < 0.02 {
			percent = 0.02
		}
		if percent > 0.99 {
			percent = 0.99
		}
		m.progress.SetLabel(fmt.Sprintf("%d/%d completed | %d active", completed, total, active))
	} else {
		m.progress.SetLabel(fmt.Sprintf("%d/%d jobs", completed, total))
	}
	m.progress.SetPercent(percent)
}

func (m InstallerModel) countJobStates() (completed int, total int, active int) {
	for _, job := range m.jobs {
		if job.Status == installer.StatusDone || job.Status == installer.StatusSkipped {
			completed++
		}
		if job.Status == installer.StatusRunning {
			active++
		}
	}
	return completed, len(m.jobs), active
}

func (m InstallerModel) renderCategory(category string, title string, maxRows int, nameColWidth int) string {
	rows := make([]string, 0, 16)
	for _, name := range m.order {
		job, ok := m.jobs[name]
		if !ok || job.Category != category {
			continue
		}
		jobName := truncateText(job.Name, nameColWidth)
		status := strings.ToUpper(string(job.Status))
		rows = append(rows, fmt.Sprintf("%s %-*s %s", statusSymbol(job.Status), nameColWidth, jobName, status))
	}
	sort.Strings(rows)
	if len(rows) == 0 {
		rows = append(rows, "(none)")
	}
	if maxRows < 1 {
		maxRows = 1
	}
	if len(rows) > maxRows {
		rows = rows[:maxRows]
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

func startInstallerCmd(ctx context.Context, inst *installer.Installer) tea.Cmd {
	return func() tea.Msg {
		if inst == nil {
			return installerDoneMsg{Err: fmt.Errorf("installer backend is nil")}
		}
		if ctx == nil {
			ctx = context.Background()
		}
		err := inst.Run(ctx)
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
