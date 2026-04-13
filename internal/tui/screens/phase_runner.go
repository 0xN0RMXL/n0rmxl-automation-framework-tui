package screens

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	cfgpkg "github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	phasespkg "github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/phases"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/components"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
)

type phaseRunnerTickMsg time.Time

type phaseRunnerStartMsg struct{}

type phaseRunnerPhasePlanMsg struct {
	Phase int
	Total int
}

type phaseRunnerPhaseStartedMsg struct {
	Phase int
}

type phaseRunnerPhaseFinishedMsg struct {
	Phase int
	Err   error
}

type phaseRunnerJobUpdateMsg struct {
	Phase int
	Tool  string
	Event string
	Line  string
	Items int
}

type phaseRunnerExecutionDoneMsg struct {
	Target models.Target
	Phases []int
	Err    error
}

type PhaseRunCompletedMsg struct {
	Target models.Target
	Phases []int
}

type phaseJobState struct {
	Phase    int
	Name     string
	Status   models.PhaseStatus
	Progress float64
	Items    int
}

type phaseExecutionControl struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	runner *engine.PhaseRunner
}

func (c *phaseExecutionControl) setCancel(cancel context.CancelFunc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cancel = cancel
}

func (c *phaseExecutionControl) setRunner(runner *engine.PhaseRunner) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runner = runner
}

func (c *phaseExecutionControl) pause() {
	c.mu.Lock()
	runner := c.runner
	c.mu.Unlock()
	if runner != nil {
		runner.Pause()
	}
}

func (c *phaseExecutionControl) resume() {
	c.mu.Lock()
	runner := c.runner
	c.mu.Unlock()
	if runner != nil {
		runner.Resume()
	}
}

func (c *phaseExecutionControl) stop() {
	c.mu.Lock()
	cancel := c.cancel
	runner := c.runner
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if runner != nil {
		runner.Stop()
	}
}

type PhaseRunnerModel struct {
	width        int
	height       int
	target       models.Target
	workspaceDir string
	phases       []int
	jobs         []phaseJobState
	index        int
	mode         string
	paused       bool
	stopped      bool
	startedAt    time.Time
	elapsed      time.Duration
	logViewer    components.LogViewer
	findings     components.TableModel
	progress     components.ProgressModel
	keymap       components.PhaseKeyMap
	completedMsg bool
	runStarted   bool
	runDone      bool
	runErr       string
	phaseTotals  map[int]int
	phaseDone    map[int]int
	eventCh      chan tea.Msg
	control      *phaseExecutionControl
}

func NewPhaseRunnerModel() PhaseRunnerModel {
	findings := components.NewTable([]table.Column{
		{Title: "ID", Width: 12},
		{Title: "Severity", Width: 12},
		{Title: "Phase", Width: 8},
		{Title: "Title", Width: 44},
		{Title: "Target", Width: 24},
	}, []table.Row{})
	m := PhaseRunnerModel{
		mode:        "log",
		startedAt:   time.Now(),
		logViewer:   components.NewLogViewer(72, 20),
		findings:    findings,
		progress:    components.NewProgressBar(42),
		keymap:      components.NewPhaseKeyMap(),
		phaseTotals: make(map[int]int),
		phaseDone:   make(map[int]int),
	}
	m.progress.SetLabel("waiting for phase selection")
	m.jobs = buildPhaseJobs([]int{0})
	return m
}

func (m PhaseRunnerModel) Init() tea.Cmd {
	return tea.Batch(
		func() tea.Msg { return phaseRunnerStartMsg{} },
		phaseRunnerTickCmd(),
	)
}

func (m *PhaseRunnerModel) SetTargetAndPhases(target models.Target, phases []int) {
	if target.Profile == "" {
		target.Profile = models.Normal
	}
	m.target = target
	m.workspaceDir = strings.TrimSpace(target.WorkspaceDir)
	m.phases = normalizePhaseSelection(phases)
	m.jobs = buildPhaseJobs(m.phases)
	m.index = 0
	m.mode = "log"
	m.paused = false
	m.stopped = false
	m.startedAt = time.Now()
	m.elapsed = 0
	m.logViewer = components.NewLogViewer(max(36, m.width-46), max(10, m.height-14))
	m.findings = components.NewTable([]table.Column{
		{Title: "ID", Width: 12},
		{Title: "Severity", Width: 12},
		{Title: "Phase", Width: 8},
		{Title: "Title", Width: 44},
		{Title: "Target", Width: 24},
	}, []table.Row{})
	m.progress = components.NewProgressBar(42)
	m.progress.SetLabel("execution in progress")
	m.progress.SetPercent(0)
	m.logViewer.AppendLine("RUN", fmt.Sprintf("Queued %d phase(s) for %s", len(m.jobs), defaultText(m.target.Domain, "unknown target")))
	m.completedMsg = false
	m.runStarted = false
	m.runDone = false
	m.runErr = ""
	m.phaseTotals = make(map[int]int)
	m.phaseDone = make(map[int]int)
	m.eventCh = nil
	m.control = nil
}

func (m *PhaseRunnerModel) Configure(target models.Target, phases []int) {
	m.SetTargetAndPhases(target, phases)
}

func (m PhaseRunnerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmds := make([]tea.Cmd, 0, 4)
	waitForEvents := false

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.SetSize(msg.Width, msg.Height)
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.index > 0 {
				m.index--
			}
		case "down", "j":
			if m.index < len(m.jobs)-1 {
				m.index++
			}
		case "p":
			if !m.runDone {
				m.paused = true
				if m.control != nil {
					m.control.pause()
				}
				m.logViewer.AppendLine("WARN", "Execution paused")
			}
		case "r":
			if !m.runDone {
				m.paused = false
				if m.control != nil {
					m.control.resume()
				}
				m.logViewer.AppendLine("RUN", "Execution resumed")
			}
		case "s", "ctrl+c":
			if !m.runDone {
				m.stopped = true
				m.progress.SetLabel("execution stopped")
				if m.control != nil {
					m.control.stop()
				}
				m.logViewer.AppendLine("CRIT", "Execution stopped by operator")
			}
		case "l":
			m.mode = "log"
		case "f":
			m.mode = "findings"
		}
	case phaseRunnerStartMsg:
		if m.runStarted {
			break
		}
		m.runStarted = true
		m.eventCh = make(chan tea.Msg, 2048)
		m.control = &phaseExecutionControl{}
		go executePhasesForTUI(m.target, m.phases, m.eventCh, m.control)
		waitForEvents = true
	case phaseRunnerPhasePlanMsg:
		m.phaseTotals[msg.Phase] = msg.Total
		m.phaseDone[msg.Phase] = 0
		if idx := m.findPhaseIndex(msg.Phase); idx >= 0 {
			m.jobs[idx].Progress = 0
			if msg.Total == 0 {
				m.jobs[idx].Progress = 1
				m.jobs[idx].Status = models.PhaseSkipped
			}
		}
		waitForEvents = true
	case phaseRunnerPhaseStartedMsg:
		if idx := m.findPhaseIndex(msg.Phase); idx >= 0 {
			m.jobs[idx].Status = models.PhaseRunning
			m.jobs[idx].Progress = 0
		}
		m.logViewer.AppendLine("RUN", fmt.Sprintf("Phase %d started: %s", msg.Phase, phaseLabel(msg.Phase)))
		waitForEvents = true
	case phaseRunnerPhaseFinishedMsg:
		if idx := m.findPhaseIndex(msg.Phase); idx >= 0 {
			if msg.Err != nil {
				m.jobs[idx].Status = models.PhaseFailed
			} else if m.jobs[idx].Status != models.PhaseSkipped {
				m.jobs[idx].Status = models.PhaseDone
			}
			m.jobs[idx].Progress = 1
		}
		if msg.Err != nil {
			m.logViewer.AppendLine("CRIT", fmt.Sprintf("Phase %d failed: %v", msg.Phase, msg.Err))
		} else {
			m.logViewer.AppendLine("DONE", fmt.Sprintf("Phase %d finished", msg.Phase))
		}
		waitForEvents = true
	case phaseRunnerJobUpdateMsg:
		m.applyJobUpdate(msg)
		waitForEvents = true
	case phaseRunnerExecutionDoneMsg:
		m.runDone = true
		m.stopped = true
		m.paused = false
		if msg.Err != nil {
			m.runErr = msg.Err.Error()
			m.progress.SetLabel("failed")
			m.logViewer.AppendLine("CRIT", "Execution failed: "+msg.Err.Error())
			waitForEvents = true
			break
		}
		m.progress.SetLabel("completed")
		m.logViewer.AppendLine("DONE", "All selected phases completed")
		if !m.completedMsg {
			m.completedMsg = true
			cmds = append(cmds, func() tea.Msg {
				return PhaseRunCompletedMsg{Target: msg.Target, Phases: append([]int{}, msg.Phases...)}
			})
		}
		waitForEvents = true
	case phaseRunnerTickMsg:
		if !m.startedAt.IsZero() {
			m.elapsed = time.Since(m.startedAt)
		}
		m.syncProgress()
		m.refreshFindingsTable()
		cmds = append(cmds, phaseRunnerTickCmd())
	}

	if waitForEvents && m.eventCh != nil {
		cmds = append(cmds, waitPhaseRunnerEventCmd(m.eventCh))
	}

	if updated, cmd := m.logViewer.Update(msg); cmd != nil {
		if cast, ok := updated.(components.LogViewer); ok {
			m.logViewer = cast
		}
		cmds = append(cmds, cmd)
	}
	if updated, cmd := m.findings.Update(msg); cmd != nil {
		if cast, ok := updated.(components.TableModel); ok {
			m.findings = cast
		}
		cmds = append(cmds, cmd)
	}
	if updated, cmd := m.progress.Update(msg); cmd != nil {
		if cast, ok := updated.(components.ProgressModel); ok {
			m.progress = cast
		}
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m PhaseRunnerModel) View() string {
	title := theme.RenderTitle(
		fmt.Sprintf("PHASE RUNNER | TARGET: %s", strings.ToUpper(defaultText(m.target.Domain, "N/A"))),
		m.width-8,
	)
	statusLine := strings.Join([]string{
		theme.RenderKeyValue("Mode", m.mode),
		theme.RenderKeyValue("Paused", fmt.Sprintf("%t", m.paused)),
		theme.RenderKeyValue("Elapsed", m.elapsed.Truncate(time.Second).String()),
		theme.RenderKeyValue("Workspace", defaultText(m.workspaceDir, "not set")),
	}, "  ")

	leftWidth := max(40, m.width/2-5)
	rightWidth := max(42, m.width-leftWidth-10)
	left := theme.Panel.Width(leftWidth).Render(strings.Join([]string{
		theme.SectionHeader.Render("Queued Phases"),
		strings.Join(m.renderJobLines(), "\n"),
		"",
		m.progress.View(),
	}, "\n"))

	rightBody := m.logViewer.View()
	if m.mode == "findings" {
		rightBody = m.findings.View()
	}
	rightTitle := "Live Logs"
	if m.mode == "findings" {
		rightTitle = "Findings Snapshot"
	}
	right := theme.Panel.Width(rightWidth).Render(strings.Join([]string{
		theme.SectionHeader.Render(rightTitle),
		rightBody,
	}, "\n"))

	help := components.RenderHelpBar(
		m.keymap.RunPhase,
		m.keymap.Pause,
		m.keymap.Resume,
		m.keymap.Stop,
		m.keymap.ViewLog,
		m.keymap.ViewFinds,
	)
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	lines := []string{title, theme.Divider(), statusLine, body, help}
	if strings.TrimSpace(m.runErr) != "" {
		lines = append(lines, theme.Badge("ERROR", theme.Danger).Render("ERROR")+" "+m.runErr)
	}
	return theme.AppFrame.Render(strings.Join(lines, "\n"))
}

func (m *PhaseRunnerModel) SetSize(width int, height int) {
	m.width = width
	m.height = height
	m.logViewer.SetSize(max(36, width/2-10), max(10, height-16))
	m.findings.SetWidth(max(42, width/2-10))
	m.findings.SetHeight(max(8, height-18))
}

func (m *PhaseRunnerModel) renderJobLines() []string {
	if len(m.jobs) == 0 {
		return []string{theme.MutedText.Render("No phases queued.")}
	}
	lines := make([]string, 0, len(m.jobs))
	for i, job := range m.jobs {
		prefix := " "
		if i == m.index {
			prefix = ">"
		}
		line := fmt.Sprintf("%s P%d %-38s %-18s %3.0f%%", prefix, job.Phase, job.Name, theme.StatusBadge(string(job.Status)), job.Progress*100)
		if i == m.index {
			line = theme.TableSelected.Render(line)
		}
		lines = append(lines, line)
	}
	return lines
}

func (m *PhaseRunnerModel) applyJobUpdate(update phaseRunnerJobUpdateMsg) {
	if idx := m.findPhaseIndex(update.Phase); idx >= 0 {
		total := m.phaseTotals[update.Phase]
		if total <= 0 {
			total = 1
		}
		switch update.Event {
		case "start":
			m.jobs[idx].Status = models.PhaseRunning
		case "done", "skip", "error":
			m.phaseDone[update.Phase]++
			if m.phaseDone[update.Phase] > total {
				m.phaseDone[update.Phase] = total
			}
			m.jobs[idx].Progress = float64(m.phaseDone[update.Phase]) / float64(total)
			if update.Items > 0 {
				m.jobs[idx].Items += update.Items
			}
			if update.Event == "error" {
				m.jobs[idx].Status = models.PhaseFailed
			}
		}
	}

	line := strings.TrimSpace(update.Line)
	tool := strings.TrimSpace(update.Tool)
	prefix := fmt.Sprintf("P%d", update.Phase)
	if tool != "" {
		prefix += "|" + tool
	}
	switch update.Event {
	case "start":
		m.logViewer.AppendLine("RUN", prefix+" started")
	case "done":
		if update.Items > 0 {
			m.logViewer.AppendLine("DONE", fmt.Sprintf("%s done (%d items)", prefix, update.Items))
		} else {
			m.logViewer.AppendLine("DONE", prefix+" done")
		}
	case "skip":
		if line == "" {
			line = "skipped"
		}
		m.logViewer.AppendLine("WARN", prefix+" "+line)
	case "error":
		if line == "" {
			line = "failed"
		}
		m.logViewer.AppendLine("CRIT", prefix+" "+line)
	case "line":
		if line != "" {
			m.logViewer.AppendLine("TOOL", prefix+" "+line)
		}
	}
}

func (m *PhaseRunnerModel) syncProgress() {
	if len(m.jobs) == 0 {
		m.progress.SetPercent(0)
		m.progress.SetLabel("no jobs")
		return
	}
	total := float64(len(m.jobs))
	sum := 0.0
	done := 0
	for _, job := range m.jobs {
		sum += job.Progress
		if job.Status == models.PhaseDone || job.Status == models.PhaseSkipped {
			done++
		}
	}
	m.progress.SetPercent(sum / total)
	if m.paused {
		m.progress.SetLabel("paused")
		return
	}
	if m.runDone {
		if strings.TrimSpace(m.runErr) != "" {
			m.progress.SetLabel("failed")
			return
		}
		m.progress.SetLabel("completed")
		return
	}
	if m.stopped {
		m.progress.SetLabel("stopped")
		return
	}
	m.progress.SetLabel(fmt.Sprintf("%d/%d phases complete", done, len(m.jobs)))
}

func (m *PhaseRunnerModel) refreshFindingsTable() {
	if strings.TrimSpace(m.workspaceDir) == "" {
		m.findings.SetRows([]table.Row{})
		return
	}
	db, err := models.InitFindingsDB(m.workspaceDir)
	if err != nil {
		return
	}
	defer db.Close()
	findings, err := models.GetFindings(db, models.FindingFilter{})
	if err != nil {
		return
	}
	sort.SliceStable(findings, func(i int, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findingSeverityRank(findings[i].Severity) > findingSeverityRank(findings[j].Severity)
		}
		if findings[i].CVSS != findings[j].CVSS {
			return findings[i].CVSS > findings[j].CVSS
		}
		return findings[i].Timestamp.After(findings[j].Timestamp)
	})
	rows := make([]table.Row, 0, minInt(120, len(findings)))
	for _, finding := range findings {
		rows = append(rows, table.Row{
			defaultText(finding.ID, "n/a"),
			components.SeverityBadge(finding.Severity),
			fmt.Sprintf("%d", finding.Phase),
			defaultText(finding.Title, defaultText(finding.VulnClass, "Untitled finding")),
			defaultText(finding.Host, defaultText(finding.Target, "n/a")),
		})
		if len(rows) >= 120 {
			break
		}
	}
	m.findings.SetRows(rows)
}

func (m *PhaseRunnerModel) findPhaseIndex(phase int) int {
	for i, job := range m.jobs {
		if job.Phase == phase {
			return i
		}
	}
	return -1
}

func executePhasesForTUI(target models.Target, phases []int, updates chan<- tea.Msg, control *phaseExecutionControl) {
	defer close(updates)
	selected := normalizePhaseSelection(phases)
	target.Domain = strings.TrimSpace(target.Domain)
	if target.Profile == "" {
		target.Profile = models.Normal
	}
	if target.Domain == "" {
		updates <- phaseRunnerExecutionDoneMsg{Target: target, Phases: selected, Err: fmt.Errorf("target domain is required")}
		return
	}

	cfg, err := cfgpkg.Load()
	if err != nil {
		updates <- phaseRunnerExecutionDoneMsg{Target: target, Phases: selected, Err: err}
		return
	}

	workspaceRoot := inferWorkspaceRoot(target.WorkspaceDir, target.Domain, cfg.WorkspaceRoot)
	workspace, err := engine.InitWorkspace(workspaceRoot, &target)
	if err != nil {
		updates <- phaseRunnerExecutionDoneMsg{Target: target, Phases: selected, Err: err}
		return
	}
	target.WorkspaceDir = workspace.Root

	runCfgValue := cfgpkg.NewRunConfig(target.Profile, cfg)
	runCfg := &runCfgValue
	runCfg.Scope = &cfgpkg.Scope{
		Wildcards:  append([]string{}, target.Wildcards...),
		Explicit:   append([]string{}, target.Explicit...),
		IPRanges:   append([]string{}, target.IPRanges...),
		OutOfScope: append([]string{}, target.OutOfScope...),
	}

	checkpoint, err := engine.NewCheckpoint(workspace.Root)
	if err != nil {
		updates <- phaseRunnerExecutionDoneMsg{Target: target, Phases: selected, Err: err}
		return
	}
	defer checkpoint.Close()

	runCtx, cancel := context.WithCancel(context.Background())
	if control != nil {
		control.setCancel(cancel)
	}
	defer cancel()

	for _, phase := range selected {
		if runCtx.Err() != nil {
			updates <- phaseRunnerExecutionDoneMsg{Target: target, Phases: selected, Err: runCtx.Err()}
			return
		}

		jobs, phaseErr := phasespkg.JobsForPhase(phase, &target, workspace, runCfg)
		if phaseErr != nil {
			updates <- phaseRunnerExecutionDoneMsg{Target: target, Phases: selected, Err: phaseErr}
			return
		}
		updates <- phaseRunnerPhasePlanMsg{Phase: phase, Total: len(jobs)}
		updates <- phaseRunnerPhaseStartedMsg{Phase: phase}

		runner := engine.NewPhaseRunner(phase, runCfg, checkpoint)
		for _, job := range jobs {
			runner.AddJob(job)
		}
		if control != nil {
			control.setRunner(runner)
		}

		consumeDone := make(chan struct{})
		go func(currentPhase int, progress <-chan engine.JobUpdate) {
			for update := range progress {
				tool := ""
				items := 0
				if update.Job != nil {
					tool = strings.TrimSpace(update.Job.ToolName)
					items = update.Job.ItemsFound
				}
				updates <- phaseRunnerJobUpdateMsg{
					Phase: currentPhase,
					Tool:  tool,
					Event: strings.TrimSpace(update.Event),
					Line:  strings.TrimSpace(update.Line),
					Items: items,
				}
			}
			close(consumeDone)
		}(phase, runner.Progress)

		runErr := runner.Run(runCtx)
		<-consumeDone
		if control != nil {
			control.setRunner(nil)
		}
		updates <- phaseRunnerPhaseFinishedMsg{Phase: phase, Err: runErr}
		if runErr != nil {
			updates <- phaseRunnerExecutionDoneMsg{Target: target, Phases: selected, Err: runErr}
			return
		}
	}

	updates <- phaseRunnerExecutionDoneMsg{Target: target, Phases: selected, Err: nil}
}

func waitPhaseRunnerEventCmd(events <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		if events == nil {
			return nil
		}
		msg, ok := <-events
		if !ok {
			return nil
		}
		return msg
	}
}

func inferWorkspaceRoot(workspaceDir string, domain string, fallbackRoot string) string {
	workspaceDir = strings.TrimSpace(workspaceDir)
	domain = strings.TrimSpace(domain)
	if workspaceDir == "" {
		return strings.TrimSpace(fallbackRoot)
	}
	if domain != "" {
		if strings.EqualFold(filepath.Base(workspaceDir), domain) {
			return filepath.Dir(workspaceDir)
		}
	}
	return workspaceDir
}

func normalizePhaseSelection(phases []int) []int {
	set := make(map[int]struct{}, len(phases))
	for _, phase := range phases {
		if phase < 0 || phase > 9 {
			continue
		}
		set[phase] = struct{}{}
	}
	if len(set) == 0 {
		set[0] = struct{}{}
	}
	out := make([]int, 0, len(set))
	for phase := range set {
		out = append(out, phase)
	}
	sort.Ints(out)
	return out
}

func buildPhaseJobs(phases []int) []phaseJobState {
	jobs := make([]phaseJobState, 0, len(phases))
	for _, phase := range normalizePhaseSelection(phases) {
		jobs = append(jobs, phaseJobState{
			Phase:    phase,
			Name:     phaseLabel(phase),
			Status:   models.PhasePending,
			Progress: 0,
			Items:    0,
		})
	}
	return jobs
}

func phaseLabel(phase int) string {
	switch phase {
	case 0:
		return "Scope & Environment Setup"
	case 1:
		return "Passive Recon & OSINT"
	case 2:
		return "Active Enumeration"
	case 3:
		return "Fingerprinting & Tech Analysis"
	case 4:
		return "URL/API/Parameter Discovery"
	case 5:
		return "Automated Vulnerability Scanning"
	case 6:
		return "Manual Exploitation Wizard"
	case 7:
		return "Post-Exploitation"
	case 8:
		return "Cloud/Mobile/Thick Client"
	case 9:
		return "Reporting & Bounty Collection"
	default:
		return "Unknown"
	}
}

func phaseRunnerTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return phaseRunnerTickMsg(t)
	})
}

func findingSeverityRank(severity models.Severity) int {
	switch severity {
	case models.Critical:
		return 5
	case models.High:
		return 4
	case models.Medium:
		return 3
	case models.Low:
		return 2
	default:
		return 1
	}
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

