package screens

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	cfgpkg "github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/components"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
)

type campaignTargetSummary struct {
	Target        string
	Workspace     string
	PhaseProgress string
	Status        models.PhaseStatus
	RunStatus     string
	Critical      int
	High          int
	Medium        int
	Low           int
	TotalFindings int
	UpdatedAt     time.Time
}

type campaignLoadedMsg struct {
	summaries []campaignTargetSummary
	state     campaignStateMeta
	warning   string
	err       error
}

type campaignStateClearedMsg struct {
	path string
	err  error
}

type campaignRunCompletedMsg struct {
	resume   bool
	duration time.Duration
	output   string
	err      error
}

type campaignRunTargetState struct {
	Status    string    `json:"status"`
	UpdatedAt time.Time `json:"updated_at"`
}

type campaignRunStateSnapshot struct {
	PhaseSpec string                            `json:"phase_spec"`
	StartedAt time.Time                         `json:"started_at"`
	UpdatedAt time.Time                         `json:"updated_at"`
	Targets   map[string]campaignRunTargetState `json:"targets"`
}

type campaignStateMeta struct {
	Path      string
	Exists    bool
	PhaseSpec string
	UpdatedAt time.Time
	Pending   int
	Succeeded int
	Failed    int
	Missing   int
}

type CampaignModel struct {
	width         int
	height        int
	workspaceRoot string
	summaries     []campaignTargetSummary
	state         campaignStateMeta
	table         table.Model
	lastError     string
	notice        string
	runInProgress bool
	runStartedAt  time.Time
	globalKeys    components.GlobalKeyMap
}

func NewCampaignModel() CampaignModel {
	columns := []table.Column{
		{Title: "Target", Width: 20},
		{Title: "Phase", Width: 8},
		{Title: "Status", Width: 9},
		{Title: "Run", Width: 10},
		{Title: "Findings", Width: 9},
		{Title: "Critical", Width: 8},
		{Title: "High", Width: 6},
		{Title: "Updated", Width: 16},
	}
	t := table.New(
		table.WithColumns(columns),
		table.WithRows([]table.Row{}),
		table.WithFocused(true),
		table.WithHeight(12),
	)
	styles := table.DefaultStyles()
	styles.Header = styles.Header.Foreground(theme.Accent).Bold(true)
	styles.Selected = styles.Selected.Foreground(theme.Text).Background(theme.Accent).Bold(true)
	t.SetStyles(styles)

	return CampaignModel{
		workspaceRoot: defaultCampaignWorkspaceRoot(),
		summaries:     []campaignTargetSummary{},
		state: campaignStateMeta{
			Path: defaultCampaignStateFile(),
		},
		table:      t,
		globalKeys: components.NewGlobalKeyMap(),
	}
}

func (m CampaignModel) Init() tea.Cmd {
	return m.reloadCmd()
}

func (m CampaignModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.SetSize(msg.Width, msg.Height)
		return m, nil
	case campaignLoadedMsg:
		if msg.err != nil {
			m.lastError = msg.err.Error()
			m.summaries = []campaignTargetSummary{}
			m.state = msg.state
			m.table.SetRows([]table.Row{})
			return m, nil
		}
		m.lastError = ""
		if strings.TrimSpace(msg.warning) != "" {
			m.notice = msg.warning
		}
		m.state = msg.state
		m.summaries = msg.summaries
		m.table.SetRows(m.rowsFromSummaries(msg.summaries))
		return m, nil
	case campaignStateClearedMsg:
		if msg.err != nil {
			m.lastError = msg.err.Error()
			return m, nil
		}
		m.lastError = ""
		m.notice = fmt.Sprintf("campaign state cleared: %s", msg.path)
		return m, m.reloadCmd()
	case campaignRunCompletedMsg:
		m.runInProgress = false
		if msg.err != nil {
			m.lastError = fmt.Sprintf("campaign execution failed: %v", msg.err)
			summary := summarizeCampaignRunOutput(msg.output)
			if strings.TrimSpace(summary) != "" {
				m.notice = summary
			}
			return m, m.reloadCmd()
		}
		m.lastError = ""
		mode := "run-all"
		if msg.resume {
			mode = "resume"
		}
		summary := summarizeCampaignRunOutput(msg.output)
		if strings.TrimSpace(summary) == "" {
			m.notice = fmt.Sprintf("campaign %s completed in %s", mode, msg.duration.Truncate(time.Second))
		} else {
			m.notice = fmt.Sprintf("campaign %s completed in %s | %s", mode, msg.duration.Truncate(time.Second), summary)
		}
		return m, m.reloadCmd()
	case tea.KeyMsg:
		switch msg.String() {
		case "r", "R":
			return m, m.reloadCmd()
		case "x", "X":
			return m, m.clearStateCmd()
		case "a", "A":
			if warning := validateCampaignAction(false, m.runInProgress, len(m.summaries), m.state.Exists); warning != "" {
				m.notice = warning
				return m, nil
			}
			m.runInProgress = true
			m.runStartedAt = time.Now()
			m.notice = "starting campaign run-all from TUI"
			return m, m.runCampaignCmd(false)
		case "u", "U":
			if warning := validateCampaignAction(true, m.runInProgress, len(m.summaries), m.state.Exists); warning != "" {
				m.notice = warning
				return m, nil
			}
			m.runInProgress = true
			m.runStartedAt = time.Now()
			m.notice = "starting campaign resume from TUI"
			return m, m.runCampaignCmd(true)
		case "enter":
			selected := m.table.SelectedRow()
			if len(selected) == 0 {
				return m, nil
			}
			targetDomain := strings.TrimSpace(selected[0])
			if targetDomain == "" {
				return m, nil
			}
			workspaceDir := filepath.Join(m.workspaceRoot, targetDomain)
			target := models.Target{
				Domain:       targetDomain,
				WorkspaceDir: workspaceDir,
				Wildcards:    []string{"*." + targetDomain},
				Profile:      models.Normal,
			}
			return m, func() tea.Msg { return TargetReadyMsg{Target: target} }
		}
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m CampaignModel) View() string {
	title := theme.RenderTitle("CAMPAIGN MANAGER", screenContentWidth(m.width)-2)
	workspace := theme.RenderKeyValue("Workspace Root", defaultText(m.workspaceRoot, "n/a"))
	stats := theme.RenderKeyValue("Targets", fmt.Sprintf("%d", len(m.summaries))) + "  " +
		theme.RenderKeyValue("Total Findings", fmt.Sprintf("%d", m.totalFindings())) + "  " +
		theme.RenderKeyValue("Active", fmt.Sprintf("%d", m.activeTargets()))
	stateUpdated := "n/a"
	if !m.state.UpdatedAt.IsZero() {
		stateUpdated = m.state.UpdatedAt.Local().Format("2006-01-02 15:04")
	}
	stateSummary := theme.RenderKeyValue("State File", defaultText(m.state.Path, "n/a")) + "  " +
		theme.RenderKeyValue("Run Phase", defaultText(m.state.PhaseSpec, "n/a")) + "  " +
		theme.RenderKeyValue("Updated", stateUpdated)
	runStats := theme.RenderKeyValue("Queued", fmt.Sprintf("%d", m.state.Pending)) + "  " +
		theme.RenderKeyValue("Succeeded", fmt.Sprintf("%d", m.state.Succeeded)) + "  " +
		theme.RenderKeyValue("Failed", fmt.Sprintf("%d", m.state.Failed)) + "  " +
		theme.RenderKeyValue("Missing", fmt.Sprintf("%d", m.state.Missing))

	help := components.RenderHelpBar(
		m.globalKeys.Select,
		m.globalKeys.ScrollUp,
		m.globalKeys.ScrollDown,
	) + "  " + theme.MutedText.Render("r reload • a run-all • u resume • x clear-state")

	body := []string{
		title,
		theme.Divider(),
		workspace,
		stats,
		stateSummary,
		runStats,
		theme.Panel.Width(screenContentWidth(m.width) - 2).Render(m.table.View()),
		help,
	}
	if m.lastError != "" {
		body = append(body, renderScreenErrorOverlay(m.lastError))
	}
	if strings.TrimSpace(m.notice) != "" {
		body = append(body, theme.MutedText.Render(m.notice))
	}
	if m.runInProgress {
		elapsed := time.Since(m.runStartedAt).Truncate(time.Second)
		body = append(body, theme.MutedText.Render(fmt.Sprintf("campaign execution running (%s)", elapsed)))
	}

	return theme.Panel.Width(screenContentWidth(m.width)).Render(strings.Join(body, "\n"))
}

func (m *CampaignModel) SetSize(width int, height int) {
	m.width = width
	m.height = height
	m.table.SetWidth(clampInt(width-10, 60, 240))
	m.table.SetHeight(max(6, height-16))
}

func (m CampaignModel) reloadCmd() tea.Cmd {
	workspaceRoot := m.workspaceRoot
	statePath := m.state.Path
	if strings.TrimSpace(statePath) == "" {
		statePath = defaultCampaignStateFile()
	}
	return func() tea.Msg {
		summaries, err := scanCampaignTargets(workspaceRoot)
		if err != nil {
			return campaignLoadedMsg{summaries: []campaignTargetSummary{}, state: campaignStateMeta{Path: statePath}, err: err}
		}
		state, stateErr := loadCampaignRunStateSnapshot(statePath)
		meta := summarizeCampaignStateMeta(statePath, state)
		warning := ""
		if stateErr != nil {
			meta = campaignStateMeta{Path: statePath}
			if !errors.Is(stateErr, os.ErrNotExist) {
				warning = fmt.Sprintf("campaign state unavailable: %v", stateErr)
			}
		} else {
			summaries = applyCampaignStateToSummaries(summaries, state)
		}
		return campaignLoadedMsg{summaries: summaries, state: meta, warning: warning, err: nil}
	}
}

func (m CampaignModel) clearStateCmd() tea.Cmd {
	statePath := strings.TrimSpace(m.state.Path)
	if statePath == "" {
		statePath = defaultCampaignStateFile()
	}
	return func() tea.Msg {
		err := os.Remove(statePath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return campaignStateClearedMsg{path: statePath, err: err}
		}
		return campaignStateClearedMsg{path: statePath, err: nil}
	}
}

func (m CampaignModel) runCampaignCmd(resume bool) tea.Cmd {
	workspaceRoot := strings.TrimSpace(m.workspaceRoot)
	if workspaceRoot == "" {
		workspaceRoot = defaultCampaignWorkspaceRoot()
	}
	statePath := strings.TrimSpace(m.state.Path)
	if statePath == "" {
		statePath = defaultCampaignStateFile()
	}
	phaseSpec := strings.TrimSpace(m.state.PhaseSpec)

	return func() tea.Msg {
		started := time.Now()
		executablePath, err := os.Executable()
		if err != nil {
			return campaignRunCompletedMsg{resume: resume, duration: time.Since(started), output: "", err: err}
		}

		args := buildCampaignCommandArgs(workspaceRoot, statePath, phaseSpec, resume)

		command := exec.Command(executablePath, args...)
		output, runErr := command.CombinedOutput()
		return campaignRunCompletedMsg{
			resume:   resume,
			duration: time.Since(started),
			output:   string(output),
			err:      runErr,
		}
	}
}

func buildCampaignCommandArgs(workspaceRoot string, statePath string, phaseSpec string, resume bool) []string {
	args := []string{"--no-tui", "campaign", "--workspace-root", workspaceRoot, "--run-all", "--state-file", statePath}
	if resume {
		return append(args, "--resume")
	}
	return append(args, "--phases", defaultCampaignRunPhaseSpec(phaseSpec))
}

func defaultCampaignRunPhaseSpec(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "0,1,2,3,4,5,6,7,8,9"
	}
	return spec
}

func validateCampaignAction(resume bool, runInProgress bool, summaryCount int, stateExists bool) string {
	if runInProgress {
		return "campaign execution already in progress"
	}
	if summaryCount <= 0 {
		return "no target workspaces available for campaign execution"
	}
	if resume && !stateExists {
		return "resume requires campaign state; run with key 'a' first"
	}
	return ""
}

func summarizeCampaignRunOutput(output string) string {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return ""
	}
	lines := strings.Split(trimmed, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.Contains(line, "[n0rmxl] campaign run complete:") {
			return line
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line != "" {
			return line
		}
	}
	return ""
}

func (m CampaignModel) rowsFromSummaries(summaries []campaignTargetSummary) []table.Row {
	rows := make([]table.Row, 0, len(summaries))
	for _, summary := range summaries {
		updated := "n/a"
		if !summary.UpdatedAt.IsZero() {
			updated = summary.UpdatedAt.Local().Format("2006-01-02 15:04")
		}
		rows = append(rows, table.Row{
			summary.Target,
			summary.PhaseProgress,
			string(summary.Status),
			defaultText(summary.RunStatus, "n/a"),
			fmt.Sprintf("%d", summary.TotalFindings),
			fmt.Sprintf("%d", summary.Critical),
			fmt.Sprintf("%d", summary.High),
			updated,
		})
	}
	return rows
}

func (m CampaignModel) totalFindings() int {
	total := 0
	for _, summary := range m.summaries {
		total += summary.TotalFindings
	}
	return total
}

func (m CampaignModel) activeTargets() int {
	count := 0
	for _, summary := range m.summaries {
		if summary.Status == models.PhaseRunning {
			count++
		}
	}
	return count
}

func defaultCampaignWorkspaceRoot() string {
	cfg, err := cfgpkg.Load()
	if err == nil && strings.TrimSpace(cfg.WorkspaceRoot) != "" {
		return strings.TrimSpace(cfg.WorkspaceRoot)
	}
	home, homeErr := os.UserHomeDir()
	if homeErr != nil {
		return filepath.Join(".", "bounty")
	}
	return filepath.Join(home, "bounty")
}

func defaultCampaignStateFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".local", "share", "n0rmxl", "campaign_state.json")
	}
	return filepath.Join(home, ".local", "share", "n0rmxl", "campaign_state.json")
}

func loadCampaignRunStateSnapshot(path string) (*campaignRunStateSnapshot, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("campaign state path is empty")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	state := &campaignRunStateSnapshot{}
	if err := json.Unmarshal(content, state); err != nil {
		return nil, fmt.Errorf("invalid campaign state file %s: %w", path, err)
	}
	if state.Targets == nil {
		state.Targets = make(map[string]campaignRunTargetState)
	}
	return state, nil
}

func summarizeCampaignStateMeta(path string, state *campaignRunStateSnapshot) campaignStateMeta {
	meta := campaignStateMeta{Path: path}
	if state == nil {
		return meta
	}
	meta.Exists = true
	meta.PhaseSpec = strings.TrimSpace(state.PhaseSpec)
	meta.UpdatedAt = state.UpdatedAt
	if meta.UpdatedAt.IsZero() {
		meta.UpdatedAt = state.StartedAt
	}
	for _, targetState := range state.Targets {
		switch normalizeCampaignRunStatus(targetState.Status) {
		case "succeeded":
			meta.Succeeded++
		case "failed":
			meta.Failed++
		case "missing":
			meta.Missing++
		default:
			meta.Pending++
		}
	}
	return meta
}

func applyCampaignStateToSummaries(summaries []campaignTargetSummary, state *campaignRunStateSnapshot) []campaignTargetSummary {
	if len(summaries) == 0 || state == nil || len(state.Targets) == 0 {
		return summaries
	}
	index := make(map[string]int, len(summaries))
	for i, summary := range summaries {
		index[summary.Target] = i
	}
	for target, targetState := range state.Targets {
		i, ok := index[target]
		if !ok {
			continue
		}
		summaries[i].RunStatus = normalizeCampaignRunStatus(targetState.Status)
	}
	return summaries
}

func normalizeCampaignRunStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "succeeded":
		return "succeeded"
	case "failed":
		return "failed"
	case "missing":
		return "missing"
	case "pending", "queued", "running":
		return "pending"
	default:
		return "pending"
	}
}

func scanCampaignTargets(workspaceRoot string) ([]campaignTargetSummary, error) {
	workspaceRoot = strings.TrimSpace(workspaceRoot)
	if workspaceRoot == "" {
		return []campaignTargetSummary{}, nil
	}
	entries, err := os.ReadDir(workspaceRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return []campaignTargetSummary{}, nil
		}
		return nil, err
	}
	summaries := make([]campaignTargetSummary, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		target := strings.TrimSpace(entry.Name())
		if target == "" {
			continue
		}
		workspaceDir := filepath.Join(workspaceRoot, target)
		hiddenDir := filepath.Join(workspaceDir, ".n0rmxl")
		if info, statErr := os.Stat(hiddenDir); statErr != nil || !info.IsDir() {
			continue
		}
		summary := campaignTargetSummary{Target: target, Workspace: workspaceDir}
		if statuses, statusErr := loadCampaignPhaseStatuses(workspaceDir); statusErr == nil {
			summary.PhaseProgress, summary.Status = summarizeCampaignPhase(statuses)
		}
		if summary.PhaseProgress == "" {
			summary.PhaseProgress = "P0/10"
		}
		if summary.Status == "" {
			summary.Status = models.PhasePending
		}
		if findings, findingErr := loadCampaignFindings(workspaceDir); findingErr == nil {
			for _, finding := range findings {
				summary.TotalFindings++
				switch finding.Severity {
				case models.Critical:
					summary.Critical++
				case models.High:
					summary.High++
				case models.Medium:
					summary.Medium++
				case models.Low:
					summary.Low++
				}
			}
		}
		summary.UpdatedAt = latestWorkspaceUpdate(workspaceDir)
		summaries = append(summaries, summary)
	}
	sort.SliceStable(summaries, func(i int, j int) bool {
		if summaries[i].Status != summaries[j].Status {
			return statusRank(summaries[i].Status) < statusRank(summaries[j].Status)
		}
		return summaries[i].Target < summaries[j].Target
	})
	return summaries, nil
}

func loadCampaignPhaseStatuses(workspaceDir string) (map[int]models.PhaseStatus, error) {
	db, err := models.InitCheckpointDB(workspaceDir)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return models.GetAllPhaseStatuses(db)
}

func loadCampaignFindings(workspaceDir string) ([]models.Finding, error) {
	db, err := models.InitFindingsDB(workspaceDir)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return models.GetFindings(db, models.FindingFilter{})
}

func summarizeCampaignPhase(statuses map[int]models.PhaseStatus) (string, models.PhaseStatus) {
	if len(statuses) == 0 {
		return "P0/10", models.PhasePending
	}
	completed := 0
	maxDone := -1
	finalStatus := models.PhasePending
	for phase := 0; phase <= 9; phase++ {
		status := statuses[phase]
		switch status {
		case models.PhaseFailed:
			finalStatus = models.PhaseFailed
		case models.PhaseRunning:
			if finalStatus != models.PhaseFailed {
				finalStatus = models.PhaseRunning
			}
		case models.PhaseDone, models.PhaseSkipped:
			completed++
			maxDone = phase
			if finalStatus == models.PhasePending {
				finalStatus = models.PhaseDone
			}
		}
	}
	if completed == 10 {
		return "Done", models.PhaseDone
	}
	current := maxDone + 1
	if current < 0 {
		current = 0
	}
	if current > 9 {
		current = 9
	}
	return fmt.Sprintf("P%d/10", current), finalStatus
}

func latestWorkspaceUpdate(workspaceDir string) time.Time {
	paths := []string{
		filepath.Join(workspaceDir, ".n0rmxl", "checkpoint.db"),
		filepath.Join(workspaceDir, ".n0rmxl", "findings.db"),
		filepath.Join(workspaceDir, "reports", "report.md"),
	}
	latest := time.Time{}
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil {
			if info.ModTime().After(latest) {
				latest = info.ModTime()
			}
		}
	}
	return latest
}

func statusRank(status models.PhaseStatus) int {
	switch status {
	case models.PhaseRunning:
		return 0
	case models.PhaseFailed:
		return 1
	case models.PhasePending:
		return 2
	case models.PhaseDone:
		return 3
	case models.PhaseSkipped:
		return 4
	default:
		return 5
	}
}
