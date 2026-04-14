package screens

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/components"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

type RunSelectedPhasesMsg struct {
	Phases []int
}

type RunAllPhasesMsg struct{}

type NavigateDashboardMsg struct{}

type phaseStatusMsg struct {
	statuses map[int]models.PhaseStatus
}

type findingsCountMsg struct {
	critical int
	high     int
	medium   int
	low      int
}

type phaseDef struct {
	number int
	name   string
}

type PhaseMenuModel struct {
	width        int
	height       int
	target       string
	workspaceDir string
	index        int
	selected     map[int]bool
	statuses     map[int]models.PhaseStatus
	findings     findingsCountMsg
	spin         spinner.Model
	phases       []phaseDef
}

func NewPhaseMenuModel(target string, workspaceDir string) PhaseMenuModel {
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = theme.BoldText.Foreground(theme.Warning)
	return PhaseMenuModel{
		target:       target,
		workspaceDir: workspaceDir,
		selected:     make(map[int]bool),
		statuses:     make(map[int]models.PhaseStatus),
		spin:         s,
		phases: []phaseDef{
			{0, "Scope & Environment Setup"},
			{1, "Passive Recon & OSINT"},
			{2, "Active Enumeration & Asset Discovery"},
			{3, "Fingerprinting, Tech Stack & Service Analysis"},
			{4, "Deep URL, API & Parameter Discovery"},
			{5, "Automated Vulnerability Scanning"},
			{6, "Manual Exploitation Wizard"},
			{7, "Post-Exploitation & Impact Demonstration"},
			{8, "Cloud, Mobile & Thick Client Testing"},
			{9, "Report Writing & Bounty Collection"},
		},
	}
}

func (m PhaseMenuModel) Init() tea.Cmd {
	return tea.Batch(
		m.spin.Tick,
		loadPhaseStatusCmd(m.workspaceDir),
		loadFindingsCountCmd(m.workspaceDir),
	)
}

func (m PhaseMenuModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case phaseStatusMsg:
		m.statuses = msg.statuses
		return m, nil
	case findingsCountMsg:
		m.findings = msg
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "Q", "esc":
			return m, func() tea.Msg { return BackToSplashMsg{} }
		case "up", "k":
			if m.index > 0 {
				m.index--
			}
			return m, nil
		case "down", "j":
			if m.index < len(m.phases)-1 {
				m.index++
			}
			return m, nil
		case " ":
			phaseNum := m.phases[m.index].number
			m.selected[phaseNum] = !m.selected[phaseNum]
			return m, nil
		case "enter":
			selected := selectedPhases(m.selected)
			if len(selected) == 0 {
				selected = []int{m.phases[m.index].number}
			}
			return m, func() tea.Msg {
				return RunSelectedPhasesMsg{Phases: selected}
			}
		case "R", "r":
			for _, phase := range m.phases {
				m.selected[phase.number] = true
			}
			return m, func() tea.Msg { return RunAllPhasesMsg{} }
		case "s":
			phaseNum := m.phases[m.index].number
			m.statuses[phaseNum] = models.PhaseSkipped
			return m, nil
		case "d":
			return m, func() tea.Msg { return NavigateDashboardMsg{} }
		}
	}

	var cmd tea.Cmd
	m.spin, cmd = m.spin.Update(msg)
	return m, cmd
}

func (m PhaseMenuModel) View() string {
	if m.width > 0 && m.height > 0 && (m.width < minTerminalWidth || m.height < minTerminalHeight) {
		return theme.Panel.Width(screenContentWidth(m.width)).Render(responsiveSizeNotice(m.width, m.height))
	}

	header := theme.RenderTitle(fmt.Sprintf("N0RMXL | Target: %s", defaultText(m.target, "n/a")), screenContentWidth(m.width)-2)
	phaseLines := make([]string, 0, len(m.phases))
	nameWidth := clampInt(m.width-46, 18, 48)
	for i, phase := range m.phases {
		pointer := " "
		if i == m.index {
			pointer = ">"
		}
		selected := "[ ]"
		if m.selected[phase.number] {
			selected = "[x]"
		}
		status := m.statuses[phase.number]
		statusText := theme.StatusBadge(string(status))
		if status == models.PhaseRunning {
			statusText = m.spin.View() + " " + statusText
		}
		phaseName := truncateText(phase.name, nameWidth)
		line := fmt.Sprintf("%s %s P%-2d %-*s %s", pointer, selected, phase.number, nameWidth, phaseName, statusText)
		if i == m.index {
			line = theme.TableSelected.Render(line)
		} else {
			line = theme.BaseText.Render(line)
		}
		phaseLines = append(phaseLines, line)
	}

	findings := strings.Join([]string{
		fmt.Sprintf("%s %d", theme.SeverityBadge("critical"), m.findings.critical),
		fmt.Sprintf("%s %d", theme.SeverityBadge("high"), m.findings.high),
		fmt.Sprintf("%s %d", theme.SeverityBadge("medium"), m.findings.medium),
		fmt.Sprintf("%s %d", theme.SeverityBadge("low"), m.findings.low),
	}, "  ")

	help := components.RenderHelpBar(
		components.NewPhaseKeyMap().RunPhase,
		components.NewPhaseKeyMap().RunAll,
		components.NewPhaseKeyMap().Skip,
	) + "  " + theme.MutedText.Render("q/esc back")

	content := strings.Join([]string{
		header,
		theme.Divider(),
		strings.Join(phaseLines, "\n"),
		"",
		"Findings: " + findings,
		"",
		help,
	}, "\n")
	return theme.Panel.Width(screenContentWidth(m.width)).Render(content)
}

func (m *PhaseMenuModel) SetSize(width int, height int) {
	m.width = width
	m.height = height
}

func selectedPhases(selected map[int]bool) []int {
	phases := make([]int, 0, len(selected))
	for phase, ok := range selected {
		if ok {
			phases = append(phases, phase)
		}
	}
	sort.Ints(phases)
	return phases
}

func loadPhaseStatusCmd(workspaceDir string) tea.Cmd {
	return func() tea.Msg {
		statuses := make(map[int]models.PhaseStatus)
		for i := 0; i <= 9; i++ {
			statuses[i] = models.PhasePending
		}
		if strings.TrimSpace(workspaceDir) == "" {
			return phaseStatusMsg{statuses: statuses}
		}
		db, err := models.InitCheckpointDB(workspaceDir)
		if err != nil {
			return phaseStatusMsg{statuses: statuses}
		}
		defer db.Close()
		stored, err := models.GetAllPhaseStatuses(db)
		if err != nil {
			return phaseStatusMsg{statuses: statuses}
		}
		for phase, status := range stored {
			statuses[phase] = status
		}
		return phaseStatusMsg{statuses: statuses}
	}
}

func loadFindingsCountCmd(workspaceDir string) tea.Cmd {
	return func() tea.Msg {
		if strings.TrimSpace(workspaceDir) == "" {
			return findingsCountMsg{}
		}
		db, err := models.InitFindingsDB(workspaceDir)
		if err != nil {
			return findingsCountMsg{}
		}
		defer db.Close()
		findings, err := models.GetFindings(db, models.FindingFilter{})
		if err != nil {
			return findingsCountMsg{}
		}
		counts := findingsCountMsg{}
		for _, f := range findings {
			switch f.Severity {
			case models.Critical:
				counts.critical++
			case models.High:
				counts.high++
			case models.Medium:
				counts.medium++
			case models.Low:
				counts.low++
			}
		}
		return counts
	}
}

func defaultText(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func WorkspacePathFromTarget(root string, target string) string {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(target) == "" {
		return ""
	}
	return filepath.Join(root, target)
}
