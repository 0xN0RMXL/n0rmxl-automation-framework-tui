package screens

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/components"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
)

type dashboardLoadedMsg struct {
	findings []models.Finding
	err      error
}

type dashboardTickMsg time.Time

type DashboardModel struct {
	width      int
	height     int
	workspace  string
	filter     string
	findings   []models.Finding
	counts     map[models.Severity]int
	table      components.TableModel
	globalKeys components.GlobalKeyMap
	lastError  string
}

func NewDashboardModel() DashboardModel {
	tableModel := components.NewTable([]table.Column{
		{Title: "Severity", Width: 12},
		{Title: "Phase", Width: 6},
		{Title: "Class", Width: 22},
		{Title: "Title", Width: 44},
		{Title: "Host", Width: 26},
		{Title: "Tool", Width: 14},
	}, []table.Row{})
	return DashboardModel{
		filter:     "all",
		findings:   []models.Finding{},
		counts:     make(map[models.Severity]int),
		table:      tableModel,
		globalKeys: components.NewGlobalKeyMap(),
	}
}

func (m DashboardModel) Init() tea.Cmd {
	if strings.TrimSpace(m.workspace) == "" {
		return dashboardTickCmd()
	}
	return tea.Batch(m.ReloadCmd(), dashboardTickCmd())
}

func (m *DashboardModel) SetWorkspace(workspace string) {
	m.workspace = strings.TrimSpace(workspace)
}

func (m DashboardModel) ReloadCmd() tea.Cmd {
	workspace := strings.TrimSpace(m.workspace)
	return func() tea.Msg {
		if workspace == "" {
			return dashboardLoadedMsg{findings: []models.Finding{}, err: nil}
		}
		db, err := models.InitFindingsDB(workspace)
		if err != nil {
			return dashboardLoadedMsg{findings: nil, err: err}
		}
		defer db.Close()
		findings, err := models.GetFindings(db, models.FindingFilter{})
		if err != nil {
			return dashboardLoadedMsg{findings: nil, err: err}
		}
		return dashboardLoadedMsg{findings: findings, err: nil}
	}
}

func (m DashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmds := make([]tea.Cmd, 0, 2)
	var reload bool

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.SetSize(msg.Width, msg.Height)
	case dashboardLoadedMsg:
		if msg.err != nil {
			m.lastError = msg.err.Error()
		} else {
			m.lastError = ""
			m.findings = msg.findings
			m.recalculate()
			m.rebuildTable()
		}
	case dashboardTickMsg:
		cmds = append(cmds, dashboardTickCmd())
		if strings.TrimSpace(m.workspace) != "" {
			reload = true
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "r", "R":
			reload = true
		case "0":
			m.filter = "all"
			m.rebuildTable()
		case "1":
			m.filter = string(models.Critical)
			m.rebuildTable()
		case "2":
			m.filter = string(models.High)
			m.rebuildTable()
		case "3":
			m.filter = string(models.Medium)
			m.rebuildTable()
		case "4":
			m.filter = string(models.Low)
			m.rebuildTable()
		case "a", "A":
			m.filter = "all"
			m.rebuildTable()
		case "c", "C":
			m.filter = string(models.Critical)
			m.rebuildTable()
		case "h", "H":
			m.filter = string(models.High)
			m.rebuildTable()
		case "m", "M":
			m.filter = string(models.Medium)
			m.rebuildTable()
		case "l", "L":
			m.filter = string(models.Low)
			m.rebuildTable()
		}
	}

	if updated, cmd := m.table.Update(msg); cmd != nil {
		if cast, ok := updated.(components.TableModel); ok {
			m.table = cast
		}
		cmds = append(cmds, cmd)
	}
	if reload {
		cmds = append(cmds, m.ReloadCmd())
	}

	return m, tea.Batch(cmds...)
}

func (m DashboardModel) View() string {
	title := theme.RenderTitle("VULNERABILITY DASHBOARD", m.width-8)
	stats := m.renderStatsLine()
	workspace := theme.RenderKeyValue("Workspace", defaultText(m.workspace, "No target selected"))
	filter := theme.RenderKeyValue("Filter", strings.ToUpper(defaultText(m.filter, "all")))
	help := strings.Join([]string{
		components.RenderHelpBar(m.globalKeys.Filter),
		theme.MutedText.Render("0 all  1 critical  2 high  3 medium  4 low  r reload"),
	}, "  ")

	tablePanel := theme.Panel.Width(max(80, m.width-8)).Render(strings.Join([]string{
		theme.SectionHeader.Render("Findings"),
		m.table.View(),
	}, "\n"))

	body := strings.Join([]string{
		title,
		theme.Divider(),
		workspace,
		filter,
		stats,
		tablePanel,
		help,
	}, "\n")
	if overlay := renderScreenErrorOverlay(m.lastError); overlay != "" {
		body += "\n\n" + overlay
	}

	return theme.AppFrame.Render(body)
}

func (m *DashboardModel) SetSize(width int, height int) {
	m.width = width
	m.height = height
	m.table.SetWidth(max(74, width-16))
	m.table.SetHeight(max(8, height-16))
}

func (m *DashboardModel) recalculate() {
	m.counts = map[models.Severity]int{
		models.Critical: 0,
		models.High:     0,
		models.Medium:   0,
		models.Low:      0,
		models.Info:     0,
	}
	for _, finding := range m.findings {
		m.counts[finding.Severity]++
	}
}

func (m *DashboardModel) rebuildTable() {
	filtered := make([]models.Finding, 0, len(m.findings))
	for _, finding := range m.findings {
		if m.filter != "all" && string(finding.Severity) != m.filter {
			continue
		}
		filtered = append(filtered, finding)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		a := severityRank(filtered[i].Severity)
		b := severityRank(filtered[j].Severity)
		if a != b {
			return a < b
		}
		if filtered[i].Phase != filtered[j].Phase {
			return filtered[i].Phase < filtered[j].Phase
		}
		return filtered[i].Title < filtered[j].Title
	})

	rows := make([]table.Row, 0, len(filtered))
	for _, finding := range filtered {
		rows = append(rows, table.Row{
			components.SeverityBadge(finding.Severity),
			fmt.Sprintf("%d", finding.Phase),
			defaultText(finding.VulnClass, "unknown"),
			defaultText(finding.Title, "untitled finding"),
			defaultText(finding.Host, "n/a"),
			defaultText(finding.Tool, "manual"),
		})
	}
	m.table.SetRows(rows)
}

func (m DashboardModel) renderStatsLine() string {
	parts := []string{
		theme.SeverityBadge(string(models.Critical)) + " " + fmt.Sprintf("%d", m.counts[models.Critical]),
		theme.SeverityBadge(string(models.High)) + " " + fmt.Sprintf("%d", m.counts[models.High]),
		theme.SeverityBadge(string(models.Medium)) + " " + fmt.Sprintf("%d", m.counts[models.Medium]),
		theme.SeverityBadge(string(models.Low)) + " " + fmt.Sprintf("%d", m.counts[models.Low]),
		theme.SeverityBadge(string(models.Info)) + " " + fmt.Sprintf("%d", m.counts[models.Info]),
	}
	return lipgloss.NewStyle().Padding(0, 1).Render(strings.Join(parts, "  "))
}

func severityRank(severity models.Severity) int {
	switch severity {
	case models.Critical:
		return 0
	case models.High:
		return 1
	case models.Medium:
		return 2
	case models.Low:
		return 3
	default:
		return 4
	}
}

func dashboardTickCmd() tea.Cmd {
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
		return dashboardTickMsg(t)
	})
}

