package screens

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type SplashAction string

const (
	ActionNewTarget SplashAction = "new_target"
	ActionCampaign  SplashAction = "campaign"
	ActionInstaller SplashAction = "installer"
	ActionSettings  SplashAction = "settings"
	ActionDashboard SplashAction = "dashboard"
	ActionVault     SplashAction = "vault"
)

type SplashNavigateMsg struct {
	Action SplashAction
}

type splashTickMsg struct{}

type pulseTickMsg struct{}

type burpStatusMsg struct {
	online bool
}

type toolsCountMsg struct {
	installed int
	total     int
}

type SplashModel struct {
	width       int
	height      int
	frame       int
	menuIndex   int
	menu        []menuEntry
	burpOnline  bool
	vaultLocked bool
	toolsCount  struct {
		installed int
		total     int
	}
	profile models.StealthProfile
	pulseOn bool
	ticker  time.Time
}

type menuEntry struct {
	label  string
	action SplashAction
}

func NewSplashModel() SplashModel {
	m := SplashModel{
		frame:       0,
		menuIndex:   0,
		burpOnline:  false,
		vaultLocked: true,
		profile:     models.Normal,
		pulseOn:     true,
		menu: []menuEntry{
			{label: "[N] New Target", action: ActionNewTarget},
			{label: "[C] Campaign Mode", action: ActionCampaign},
			{label: "[I] Install Tools", action: ActionInstaller},
			{label: "[S] Settings", action: ActionSettings},
			{label: "[D] Dashboard", action: ActionDashboard},
			{label: "[V] Vault Manager", action: ActionVault},
		},
	}
	m.toolsCount.total = 102
	return m
}

func (m SplashModel) Init() tea.Cmd {
	return tea.Batch(
		splashTickCmd(),
		pulseTickCmd(),
		checkBurpCmd(),
		countToolsCmd(),
	)
}

func (m SplashModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case splashTickMsg:
		if m.frame < 10 {
			m.frame++
		}
		m.ticker = time.Now()
		return m, splashTickCmd()
	case pulseTickMsg:
		m.pulseOn = !m.pulseOn
		return m, pulseTickCmd()
	case burpStatusMsg:
		m.burpOnline = msg.online
		return m, nil
	case toolsCountMsg:
		m.toolsCount.installed = msg.installed
		if msg.total > 0 {
			m.toolsCount.total = msg.total
		}
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.menuIndex > 0 {
				m.menuIndex--
			}
		case "down", "j":
			if m.menuIndex < len(m.menu)-1 {
				m.menuIndex++
			}
		case "enter":
			return m, func() tea.Msg {
				return SplashNavigateMsg{Action: m.menu[m.menuIndex].action}
			}
		case "n":
			return m, func() tea.Msg { return SplashNavigateMsg{Action: ActionNewTarget} }
		case "c":
			return m, func() tea.Msg { return SplashNavigateMsg{Action: ActionCampaign} }
		case "i":
			return m, func() tea.Msg { return SplashNavigateMsg{Action: ActionInstaller} }
		case "s":
			return m, func() tea.Msg { return SplashNavigateMsg{Action: ActionSettings} }
		case "d":
			return m, func() tea.Msg { return SplashNavigateMsg{Action: ActionDashboard} }
		case "v":
			return m, func() tea.Msg { return SplashNavigateMsg{Action: ActionVault} }
		case "p":
			m.profile = nextProfile(m.profile)
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m SplashModel) View() string {
	if m.width > 0 && m.height > 0 && (m.width < minTerminalWidth || m.height < minTerminalHeight) {
		return theme.Panel.Width(screenContentWidth(m.width)).Render(responsiveSizeNotice(m.width, m.height))
	}

	logo := m.renderAnimatedLogo()
	subtitleStyle := theme.MutedText
	if m.pulseOn {
		subtitleStyle = theme.BoldText.Foreground(theme.Accent2)
	}
	subtitle := subtitleStyle.Render("Elite Recon | 100+ Tools | 10 Phases")

	menuLines := make([]string, 0, len(m.menu))
	for idx, item := range m.menu {
		if idx == m.menuIndex {
			menuLines = append(menuLines, theme.TableSelected.Render("> "+item.label))
			continue
		}
		menuLines = append(menuLines, theme.BaseText.Render("  "+item.label))
	}

	burpStatus := theme.Badge("Offline", theme.Danger).Render("Offline")
	if m.burpOnline {
		burpStatus = theme.Badge("Connected", theme.Accent2).Render("Connected")
	}
	vaultStatus := theme.Badge("Locked", theme.Warning).Render("Locked")
	if !m.vaultLocked {
		vaultStatus = theme.Badge("Unlocked", theme.Accent2).Render("Unlocked")
	}
	toolStatus := theme.Badge("Tools", theme.Accent).Render(fmt.Sprintf("%d/%d installed", m.toolsCount.installed, m.toolsCount.total))

	content := strings.Join([]string{
		logo,
		"",
		subtitle,
		"",
		theme.Panel.Render(strings.Join(menuLines, "\n")),
		"",
		fmt.Sprintf("Profile: %s", strings.ToUpper(string(m.profile))),
		fmt.Sprintf("Burp: %s | Vault: %s | %s", burpStatus, vaultStatus, toolStatus),
	}, "\n")

	return theme.Panel.Width(screenContentWidth(m.width)).Render(content)
}

func (m *SplashModel) SetSize(width int, height int) {
	m.width = width
	m.height = height
}

func splashTickCmd() tea.Cmd {
	return tea.Tick(50*time.Millisecond, func(time.Time) tea.Msg {
		return splashTickMsg{}
	})
}

func pulseTickCmd() tea.Cmd {
	return tea.Tick(800*time.Millisecond, func(time.Time) tea.Msg {
		return pulseTickMsg{}
	})
}

func checkBurpCmd() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:1337/v0.1/", nil)
		if err != nil {
			return burpStatusMsg{online: false}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return burpStatusMsg{online: false}
		}
		_ = resp.Body.Close()
		return burpStatusMsg{online: resp.StatusCode >= 200 && resp.StatusCode < 400}
	}
}

func countToolsCmd() tea.Cmd {
	return func() tea.Msg {
		known := []string{"subfinder", "httpx", "nuclei", "katana", "dnsx", "naabu", "gowitness", "ffuf", "sqlmap", "nmap"}
		installed := 0
		for _, bin := range known {
			if _, err := exec.LookPath(bin); err == nil {
				installed++
			}
		}
		return toolsCountMsg{installed: installed, total: 102}
	}
}

func nextProfile(current models.StealthProfile) models.StealthProfile {
	switch current {
	case models.Slow:
		return models.Normal
	case models.Normal:
		return models.Aggressive
	default:
		return models.Slow
	}
}

func (m SplashModel) renderAnimatedLogo() string {
	lines := []string{
		" _   _  ___  ____  __  __ __  __ _      _ ",
		"| \\ | |/ _ \\|  _ \\|  \\/  |  \\/  | |    | |",
		"|  \\| | | | | |_) | |\\/| | |\\/| | |    | |",
		"| |\\  | |_| |  _ <| |  | | |  | | |___ | |",
		"|_| \\_|\\___/|_| \\_\\_|  |_|_|  |_|_____|___|",
		"      N0RMXL Automation Framework v1.0",
	}
	visible := len(lines)
	if m.frame < 10 {
		visible = (m.frame*len(lines))/10 + 1
		if visible > len(lines) {
			visible = len(lines)
		}
	}
	return lipgloss.NewStyle().Foreground(theme.Accent).Bold(true).Render(strings.Join(lines[:visible], "\n"))
}
