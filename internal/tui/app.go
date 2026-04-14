package tui

import (
	"fmt"
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/screens"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
	tea "github.com/charmbracelet/bubbletea"
)

type Screen int

const (
	ScreenSplash Screen = iota
	ScreenNewTarget
	ScreenPhaseMenu
	ScreenPhaseRunner
	ScreenCampaign
	ScreenDashboard
	ScreenSettings
	ScreenInstaller
	ScreenExploitWizard
	ScreenReportViewer
)

type NavigateTo struct{ Screen Screen }

type LoadTarget struct{ Target models.Target }

type AppModel struct {
	screen      Screen
	width       int
	height      int
	splash      screens.SplashModel
	newTarget   screens.TargetInputModel
	phaseMenu   screens.PhaseMenuModel
	phaseRunner screens.PhaseRunnerModel
	campaign    screens.CampaignModel
	dashboard   screens.DashboardModel
	settings    screens.SettingsModel
	installer   screens.InstallerModel
	wizard      screens.ExploitWizardModel
	report      screens.ReportViewerModel
	target      *models.Target
}

func NewAppModel() AppModel {
	return AppModel{
		screen:      ScreenSplash,
		splash:      screens.NewSplashModel(),
		newTarget:   screens.NewTargetInputModel(),
		phaseMenu:   screens.NewPhaseMenuModel("", ""),
		phaseRunner: screens.NewPhaseRunnerModel(),
		campaign:    screens.NewCampaignModel(),
		dashboard:   screens.NewDashboardModel(),
		settings:    screens.NewSettingsModel(),
		installer:   screens.NewInstallerModel(),
		wizard:      screens.NewExploitWizardModel(),
		report:      screens.NewReportViewerModel(""),
	}
}

func NewAppModelForRun(target models.Target, phases []int) AppModel {
	m := NewAppModel()
	m.target = &target
	m.phaseMenu = screens.NewPhaseMenuModel(target.Domain, target.WorkspaceDir)
	m.dashboard.SetWorkspace(target.WorkspaceDir)
	m.report.SetWorkspace(target.WorkspaceDir)
	m.wizard.SetTarget(target)
	m.phaseRunner = screens.NewPhaseRunnerModel()
	m.phaseRunner.Configure(target, phases)
	m.screen = ScreenPhaseRunner
	return m
}

func (m AppModel) Init() tea.Cmd {
	if m.screen == ScreenPhaseRunner {
		return m.phaseRunner.Init()
	}
	return m.splash.Init()
}

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.applyChildSizes()
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case NavigateTo:
		m.screen = msg.Screen
		m.applyChildSizes()
		if msg.Screen == ScreenCampaign {
			return m, m.campaign.Init()
		}
		if msg.Screen == ScreenInstaller {
			return m, m.installer.Init()
		}
		return m, nil
	case screens.BackToSplashMsg:
		m.screen = ScreenSplash
		m.applyChildSizes()
		return m, nil
	case screens.BackToPhaseMenuMsg:
		if m.target != nil {
			m.phaseMenu = screens.NewPhaseMenuModel(m.target.Domain, m.target.WorkspaceDir)
			m.screen = ScreenPhaseMenu
			m.applyChildSizes()
			return m, m.phaseMenu.Init()
		}
		m.screen = ScreenSplash
		m.applyChildSizes()
		return m, nil
	case LoadTarget:
		target := msg.Target
		m.target = &target
		m.phaseMenu = screens.NewPhaseMenuModel(target.Domain, target.WorkspaceDir)
		m.dashboard.SetWorkspace(target.WorkspaceDir)
		m.report.SetWorkspace(target.WorkspaceDir)
		m.wizard.SetTarget(target)
		m.screen = ScreenPhaseMenu
		m.applyChildSizes()
		return m, m.phaseMenu.Init()
	case screens.TargetReadyMsg:
		target := msg.Target
		m.target = &target
		m.phaseMenu = screens.NewPhaseMenuModel(target.Domain, target.WorkspaceDir)
		m.dashboard.SetWorkspace(target.WorkspaceDir)
		m.report.SetWorkspace(target.WorkspaceDir)
		m.wizard.SetTarget(target)
		m.screen = ScreenPhaseMenu
		m.applyChildSizes()
		return m, m.phaseMenu.Init()
	case screens.RunSelectedPhasesMsg:
		target := models.Target{}
		if m.target != nil {
			target = *m.target
		}
		m.phaseRunner = screens.NewPhaseRunnerModel()
		m.phaseRunner.Configure(target, msg.Phases)
		m.screen = ScreenPhaseRunner
		m.applyChildSizes()
		return m, m.phaseRunner.Init()
	case screens.RunAllPhasesMsg:
		target := models.Target{}
		if m.target != nil {
			target = *m.target
		}
		m.phaseRunner = screens.NewPhaseRunnerModel()
		m.phaseRunner.Configure(target, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
		m.screen = ScreenPhaseRunner
		m.applyChildSizes()
		return m, m.phaseRunner.Init()
	case screens.NavigateDashboardMsg:
		if m.target != nil {
			m.dashboard.SetWorkspace(m.target.WorkspaceDir)
		}
		m.screen = ScreenDashboard
		m.applyChildSizes()
		return m, m.dashboard.ReloadCmd()
	case screens.PhaseRunCompletedMsg:
		if strings.TrimSpace(msg.Target.WorkspaceDir) != "" {
			m.report.SetWorkspace(msg.Target.WorkspaceDir)
			m.wizard.SetTarget(msg.Target)
		}
		if containsPhase(msg.Phases, 9) {
			m.screen = ScreenReportViewer
			m.applyChildSizes()
			return m, m.report.ReloadCmd()
		}
		if containsPhase(msg.Phases, 5) {
			m.screen = ScreenExploitWizard
			m.applyChildSizes()
			return m, m.wizard.ReloadCmd()
		}
		m.screen = ScreenPhaseMenu
		m.applyChildSizes()
		return m, m.phaseMenu.Init()
	case screens.SplashNavigateMsg:
		switch msg.Action {
		case screens.ActionNewTarget:
			m.screen = ScreenNewTarget
			m.applyChildSizes()
		case screens.ActionCampaign:
			m.screen = ScreenCampaign
			m.applyChildSizes()
			return m, m.campaign.Init()
		case screens.ActionInstaller:
			m.screen = ScreenInstaller
			m.applyChildSizes()
			return m, m.installer.Init()
		case screens.ActionSettings, screens.ActionVault:
			m.screen = ScreenSettings
			m.applyChildSizes()
		case screens.ActionDashboard:
			if m.target != nil {
				m.dashboard.SetWorkspace(m.target.WorkspaceDir)
			}
			m.screen = ScreenDashboard
			m.applyChildSizes()
		default:
			m.screen = ScreenSplash
			m.applyChildSizes()
		}
		return m, nil
	}

	switch m.screen {
	case ScreenSplash:
		updated, cmd := m.splash.Update(msg)
		m.splash = updated.(screens.SplashModel)
		return m, cmd
	case ScreenNewTarget:
		updated, cmd := m.newTarget.Update(msg)
		m.newTarget = updated.(screens.TargetInputModel)
		return m, cmd
	case ScreenPhaseMenu:
		updated, cmd := m.phaseMenu.Update(msg)
		m.phaseMenu = updated.(screens.PhaseMenuModel)
		return m, cmd
	case ScreenPhaseRunner:
		updated, cmd := m.phaseRunner.Update(msg)
		m.phaseRunner = updated.(screens.PhaseRunnerModel)
		return m, cmd
	case ScreenCampaign:
		updated, cmd := m.campaign.Update(msg)
		m.campaign = updated.(screens.CampaignModel)
		return m, cmd
	case ScreenDashboard:
		updated, cmd := m.dashboard.Update(msg)
		m.dashboard = updated.(screens.DashboardModel)
		return m, cmd
	case ScreenSettings:
		updated, cmd := m.settings.Update(msg)
		m.settings = updated.(screens.SettingsModel)
		return m, cmd
	case ScreenInstaller:
		updated, cmd := m.installer.Update(msg)
		m.installer = updated.(screens.InstallerModel)
		return m, cmd
	case ScreenExploitWizard:
		updated, cmd := m.wizard.Update(msg)
		m.wizard = updated.(screens.ExploitWizardModel)
		return m, cmd
	case ScreenReportViewer:
		updated, cmd := m.report.Update(msg)
		m.report = updated.(screens.ReportViewerModel)
		return m, cmd
	default:
		return m, nil
	}
}

func (m AppModel) View() string {
	body := ""
	switch m.screen {
	case ScreenSplash:
		body = m.splash.View()
	case ScreenNewTarget:
		body = m.newTarget.View()
	case ScreenPhaseMenu:
		body = m.phaseMenu.View()
	case ScreenPhaseRunner:
		body = m.phaseRunner.View()
	case ScreenCampaign:
		body = m.campaign.View()
	case ScreenDashboard:
		body = m.dashboard.View()
	case ScreenSettings:
		body = m.settings.View()
	case ScreenInstaller:
		body = m.installer.View()
	case ScreenExploitWizard:
		body = m.wizard.View()
	case ScreenReportViewer:
		body = m.report.View()
	default:
		body = "Loading..."
	}

	if m.width > 0 && m.height > 0 {
		header := theme.BoldText.Render("N0RMXL Automation Framework TUI")
		footer := theme.MutedText.Render(fmt.Sprintf("Screen: %s", screenName(m.screen)))
		frameWidth := m.width - 2
		if frameWidth < 1 {
			frameWidth = 1
		}
		return theme.AppFrame.Width(frameWidth).Render(header + "\n" + body + "\n" + footer)
	}
	return body
}

func (m AppModel) childAreaSize() (int, int) {
	width := m.width - 6
	height := m.height - 6
	if width < 24 {
		width = 24
	}
	if height < 8 {
		height = 8
	}
	return width, height
}

func (m *AppModel) applyChildSizes() {
	childWidth, childHeight := m.childAreaSize()
	m.splash.SetSize(childWidth, childHeight)
	m.newTarget.SetSize(childWidth, childHeight)
	m.phaseMenu.SetSize(childWidth, childHeight)
	m.phaseRunner.SetSize(childWidth, childHeight)
	m.campaign.SetSize(childWidth, childHeight)
	m.dashboard.SetSize(childWidth, childHeight)
	m.settings.SetSize(childWidth, childHeight)
	m.installer.SetSize(childWidth, childHeight)
	m.wizard.SetSize(childWidth, childHeight)
	m.report.SetSize(childWidth, childHeight)
}

func screenName(screen Screen) string {
	switch screen {
	case ScreenSplash:
		return "Splash"
	case ScreenNewTarget:
		return "NewTarget"
	case ScreenPhaseMenu:
		return "PhaseMenu"
	case ScreenPhaseRunner:
		return "PhaseRunner"
	case ScreenCampaign:
		return "Campaign"
	case ScreenDashboard:
		return "Dashboard"
	case ScreenSettings:
		return "Settings"
	case ScreenInstaller:
		return "Installer"
	case ScreenExploitWizard:
		return "ExploitWizard"
	case ScreenReportViewer:
		return "ReportViewer"
	default:
		return "Unknown"
	}
}

func containsPhase(phases []int, target int) bool {
	for _, phase := range phases {
		if phase == target {
			return true
		}
	}
	return false
}
