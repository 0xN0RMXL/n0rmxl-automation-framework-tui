package screens

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/n0rmxl/n0rmxl/internal/models"
	"github.com/n0rmxl/n0rmxl/internal/tui/theme"
)

type TargetReadyMsg struct {
	Target models.Target
}

type wizardStep int

const (
	stepDomain wizardStep = iota + 1
	stepScope
	stepRunConfig
	stepConfirm
)

type TargetInputModel struct {
	width      int
	height     int
	step       wizardStep
	domain     textinput.Model
	platform   textinput.Model
	programURL textinput.Model
	wildcards  textinput.Model
	explicit   textinput.Model
	ipRanges   textinput.Model
	outOfScope textinput.Model
	workspace  textinput.Model
	profile    string
	useBurp    bool
	useNotify  bool
	lastError  string
}

func NewTargetInputModel() TargetInputModel {
	domain := textinput.New()
	domain.Prompt = "Domain: "
	domain.Placeholder = "example.com"
	domain.Focus()
	domain.Width = 48

	platform := textinput.New()
	platform.Prompt = "Platform: "
	platform.Placeholder = "hackerone"
	platform.SetValue("hackerone")
	platform.Width = 32

	program := textinput.New()
	program.Prompt = "Program URL: "
	program.Placeholder = "https://hackerone.com/program"
	program.Width = 56

	wild := textinput.New()
	wild.Prompt = "Wildcards (comma): "
	wild.Placeholder = "*.example.com"
	wild.Width = 56

	explicit := textinput.New()
	explicit.Prompt = "Explicit hosts (comma): "
	explicit.Placeholder = "api.example.com,app.example.com"
	explicit.Width = 56

	cidr := textinput.New()
	cidr.Prompt = "IP ranges (comma): "
	cidr.Placeholder = "10.0.0.0/8"
	cidr.Width = 56

	oos := textinput.New()
	oos.Prompt = "Out-of-scope (comma): "
	oos.Placeholder = "dev.example.com"
	oos.Width = 56

	workspace := textinput.New()
	workspace.Prompt = "Workspace root: "
	workspace.Placeholder = "~/bounty"
	workspace.SetValue("~/bounty")
	workspace.Width = 56

	return TargetInputModel{
		step:       stepDomain,
		domain:     domain,
		platform:   platform,
		programURL: program,
		wildcards:  wild,
		explicit:   explicit,
		ipRanges:   cidr,
		outOfScope: oos,
		workspace:  workspace,
		profile:    string(models.Normal),
		useBurp:    true,
		useNotify:  false,
	}
}

func (m TargetInputModel) Init() tea.Cmd {
	return nil
}

func (m TargetInputModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.setWidths(msg.Width)
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			if m.step > stepDomain {
				m.step--
				m.focusCurrentStepInput()
				return m, nil
			}
			return m, nil
		case "left":
			if m.step > stepDomain {
				m.step--
				m.focusCurrentStepInput()
			}
			return m, nil
		case "right":
			if m.step < stepConfirm {
				m.step++
				m.focusCurrentStepInput()
			}
			return m, nil
		case "enter":
			if m.step < stepConfirm {
				if err := m.validateCurrentStep(); err != nil {
					m.lastError = err.Error()
					return m, nil
				}
				m.lastError = ""
				m.step++
				m.focusCurrentStepInput()
				return m, nil
			}
			target, err := m.buildTarget()
			if err != nil {
				m.lastError = err.Error()
				return m, nil
			}
			m.lastError = ""
			return m, func() tea.Msg { return TargetReadyMsg{Target: target} }
		case "p":
			m.profile = nextProfileString(m.profile)
			return m, nil
		case "b":
			m.useBurp = !m.useBurp
			return m, nil
		case "n":
			m.useNotify = !m.useNotify
			return m, nil
		}
	}

	var cmd tea.Cmd
	switch m.step {
	case stepDomain:
		m.domain, cmd = m.domain.Update(msg)
		m.platform, _ = m.platform.Update(msg)
		m.programURL, _ = m.programURL.Update(msg)
	case stepScope:
		m.wildcards, cmd = m.wildcards.Update(msg)
		m.explicit, _ = m.explicit.Update(msg)
		m.ipRanges, _ = m.ipRanges.Update(msg)
		m.outOfScope, _ = m.outOfScope.Update(msg)
	case stepRunConfig:
		m.workspace, cmd = m.workspace.Update(msg)
	}
	return m, cmd
}

func (m TargetInputModel) View() string {
	title := fmt.Sprintf("NEW TARGET SETUP  Step %d of 4", m.step)
	body := ""
	switch m.step {
	case stepDomain:
		body = strings.Join([]string{
			m.domain.View(),
			m.platform.View(),
			m.programURL.View(),
			"[Enter] Next  [Q] Cancel",
		}, "\n")
	case stepScope:
		body = strings.Join([]string{
			m.wildcards.View(),
			m.explicit.View(),
			m.ipRanges.View(),
			m.outOfScope.View(),
			"[Enter] Next  [Left/Esc] Back",
		}, "\n")
	case stepRunConfig:
		body = strings.Join([]string{
			m.workspace.View(),
			fmt.Sprintf("Profile: %s  (press P to cycle)", strings.ToUpper(m.profile)),
			fmt.Sprintf("Burp integration: %t  (press B to toggle)", m.useBurp),
			fmt.Sprintf("Notifications: %t  (press N to toggle)", m.useNotify),
			"[Enter] Next  [Left/Esc] Back",
		}, "\n")
	case stepConfirm:
		target, _ := m.buildTarget()
		body = strings.Join([]string{
			theme.RenderKeyValue("Domain", target.Domain),
			theme.RenderKeyValue("Platform", target.Platform),
			theme.RenderKeyValue("Program URL", target.ProgramURL),
			theme.RenderKeyValue("Wildcards", strings.Join(target.Wildcards, ", ")),
			theme.RenderKeyValue("Explicit", strings.Join(target.Explicit, ", ")),
			theme.RenderKeyValue("IP Ranges", strings.Join(target.IPRanges, ", ")),
			theme.RenderKeyValue("Out-of-scope", strings.Join(target.OutOfScope, ", ")),
			theme.RenderKeyValue("Workspace", target.WorkspaceDir),
			theme.RenderKeyValue("Profile", strings.ToUpper(string(target.Profile))),
			"[Enter] Launch  [Left/Esc] Back",
		}, "\n")
	}

	if m.lastError != "" {
		body += "\n\n" + theme.MutedText.Render("Error: "+m.lastError)
	}

	return theme.Panel.Render(strings.Join([]string{
		theme.BoldText.Render(title),
		theme.Divider(),
		body,
	}, "\n"))
}

func (m *TargetInputModel) SetSize(width int, height int) {
	m.width = width
	m.height = height
	m.setWidths(width)
}

func (m *TargetInputModel) setWidths(width int) {
	if width <= 0 {
		return
	}
	w := width - 24
	if w < 24 {
		w = 24
	}
	if w > 72 {
		w = 72
	}
	m.domain.Width = w
	m.platform.Width = 24
	m.programURL.Width = w
	m.wildcards.Width = w
	m.explicit.Width = w
	m.ipRanges.Width = w
	m.outOfScope.Width = w
	m.workspace.Width = w
}

func (m *TargetInputModel) focusCurrentStepInput() {
	m.domain.Blur()
	m.platform.Blur()
	m.programURL.Blur()
	m.wildcards.Blur()
	m.explicit.Blur()
	m.ipRanges.Blur()
	m.outOfScope.Blur()
	m.workspace.Blur()

	switch m.step {
	case stepDomain:
		m.domain.Focus()
	case stepScope:
		m.wildcards.Focus()
	case stepRunConfig:
		m.workspace.Focus()
	}
}

func (m TargetInputModel) validateCurrentStep() error {
	switch m.step {
	case stepDomain:
		if strings.TrimSpace(m.domain.Value()) == "" {
			return fmt.Errorf("domain is required")
		}
	case stepRunConfig:
		if strings.TrimSpace(m.workspace.Value()) == "" {
			return fmt.Errorf("workspace root is required")
		}
	}
	return nil
}

func (m TargetInputModel) buildTarget() (models.Target, error) {
	domain := strings.TrimSpace(m.domain.Value())
	if domain == "" {
		return models.Target{}, fmt.Errorf("domain is required")
	}
	profile := models.StealthProfile(strings.ToLower(strings.TrimSpace(m.profile)))
	if profile != models.Slow && profile != models.Normal && profile != models.Aggressive {
		profile = models.Normal
	}
	return models.Target{
		Domain:       domain,
		Wildcards:    splitCSV(m.wildcards.Value()),
		Explicit:     splitCSV(m.explicit.Value()),
		IPRanges:     splitCSV(m.ipRanges.Value()),
		OutOfScope:   splitCSV(m.outOfScope.Value()),
		Platform:     strings.ToLower(strings.TrimSpace(m.platform.Value())),
		ProgramURL:   strings.TrimSpace(m.programURL.Value()),
		WorkspaceDir: strings.TrimSpace(m.workspace.Value()),
		StartedAt:    time.Now().UTC(),
		Profile:      profile,
	}, nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func nextProfileString(profile string) string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "slow":
		return "normal"
	case "normal":
		return "aggressive"
	default:
		return "slow"
	}
}
