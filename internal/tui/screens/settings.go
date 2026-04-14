package screens

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type settingsTab int

const (
	tabAPIKeys settingsTab = iota
	tabBurp
	tabNotifications
	tabProfiles
	tabTools
)

type burpTestResultMsg struct {
	online  bool
	message string
}

type SettingsModel struct {
	width               int
	height              int
	tab                 settingsTab
	cfg                 *config.Config
	vault               *config.Vault
	keys                []string
	burpURLInput        textinput.Model
	burpHostInput       textinput.Model
	burpPortInput       textinput.Model
	passwordInput       textinput.Model
	keyNameInput        textinput.Model
	keyValueInput       textinput.Model
	showUnlockModal     bool
	showAddKeyModal     bool
	burpTesting         bool
	burpStatus          string
	lastError           string
	selectedProfile     string
	toolStatusLines     []string
	notificationMinimum string
}

func NewSettingsModel() SettingsModel {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	burpURL := textinput.New()
	burpURL.Placeholder = "http://127.0.0.1:1337"
	burpURL.SetValue(cfg.Burp.APIURL)
	burpURL.Prompt = "API URL: "
	burpURL.Width = 48

	burpHost := textinput.New()
	burpHost.Placeholder = "127.0.0.1"
	burpHost.SetValue(cfg.Burp.ProxyHost)
	burpHost.Prompt = "Proxy Host: "
	burpHost.Width = 32

	burpPort := textinput.New()
	burpPort.Placeholder = "8080"
	burpPort.SetValue(fmt.Sprintf("%d", cfg.Burp.ProxyPort))
	burpPort.Prompt = "Proxy Port: "
	burpPort.Width = 12

	password := textinput.New()
	password.Prompt = "Vault Password: "
	password.Width = 36
	password.EchoMode = textinput.EchoPassword
	password.EchoCharacter = '*'

	keyName := textinput.New()
	keyName.Prompt = "Key: "
	keyName.Width = 20
	keyName.Placeholder = "github_token"

	keyValue := textinput.New()
	keyValue.Prompt = "Value: "
	keyValue.Width = 36
	keyValue.EchoMode = textinput.EchoPassword
	keyValue.EchoCharacter = '*'

	vault := config.NewVault(cfg.VaultPath)
	keys := []string{
		"virustotal", "shodan", "censys_id", "censys_secret", "chaos", "github_token", "gitlab_token",
		"securitytrails", "binaryedge", "hunter", "burp_api_key", "telegram_bot_token", "telegram_chat_id",
		"slack_webhook", "discord_webhook",
	}

	return SettingsModel{
		tab:                 tabAPIKeys,
		cfg:                 cfg,
		vault:               vault,
		keys:                keys,
		burpURLInput:        burpURL,
		burpHostInput:       burpHost,
		burpPortInput:       burpPort,
		passwordInput:       password,
		keyNameInput:        keyName,
		keyValueInput:       keyValue,
		selectedProfile:     cfg.StealthProfile,
		notificationMinimum: cfg.Notify.MinSeverity,
		toolStatusLines: []string{
			"subfinder: unknown",
			"httpx: unknown",
			"nuclei: unknown",
			"katana: unknown",
			"gowitness: unknown",
		},
	}
}

func (m SettingsModel) Init() tea.Cmd {
	return nil
}

func (m SettingsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.setInputWidths(msg.Width)
		return m, nil
	case burpTestResultMsg:
		m.burpTesting = false
		if msg.online {
			m.burpStatus = "Connected"
			m.lastError = ""
		} else {
			m.burpStatus = "Offline"
			m.lastError = msg.message
		}
		return m, nil
	case tea.KeyMsg:
		if m.showUnlockModal {
			return m.handleUnlockModal(msg)
		}
		if m.showAddKeyModal {
			return m.handleAddKeyModal(msg)
		}
		switch msg.String() {
		case "left":
			if m.tab > tabAPIKeys {
				m.tab--
			}
			return m, nil
		case "right":
			if m.tab < tabTools {
				m.tab++
			}
			return m, nil
		case "1":
			m.tab = tabAPIKeys
			return m, nil
		case "2":
			m.tab = tabBurp
			return m, nil
		case "3":
			m.tab = tabNotifications
			return m, nil
		case "4":
			m.tab = tabProfiles
			return m, nil
		case "5":
			m.tab = tabTools
			return m, nil
		case "u", "U":
			if m.tab == tabAPIKeys {
				m.showUnlockModal = true
				m.passwordInput.Focus()
			}
			return m, nil
		case "a", "A":
			if m.tab == tabAPIKeys && !m.vault.IsLocked() {
				m.showAddKeyModal = true
				m.keyNameInput.Focus()
			}
			return m, nil
		case "d", "D":
			if m.tab == tabAPIKeys && !m.vault.IsLocked() {
				key := strings.TrimSpace(m.keyNameInput.Value())
				if key != "" {
					if err := m.vault.Delete(key); err != nil {
						m.lastError = err.Error()
					}
				}
			}
			return m, nil
		case "t", "T":
			if m.tab == tabBurp {
				m.burpTesting = true
				m.cfg.Burp.APIURL = strings.TrimSpace(m.burpURLInput.Value())
				return m, testBurpConnectionCmd(m.cfg.Burp.APIURL)
			}
			return m, nil
		case "s", "S":
			m.applyInputValues()
			if err := m.cfg.Save(); err != nil {
				m.lastError = err.Error()
			} else {
				m.lastError = ""
			}
			return m, nil
		case "p", "P":
			if m.tab == tabProfiles {
				m.selectedProfile = nextProfileValue(m.selectedProfile)
				return m, nil
			}
		case "c", "C":
			if m.tab == tabNotifications {
				m.notificationMinimum = "critical"
				return m, nil
			}
		case "h", "H":
			if m.tab == tabNotifications {
				m.notificationMinimum = "high"
				return m, nil
			}
		case "m", "M":
			if m.tab == tabNotifications {
				m.notificationMinimum = "medium"
				return m, nil
			}
		case "l", "L":
			if m.tab == tabNotifications {
				m.notificationMinimum = "low"
				return m, nil
			}
		case "i", "I":
			if m.tab == tabNotifications {
				m.notificationMinimum = "info"
				return m, nil
			}
		}
	}

	var cmd tea.Cmd
	switch m.tab {
	case tabBurp:
		m.burpURLInput, cmd = m.burpURLInput.Update(msg)
		m.burpHostInput, _ = m.burpHostInput.Update(msg)
		m.burpPortInput, _ = m.burpPortInput.Update(msg)
	case tabAPIKeys:
		if m.showUnlockModal {
			m.passwordInput, cmd = m.passwordInput.Update(msg)
		}
	}
	return m, cmd
}

func (m SettingsModel) View() string {
	tabs := []string{"[1] API Keys", "[2] Burp", "[3] Notifications", "[4] Profiles", "[5] Tools"}
	for i := range tabs {
		if int(m.tab) == i {
			tabs[i] = theme.TableSelected.Render(tabs[i])
		} else {
			tabs[i] = theme.MutedText.Render(tabs[i])
		}
	}

	content := ""
	switch m.tab {
	case tabAPIKeys:
		content = m.viewAPIKeysTab()
	case tabBurp:
		content = m.viewBurpTab()
	case tabNotifications:
		content = m.viewNotificationsTab()
	case tabProfiles:
		content = m.viewProfilesTab()
	case tabTools:
		content = m.viewToolsTab()
	}

	if m.showUnlockModal {
		content += "\n\n" + theme.Panel.Render(strings.Join([]string{
			theme.BoldText.Render("Unlock Vault"),
			m.passwordInput.View(),
			theme.MutedText.Render("[Enter] Unlock  [Esc] Cancel"),
		}, "\n"))
	}

	if m.showAddKeyModal {
		content += "\n\n" + theme.Panel.Render(strings.Join([]string{
			theme.BoldText.Render("Add/Edit Vault Key"),
			m.keyNameInput.View(),
			m.keyValueInput.View(),
			theme.MutedText.Render("[Enter] Save  [Esc] Cancel"),
		}, "\n"))
	}

	if m.lastError != "" {
		content += "\n\n" + renderScreenErrorOverlay(m.lastError)
	}

	return theme.Panel.Width(screenContentWidth(m.width)).Render(strings.Join([]string{
		theme.BoldText.Render("SETTINGS"),
		strings.Join(tabs, "  "),
		theme.Divider(),
		content,
	}, "\n"))
}

func (m *SettingsModel) SetSize(width int, height int) {
	m.width = width
	m.height = height
	m.setInputWidths(width)
}

func (m SettingsModel) handleUnlockModal(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "esc":
		m.showUnlockModal = false
		m.passwordInput.SetValue("")
		return m, nil
	case "enter":
		password := strings.TrimSpace(m.passwordInput.Value())
		if password == "" {
			m.lastError = "vault password cannot be empty"
			return m, nil
		}
		if _, err := os.Stat(m.cfg.VaultPath); errors.Is(err, os.ErrNotExist) {
			if err := m.vault.Create(password); err != nil {
				m.lastError = err.Error()
				return m, nil
			}
		} else if err := m.vault.Unlock(password); err != nil {
			m.lastError = err.Error()
			return m, nil
		}
		m.showUnlockModal = false
		m.passwordInput.SetValue("")
		m.lastError = ""
		return m, nil
	}
	var cmd tea.Cmd
	m.passwordInput, cmd = m.passwordInput.Update(key)
	return m, cmd
}

func (m SettingsModel) handleAddKeyModal(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "esc":
		m.showAddKeyModal = false
		m.keyNameInput.SetValue("")
		m.keyValueInput.SetValue("")
		return m, nil
	case "tab":
		if m.keyNameInput.Focused() {
			m.keyNameInput.Blur()
			m.keyValueInput.Focus()
		} else {
			m.keyValueInput.Blur()
			m.keyNameInput.Focus()
		}
		return m, nil
	case "enter":
		keyName := strings.TrimSpace(m.keyNameInput.Value())
		keyValue := strings.TrimSpace(m.keyValueInput.Value())
		if keyName == "" {
			m.lastError = "key name is required"
			return m, nil
		}
		if err := m.vault.Set(keyName, keyValue); err != nil {
			m.lastError = err.Error()
			return m, nil
		}
		m.showAddKeyModal = false
		m.keyNameInput.SetValue("")
		m.keyValueInput.SetValue("")
		m.lastError = ""
		return m, nil
	}
	var cmd tea.Cmd
	if m.keyNameInput.Focused() {
		m.keyNameInput, cmd = m.keyNameInput.Update(key)
	} else {
		m.keyValueInput, cmd = m.keyValueInput.Update(key)
	}
	return m, cmd
}

func (m *SettingsModel) applyInputValues() {
	m.cfg.Burp.APIURL = strings.TrimSpace(m.burpURLInput.Value())
	m.cfg.Burp.ProxyHost = strings.TrimSpace(m.burpHostInput.Value())
	var port int
	_, _ = fmt.Sscanf(strings.TrimSpace(m.burpPortInput.Value()), "%d", &port)
	if port > 0 {
		m.cfg.Burp.ProxyPort = port
	}
	m.cfg.StealthProfile = m.selectedProfile
	m.cfg.Notify.MinSeverity = m.notificationMinimum
}

func (m *SettingsModel) setInputWidths(width int) {
	if width <= 0 {
		return
	}
	calc := width - 24
	if calc < 24 {
		calc = 24
	}
	if calc > 120 {
		calc = 120
	}
	m.burpURLInput.Width = calc
	m.burpHostInput.Width = clampInt(calc/2, 20, 48)
	m.burpPortInput.Width = 10
	m.passwordInput.Width = calc
	m.keyNameInput.Width = clampInt(calc/2, 20, 48)
	m.keyValueInput.Width = calc
}

func (m SettingsModel) viewAPIKeysTab() string {
	lines := []string{theme.BoldText.Render("API KEY VAULT")}
	vaultStatus := "LOCKED"
	if !m.vault.IsLocked() {
		vaultStatus = "UNLOCKED"
	}
	lines = append(lines, theme.RenderKeyValue("Vault Status", vaultStatus))
	lines = append(lines, theme.MutedText.Render("[U] Unlock Vault  [A] Add/Edit Key  [D] Delete Key  [S] Save Settings"))
	lines = append(lines, "")
	for _, key := range m.keys {
		state := "empty"
		masked := ""
		if !m.vault.IsLocked() {
			if value, ok := m.vault.Get(key); ok && value != "" {
				state = "set"
				masked = strings.Repeat("*", 8)
			}
		}
		lines = append(lines, fmt.Sprintf("%-18s %-6s %s", key, state, masked))
	}
	return strings.Join(lines, "\n")
}

func (m SettingsModel) viewBurpTab() string {
	status := m.burpStatus
	if status == "" {
		status = "Unknown"
	}
	if m.burpTesting {
		status = "Testing..."
	}
	lines := []string{
		theme.BoldText.Render("Burp Suite Pro Integration"),
		m.burpURLInput.View(),
		m.burpHostInput.View(),
		m.burpPortInput.View(),
		theme.RenderKeyValue("Status", status),
		theme.MutedText.Render("[T] Test Connection  [S] Save"),
	}
	return strings.Join(lines, "\n")
}

func (m SettingsModel) viewNotificationsTab() string {
	levels := []string{"critical", "high", "medium", "low", "info"}
	for i, level := range levels {
		if level == m.notificationMinimum {
			levels[i] = theme.TableSelected.Render(strings.ToUpper(level))
		} else {
			levels[i] = strings.ToUpper(level)
		}
	}
	return strings.Join([]string{
		theme.BoldText.Render("Notification Settings"),
		theme.RenderKeyValue("Min Severity", strings.ToUpper(m.notificationMinimum)),
		"Levels: " + strings.Join(levels, " | "),
		theme.MutedText.Render("[C/H/M/L/I] Set severity   [S] Save"),
	}, "\n")
}

func (m SettingsModel) viewProfilesTab() string {
	profiles := []string{"slow", "normal", "aggressive"}
	lines := []string{theme.BoldText.Render("Stealth Profiles")}
	for _, profile := range profiles {
		label := strings.ToUpper(profile)
		if profile == m.selectedProfile {
			label = theme.TableSelected.Render(label)
		}
		lines = append(lines, label)
	}
	lines = append(lines, theme.MutedText.Render("[P] Cycle profile   [S] Save"))
	return strings.Join(lines, "\n")
}

func nextProfileValue(current string) string {
	switch strings.ToLower(strings.TrimSpace(current)) {
	case "slow":
		return "normal"
	case "normal":
		return "aggressive"
	default:
		return "slow"
	}
}

func (m SettingsModel) viewToolsTab() string {
	lines := []string{theme.BoldText.Render("Tool Installation Status")}
	sorted := append([]string(nil), m.toolStatusLines...)
	sort.Strings(sorted)
	lines = append(lines, sorted...)
	return strings.Join(lines, "\n")
}

func testBurpConnectionCmd(apiURL string) tea.Cmd {
	return func() tea.Msg {
		apiURL = strings.TrimRight(strings.TrimSpace(apiURL), "/")
		if apiURL == "" {
			return burpTestResultMsg{online: false, message: "api url is empty"}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 1800*time.Millisecond)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/v0.1/", nil)
		if err != nil {
			return burpTestResultMsg{online: false, message: err.Error()}
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return burpTestResultMsg{online: false, message: err.Error()}
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return burpTestResultMsg{online: true, message: "connected"}
		}
		return burpTestResultMsg{online: false, message: fmt.Sprintf("status %d", resp.StatusCode)}
	}
}
