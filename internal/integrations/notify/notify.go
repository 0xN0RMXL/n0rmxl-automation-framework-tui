package notify

import (
	"fmt"
	"strings"
	"sync"

	"github.com/n0rmxl/n0rmxl/internal/config"
	"github.com/n0rmxl/n0rmxl/internal/models"
)

type Notifier struct {
	cfg    *config.NotifyConfig
	vault  *config.Vault
	minSev models.Severity
}

func NewNotifier(cfg *config.NotifyConfig, vault *config.Vault) *Notifier {
	copyCfg := config.NotifyConfig{}
	if cfg != nil {
		copyCfg = *cfg
	}
	if copyCfg.MinSeverity == "" {
		copyCfg.MinSeverity = "high"
	}
	if vault != nil && !vault.IsLocked() {
		if value, ok := vault.Get("telegram_bot_token"); ok && strings.TrimSpace(value) != "" {
			copyCfg.Telegram.BotToken = strings.TrimSpace(value)
		}
		if value, ok := vault.Get("telegram_chat_id"); ok && strings.TrimSpace(value) != "" {
			copyCfg.Telegram.ChatID = strings.TrimSpace(value)
		}
		if value, ok := vault.Get("slack_webhook"); ok && strings.TrimSpace(value) != "" {
			copyCfg.Slack.WebhookURL = strings.TrimSpace(value)
		}
		if value, ok := vault.Get("discord_webhook"); ok && strings.TrimSpace(value) != "" {
			copyCfg.Discord.WebhookURL = strings.TrimSpace(value)
		}
	}
	return &Notifier{
		cfg:    &copyCfg,
		vault:  vault,
		minSev: parseSeverity(copyCfg.MinSeverity),
	}
}

func (n *Notifier) Send(f models.Finding) error {
	if n == nil || n.cfg == nil {
		return nil
	}
	if !severityAtLeast(f.Severity, n.minSev) {
		return nil
	}
	tasks := make([]func() error, 0, 3)
	if n.cfg.Telegram.Enabled {
		tg := NewTelegramNotifier(n.cfg.Telegram.BotToken, n.cfg.Telegram.ChatID)
		tasks = append(tasks, func() error { return tg.SendFinding(f) })
	}
	if n.cfg.Slack.Enabled {
		s := NewSlackNotifier(n.cfg.Slack.WebhookURL)
		tasks = append(tasks, func() error { return s.SendFinding(f) })
	}
	if n.cfg.Discord.Enabled {
		d := NewDiscordNotifier(n.cfg.Discord.WebhookURL)
		tasks = append(tasks, func() error { return d.SendFinding(f) })
	}
	return runInParallel(tasks)
}

func (n *Notifier) SendText(title string, body string) error {
	if n == nil || n.cfg == nil {
		return nil
	}
	title = strings.TrimSpace(title)
	body = strings.TrimSpace(body)
	if title == "" && body == "" {
		return nil
	}
	message := strings.TrimSpace(strings.Join([]string{title, body}, "\n"))
	tasks := make([]func() error, 0, 3)
	if n.cfg.Telegram.Enabled {
		tg := NewTelegramNotifier(n.cfg.Telegram.BotToken, n.cfg.Telegram.ChatID)
		tasks = append(tasks, func() error { return tg.Send(message) })
	}
	if n.cfg.Slack.Enabled {
		s := NewSlackNotifier(n.cfg.Slack.WebhookURL)
		tasks = append(tasks, func() error { return s.SendText(title, body) })
	}
	if n.cfg.Discord.Enabled {
		d := NewDiscordNotifier(n.cfg.Discord.WebhookURL)
		tasks = append(tasks, func() error { return d.SendText(title, body) })
	}
	return runInParallel(tasks)
}

func runInParallel(tasks []func() error) error {
	if len(tasks) == 0 {
		return nil
	}
	errCh := make(chan error, len(tasks))
	var wg sync.WaitGroup
	for _, task := range tasks {
		task := task
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := task(); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func formatFindingMessage(f models.Finding) string {
	return fmt.Sprintf(
		"[%s] %s\nTarget: %s\nURL: %s\nParam: %s\nTool: %s\nCVSS: %.1f\n\nPayload: %s",
		strings.ToUpper(string(f.Severity)),
		safe(f.Title, safe(f.VulnClass, "Finding")),
		safe(f.Host, safe(f.Target, "unknown")),
		safe(f.URL, "n/a"),
		safe(f.Parameter, "n/a"),
		safe(f.Tool, "manual"),
		f.CVSS,
		safe(f.Payload, "n/a"),
	)
}

func parseSeverity(raw string) models.Severity {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "critical":
		return models.Critical
	case "high":
		return models.High
	case "medium":
		return models.Medium
	case "low":
		return models.Low
	default:
		return models.Info
	}
}

func severityAtLeast(current models.Severity, minimum models.Severity) bool {
	return severityRank(current) >= severityRank(minimum)
}

func severityRank(sev models.Severity) int {
	switch sev {
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

func safe(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}
