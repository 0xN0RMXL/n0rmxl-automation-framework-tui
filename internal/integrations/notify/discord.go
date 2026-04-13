package notify

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

type DiscordNotifier struct {
	webhookURL string
	client     *http.Client
}

func NewDiscordNotifier(webhookURL string) *DiscordNotifier {
	return &DiscordNotifier{
		webhookURL: strings.TrimSpace(webhookURL),
		client:     newNotifierHTTPClient(),
	}
}

func (d *DiscordNotifier) SendText(title string, body string) error {
	if d == nil || strings.TrimSpace(d.webhookURL) == "" {
		return fmt.Errorf("discord notifier is not configured")
	}
	content := strings.TrimSpace(strings.Join([]string{strings.TrimSpace(title), strings.TrimSpace(body)}, "\n"))
	if content == "" {
		content = "n0rmxl notification"
	}
	return d.post(map[string]any{"content": content})
}

func (d *DiscordNotifier) SendFinding(f models.Finding) error {
	if d == nil || strings.TrimSpace(d.webhookURL) == "" {
		return fmt.Errorf("discord notifier is not configured")
	}
	embed := map[string]any{
		"title":       fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), safe(f.VulnClass, safe(f.Title, "Finding"))),
		"description": fmt.Sprintf("%s\n%s", safe(f.Host, safe(f.Target, "n/a")), safe(f.Description, "No description provided.")),
		"color":       discordColor(f.Severity),
		"fields": []map[string]any{
			{"name": "URL", "value": safe(f.URL, "n/a"), "inline": false},
			{"name": "Parameter", "value": safe(f.Parameter, "n/a"), "inline": true},
			{"name": "Tool", "value": safe(f.Tool, "manual"), "inline": true},
			{"name": "CVSS", "value": fmt.Sprintf("%.1f", f.CVSS), "inline": true},
			{"name": "Payload", "value": safe(f.Payload, "n/a"), "inline": false},
		},
		"footer": map[string]any{
			"text":      "n0rmxl",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	}
	return d.post(map[string]any{"embeds": []map[string]any{embed}})
}

func (d *DiscordNotifier) post(payload any) error {
	if d == nil || strings.TrimSpace(d.webhookURL) == "" {
		return fmt.Errorf("discord notifier is not configured")
	}
	return postJSONWithRetry(d.client, d.webhookURL, payload)
}

func discordColor(sev models.Severity) int {
	switch sev {
	case models.Critical:
		return 0xFF0000
	case models.High:
		return 0xFF7A00
	case models.Medium:
		return 0xF4C20D
	case models.Low:
		return 0x1D9BF0
	default:
		return 0x9AA0A6
	}
}

