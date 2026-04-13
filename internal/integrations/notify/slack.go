package notify

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/models"
)

type SlackNotifier struct {
	webhookURL string
	client     *http.Client
}

func NewSlackNotifier(webhookURL string) *SlackNotifier {
	return &SlackNotifier{
		webhookURL: strings.TrimSpace(webhookURL),
		client:     newNotifierHTTPClient(),
	}
}

func (s *SlackNotifier) SendText(title string, body string) error {
	if s == nil || strings.TrimSpace(s.webhookURL) == "" {
		return fmt.Errorf("slack notifier is not configured")
	}
	text := strings.TrimSpace(strings.Join([]string{strings.TrimSpace(title), strings.TrimSpace(body)}, "\n"))
	if text == "" {
		text = "n0rmxl notification"
	}
	return s.post(map[string]any{"text": text})
}

func (s *SlackNotifier) SendFinding(f models.Finding) error {
	if s == nil || strings.TrimSpace(s.webhookURL) == "" {
		return fmt.Errorf("slack notifier is not configured")
	}
	header := fmt.Sprintf("%s [%s] %s", slackEmoji(f.Severity), strings.ToUpper(string(f.Severity)), safe(f.Title, safe(f.VulnClass, "Finding")))
	curl := safe(f.ToCurlCommand(), "n/a")
	if len(curl) > 1200 {
		curl = curl[:1200] + "..."
	}
	payload := map[string]any{
		"text": header,
		"blocks": []map[string]any{
			{
				"type": "section",
				"text": map[string]any{
					"type": "mrkdwn",
					"text": "*" + header + "*",
				},
			},
			{
				"type": "section",
				"fields": []map[string]any{
					{"type": "mrkdwn", "text": "*Target*\n" + safe(f.Host, safe(f.Target, "n/a"))},
					{"type": "mrkdwn", "text": "*Parameter*\n" + safe(f.Parameter, "n/a")},
					{"type": "mrkdwn", "text": "*Tool*\n" + safe(f.Tool, "manual")},
					{"type": "mrkdwn", "text": fmt.Sprintf("*CVSS*\n%.1f", f.CVSS)},
				},
			},
			{
				"type": "section",
				"text": map[string]any{
					"type": "mrkdwn",
					"text": "```" + curl + "```",
				},
			},
			{
				"type": "context",
				"elements": []map[string]any{
					{"type": "mrkdwn", "text": "n0rmxl | " + time.Now().UTC().Format(time.RFC3339)},
				},
			},
		},
	}
	return s.post(payload)
}

func (s *SlackNotifier) post(payload any) error {
	if s == nil || strings.TrimSpace(s.webhookURL) == "" {
		return fmt.Errorf("slack notifier is not configured")
	}
	return postJSONWithRetry(s.client, s.webhookURL, payload)
}

func slackEmoji(sev models.Severity) string {
	switch sev {
	case models.Critical:
		return "🔴"
	case models.High:
		return "🟠"
	case models.Medium:
		return "🟡"
	case models.Low:
		return "🔵"
	default:
		return "⚪"
	}
}
