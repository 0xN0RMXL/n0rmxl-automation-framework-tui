package notify

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/n0rmxl/n0rmxl/internal/config"
	"github.com/n0rmxl/n0rmxl/internal/models"
)

func TestNotifyMinSeverityFilter(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewNotifier(&config.NotifyConfig{
		MinSeverity: "high",
		Slack: config.SlackConfig{
			Enabled:    true,
			WebhookURL: server.URL,
		},
	}, nil)

	err := notifier.Send(models.Finding{
		Severity: models.Info,
		Title:    "Informational finding",
		Host:     "app.example.com",
		URL:      "https://app.example.com",
	})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("expected no outgoing requests for filtered severity, got %d", got)
	}
}

func TestNotifyDisabledChannel(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := NewNotifier(&config.NotifyConfig{
		MinSeverity: "low",
		Slack: config.SlackConfig{
			Enabled:    true,
			WebhookURL: server.URL,
		},
		Discord: config.DiscordConfig{
			Enabled:    false,
			WebhookURL: "http://127.0.0.1:1/disabled",
		},
	}, nil)

	err := notifier.Send(models.Finding{
		Severity:  models.High,
		Title:     "High finding",
		VulnClass: "xss",
		Host:      "app.example.com",
		URL:       "https://app.example.com",
		Tool:      "dalfox",
	})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if got := atomic.LoadInt32(&requests); got != 1 {
		t.Fatalf("expected exactly one enabled-channel request, got %d", got)
	}
}
