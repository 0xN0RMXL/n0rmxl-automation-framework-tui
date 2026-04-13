package burp

import (
	"testing"

	"github.com/n0rmxl/n0rmxl/internal/models"
)

func TestBurpPingOffline(t *testing.T) {
	client := NewBurpClient("http://127.0.0.1:1", "test-key")
	if _, err := client.Ping(); err == nil {
		t.Fatal("expected offline burp ping to return an error")
	}
}

func TestBurpIssuesToFindings(t *testing.T) {
	client := NewBurpClient("http://127.0.0.1:1337", "test-key")
	issues := []BurpIssue{
		{Name: "SQL injection", Severity: "critical", Confidence: "certain", URL: "https://app.example.com/a", Host: "app.example.com"},
		{Name: "Reflected XSS", Severity: "high", Confidence: "firm", URL: "https://app.example.com/b", Host: "app.example.com"},
		{Name: "CORS misconfiguration", Severity: "medium", URL: "https://app.example.com/c", Host: "app.example.com"},
		{Name: "Information disclosure", Severity: "low", URL: "https://app.example.com/d", Host: "app.example.com"},
		{Name: "Verbose response", Severity: "info", URL: "https://app.example.com/e", Host: "app.example.com"},
	}

	findings := client.IssuesToFindings(issues, "example.com")
	if len(findings) != len(issues) {
		t.Fatalf("expected %d findings, got %d", len(issues), len(findings))
	}

	want := []models.Severity{models.Critical, models.High, models.Medium, models.Low, models.Info}
	for i, finding := range findings {
		if finding.Severity != want[i] {
			t.Fatalf("finding %d expected severity %q, got %q", i, want[i], finding.Severity)
		}
		if finding.Tool != "burp-active-scan" {
			t.Fatalf("expected burp tool name, got %q", finding.Tool)
		}
	}
	if findings[0].VulnClass != "sqli" {
		t.Fatalf("expected SQL injection to map to sqli, got %q", findings[0].VulnClass)
	}
	if findings[1].VulnClass != "xss" {
		t.Fatalf("expected reflected XSS to map to xss, got %q", findings[1].VulnClass)
	}
	if findings[2].VulnClass != "cors" {
		t.Fatalf("expected CORS issue to map to cors, got %q", findings[2].VulnClass)
	}
}
