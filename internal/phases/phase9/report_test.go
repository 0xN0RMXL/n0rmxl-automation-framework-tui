package phase9

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n0rmxl/n0rmxl/internal/models"
)

func TestSummarizeFindingsAggregatesAndSorts(t *testing.T) {
	findings := []models.Finding{
		{VulnClass: "xss", Severity: models.High, CVSS: 8.1, Confirmed: true, URL: "https://a.example"},
		{VulnClass: "sqli", Severity: models.Critical, CVSS: 9.8, URL: "https://b.example"},
		{VulnClass: "idor", Severity: models.Medium, CVSS: 5.4, URL: "https://c.example"},
	}

	summary := summarizeFindings(findings, nil, nil)
	if summary.TotalFindings != 3 {
		t.Fatalf("expected total findings 3, got %d", summary.TotalFindings)
	}
	if summary.ConfirmedFindings != 1 {
		t.Fatalf("expected one confirmed finding, got %d", summary.ConfirmedFindings)
	}
	if summary.BySeverity[models.Critical] != 1 || summary.BySeverity[models.High] != 1 || summary.BySeverity[models.Medium] != 1 {
		t.Fatalf("unexpected severity counts: %#v", summary.BySeverity)
	}
	if len(summary.CriticalFindings) != 1 {
		t.Fatalf("expected one critical finding, got %d", len(summary.CriticalFindings))
	}
	if len(summary.TopFindings) == 0 || summary.TopFindings[0].VulnClass != "sqli" {
		t.Fatalf("expected highest-ranked finding to be sqli, got %+v", summary.TopFindings)
	}
}

func TestGenerateHTMLRendersMarkdownBasics(t *testing.T) {
	dir := t.TempDir()
	markdownPath := filepath.Join(dir, "report.md")
	htmlPath := filepath.Join(dir, "report.html")
	markdown := strings.Join([]string{
		"# Title",
		"",
		"## Section",
		"- item",
		"```",
		"<script>alert(1)</script>",
		"```",
	}, "\n")
	if err := os.WriteFile(markdownPath, []byte(markdown), 0o600); err != nil {
		t.Fatalf("failed to write markdown fixture: %v", err)
	}

	if err := generateHTML(markdownPath, htmlPath); err != nil {
		t.Fatalf("generateHTML failed: %v", err)
	}

	raw, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("failed to read generated HTML: %v", err)
	}
	html := string(raw)
	if !strings.Contains(html, "<h1>Title</h1>") {
		t.Fatalf("expected h1 in generated html, got %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("expected escaped code block content in generated html")
	}
}
