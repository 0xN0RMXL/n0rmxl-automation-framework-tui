package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

type Finding struct {
	ID          string
	Phase       int
	VulnClass   string
	Target      string
	Host        string
	URL         string
	Method      string
	Parameter   string
	Payload     string
	Severity    Severity
	CVSS        float64
	Title       string
	Description string
	Evidence    string
	CurlCmd     string
	Screenshot  string
	Tool        string
	Timestamp   time.Time
	Tags        []string
	Remediation string
	Confirmed   bool
	Duplicate   bool
	ChainedWith []string
}

func (f Finding) SeverityColor() lipgloss.Color {
	switch f.Severity {
	case Critical:
		return lipgloss.Color("#FF0000")
	case High:
		return lipgloss.Color("#F85149")
	case Medium:
		return lipgloss.Color("#D29922")
	case Low:
		return lipgloss.Color("#58A6FF")
	default:
		return lipgloss.Color("#8B949E")
	}
}

func (f Finding) CVSSBadge() string {
	if f.CVSS <= 0 {
		return "[CVSS: N/A]"
	}
	return fmt.Sprintf("[CVSS: %.1f]", f.CVSS)
}

func (f Finding) ToMarkdown() string {
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now().UTC()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "### %s\n\n", safeText(f.Title, "Untitled Finding"))
	fmt.Fprintf(&b, "- Severity: **%s** %s\n", strings.ToUpper(string(f.Severity)), f.CVSSBadge())
	fmt.Fprintf(&b, "- Phase: %d\n", f.Phase)
	fmt.Fprintf(&b, "- Class: %s\n", safeText(f.VulnClass, "unknown"))
	fmt.Fprintf(&b, "- Host: %s\n", safeText(f.Host, "n/a"))
	fmt.Fprintf(&b, "- URL: %s\n", safeText(f.URL, "n/a"))
	fmt.Fprintf(&b, "- Tool: %s\n", safeText(f.Tool, "manual"))
	fmt.Fprintf(&b, "- Time: %s\n\n", f.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(&b, "**Description**\n\n%s\n\n", safeText(f.Description, "No description provided."))
	fmt.Fprintf(&b, "**Evidence**\n\n```\n%s\n```\n\n", safeText(f.Evidence, "No evidence captured."))
	fmt.Fprintf(&b, "**Reproduction Command**\n\n```bash\n%s\n```\n\n", f.ToCurlCommand())
	if f.Remediation != "" {
		fmt.Fprintf(&b, "**Remediation**\n\n%s\n\n", f.Remediation)
	}
	return b.String()
}

func (f Finding) ToCurlCommand() string {
	if strings.TrimSpace(f.CurlCmd) != "" {
		return f.CurlCmd
	}
	method := strings.ToUpper(strings.TrimSpace(f.Method))
	if method == "" {
		method = "GET"
	}
	url := strings.TrimSpace(f.URL)
	if url == "" {
		url = "http://example.com"
	}
	if strings.TrimSpace(f.Payload) == "" {
		return fmt.Sprintf("curl -i -X %s '%s'", method, shellEscape(url))
	}
	if method == "GET" {
		return fmt.Sprintf("curl -i -X GET '%s' --get --data '%s'", shellEscape(url), shellEscape(f.Payload))
	}
	return fmt.Sprintf("curl -i -X %s '%s' --data '%s'", method, shellEscape(url), shellEscape(f.Payload))
}

func safeText(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func shellEscape(value string) string {
	return strings.ReplaceAll(value, "'", "'\"'\"'")
}
