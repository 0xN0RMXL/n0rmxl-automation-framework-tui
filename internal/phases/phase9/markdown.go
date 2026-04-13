package phase9

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

func generateMarkdown(data ReportData, outputFile string) error {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# N0RMXL Bug Bounty Report - %s\n\n", data.Target.Domain))
	b.WriteString("## Executive Summary\n\n")
	b.WriteString(fmt.Sprintf("Assessment completed for %s with %d findings (%d confirmed).", data.Target.Domain, data.Summary.TotalFindings, data.Summary.ConfirmedFindings))
	b.WriteString(" The findings below are ordered by severity and impact to support triage and remediation.\n\n")

	b.WriteString("## Scope\n\n")
	b.WriteString("- Domain: " + data.Target.Domain + "\n")
	if len(data.Target.Wildcards) > 0 {
		b.WriteString("- Wildcards:\n")
		for _, item := range data.Target.Wildcards {
			b.WriteString("  - " + item + "\n")
		}
	}
	b.WriteString("\n## Methodology\n\n")
	b.WriteString("Automated multi-phase reconnaissance and validation were executed, followed by manual exploitation workflows for high-priority findings.\n\n")

	b.WriteString("## Findings Summary\n\n")
	b.WriteString("| Severity | Count |\n")
	b.WriteString("|---|---:|\n")
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		count := data.Summary.BySeverity[models.Severity(severityFromString(severity))]
		b.WriteString(fmt.Sprintf("| %s | %d |\n", strings.Title(severity), count))
	}
	b.WriteString("\n")
	b.WriteString("## Severity Scoring Table\n\n")
	b.WriteString("| Rating | CVSS v3.1 |\n")
	b.WriteString("|---|---|\n")
	b.WriteString("| Critical | 9.0 - 10.0 |\n")
	b.WriteString("| High | 7.0 - 8.9 |\n")
	b.WriteString("| Medium | 4.0 - 6.9 |\n")
	b.WriteString("| Low | 0.1 - 3.9 |\n")
	b.WriteString("| Info | 0.0 |\n\n")

	if len(data.Summary.Chains) > 0 {
		b.WriteString("## Chain Opportunities\n\n")
		for _, chain := range data.Summary.Chains {
			b.WriteString(fmt.Sprintf("- **%s** (%s): %s\n", chain.Name, strings.ToUpper(string(chain.Severity)), chain.Description))
		}
		b.WriteString("\n")
	}

	sorted := append([]modelsFindingAlias{}, findingsToAlias(data.Findings)...)
	sort.SliceStable(sorted, func(i int, j int) bool {
		if severityRank(sorted[i].Severity) != severityRank(sorted[j].Severity) {
			return severityRank(sorted[i].Severity) > severityRank(sorted[j].Severity)
		}
		if sorted[i].CVSS != sorted[j].CVSS {
			return sorted[i].CVSS > sorted[j].CVSS
		}
		return sorted[i].URL < sorted[j].URL
	})

	b.WriteString("## Findings\n\n")
	for idx, finding := range sorted {
		id := fmt.Sprintf("F-%03d", idx+1)
		b.WriteString(fmt.Sprintf("### [%s] %s\n\n", id, reportFindingTitle(finding)))
		b.WriteString(fmt.Sprintf("- Severity: **%s**\n", strings.ToUpper(string(finding.Severity))))
		b.WriteString(fmt.Sprintf("- CVSS: %.1f\n", finding.CVSS))
		b.WriteString(fmt.Sprintf("- CVSS Vector: `%s`\n", cvssVectorForFinding(finding)))
		b.WriteString(fmt.Sprintf("- Affected: %s\n", safeString(finding.URL, "n/a")))
		b.WriteString(fmt.Sprintf("- Tool: %s\n\n", safeString(finding.Tool, "manual")))
		b.WriteString("**Summary**\n\n")
		b.WriteString(safeString(finding.Description, "No description provided.") + "\n\n")
		b.WriteString("**Vulnerability Details**\n\n")
		b.WriteString(safeString(finding.Description, "Root cause details were not captured.") + "\n\n")
		b.WriteString("**Steps to Reproduce**\n\n")
		b.WriteString("1. Reach the affected asset or endpoint.\n")
		b.WriteString("2. Replay the proof-of-concept request or command below.\n")
		b.WriteString("3. Confirm the returned behavior matches the attached evidence.\n\n")
		b.WriteString("**Proof of Concept**\n\n")
		b.WriteString("```bash\n")
		b.WriteString(safeString(finding.CurlCmd, "curl -i \""+safeString(finding.URL, "https://example.com")+"\"") + "\n")
		b.WriteString("```\n\n")
		b.WriteString("Burp Request: attach the reproduced request from the active workflow.\n\n")
		b.WriteString("**Evidence**\n\n")
		b.WriteString("```\n")
		b.WriteString(safeString(finding.Evidence, "No evidence captured."))
		b.WriteString("\n```\n\n")
		if strings.TrimSpace(finding.Screenshot) != "" {
			b.WriteString(fmt.Sprintf("Screenshot: %s\n\n", filepath.ToSlash(finding.Screenshot)))
		}
		b.WriteString("**Impact**\n\n")
		b.WriteString(reportFindingImpact(finding) + "\n\n")
		b.WriteString("**Remediation**\n\n")
		b.WriteString(safeString(finding.Remediation, "Apply strict input validation, authorization checks, and secure defaults.") + "\n\n")
	}

	b.WriteString("## Platform Submission Tips\n\n")
	b.WriteString("- HackerOne: include CWE mapping, affected asset, and a concise impact statement.\n")
	b.WriteString("- Bugcrowd: align the issue to the correct VRT category and explain exploit preconditions.\n")
	b.WriteString("- Intigriti: use a title that states vuln type, component, and impact.\n")
	b.WriteString("- YesWeHack: keep remediation concrete and attach the cleanest request/response pair.\n")
	b.WriteString("- Immunefi: prioritize blast radius, user impact, and exploit reliability.\n\n")

	b.WriteString("## Pre-Submission Checklist\n\n")
	b.WriteString("- Reproduction steps are deterministic.\n")
	b.WriteString("- Evidence is attached and readable.\n")
	b.WriteString("- Impact is specific and not overstated.\n")
	b.WriteString("- Remediation is actionable.\n")
	b.WriteString("- Duplicate and chain relationships are identified.\n\n")

	b.WriteString("## Appendix A - Raw Tool Outputs\n\n")
	b.WriteString("- recon/\n")
	b.WriteString("- scans/\n")
	b.WriteString("- vulns/\n")
	b.WriteString("- loot/\n\n")
	b.WriteString("## Appendix B - Remediation Checklist\n\n")
	for _, finding := range sorted {
		b.WriteString(fmt.Sprintf("- [ ] %s\n", safeString(finding.Title, safeString(finding.VulnClass, "finding"))))
	}
	b.WriteString("\nGenerated at: " + data.GeneratedAt.Format("2006-01-02 15:04:05Z") + "\n")

	return writeText(outputFile, b.String())
}

type modelsFindingAlias struct {
	Severity    modelsSeverityAlias
	CVSS        float64
	Title       string
	VulnClass   string
	URL         string
	Tool        string
	Description string
	CurlCmd     string
	Evidence    string
	Screenshot  string
	Remediation string
}

type modelsSeverityAlias string

const (
	sevCritical modelsSeverityAlias = "critical"
	sevHigh     modelsSeverityAlias = "high"
	sevMedium   modelsSeverityAlias = "medium"
	sevLow      modelsSeverityAlias = "low"
	sevInfo     modelsSeverityAlias = "info"
)

func findingsToAlias(in []models.Finding) []modelsFindingAlias {
	out := make([]modelsFindingAlias, 0, len(in))
	for _, f := range in {
		out = append(out, modelsFindingAlias{
			Severity:    modelsSeverityAlias(f.Severity),
			CVSS:        f.CVSS,
			Title:       f.Title,
			VulnClass:   f.VulnClass,
			URL:         f.URL,
			Tool:        f.Tool,
			Description: f.Description,
			CurlCmd:     f.CurlCmd,
			Evidence:    f.Evidence,
			Screenshot:  f.Screenshot,
			Remediation: f.Remediation,
		})
	}
	return out
}

func severityFromString(raw string) modelsSeverityAlias {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return sevCritical
	case "high":
		return sevHigh
	case "medium":
		return sevMedium
	case "low":
		return sevLow
	default:
		return sevInfo
	}
}

func severityRank(sev modelsSeverityAlias) int {
	switch sev {
	case sevCritical:
		return 5
	case sevHigh:
		return 4
	case sevMedium:
		return 3
	case sevLow:
		return 2
	default:
		return 1
	}
}

func safeString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func reportFindingTitle(finding modelsFindingAlias) string {
	className := safeString(strings.ReplaceAll(finding.VulnClass, "-", " "), "Issue")
	component := safeString(finding.URL, "component")
	return fmt.Sprintf("[%s] in %s allows %s", strings.Title(className), component, reportFindingImpact(finding))
}

func reportFindingImpact(finding modelsFindingAlias) string {
	switch finding.Severity {
	case sevCritical:
		return "critical compromise"
	case sevHigh:
		return "high-impact unauthorized access"
	case sevMedium:
		return "meaningful security impact"
	case sevLow:
		return "low-risk information disclosure"
	default:
		return "security-relevant behavior"
	}
}

func cvssVectorForFinding(finding modelsFindingAlias) string {
	switch finding.Severity {
	case sevCritical:
		return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
	case sevHigh:
		return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"
	case sevMedium:
		return "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N"
	case sevLow:
		return "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N"
	default:
		return "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:N"
	}
}

