package phase9

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
)

func buildCoverageJobs(ctx phase9Context, markdownID string, htmlID string, pdfID string, execID string) []*engine.Job {
	specs := []struct {
		name        string
		description string
		output      string
		deps        []string
		exec        func(context.Context, *engine.Job) error
	}{
		{
			name:        "report-severity-table",
			description: "Generate severity scoring table for report appendix",
			output:      filepath.Join(ctx.ws.Reports, "severity_table.md"),
			deps:        []string{markdownID},
			exec: func(_ context.Context, j *engine.Job) error {
				content := "# Severity Table\n\n| Severity | Range |\n|---|---|\n| Critical | 9.0 - 10.0 |\n| High | 7.0 - 8.9 |\n| Medium | 4.0 - 6.9 |\n| Low | 0.1 - 3.9 |\n| Info | 0.0 |\n"
				return writeText(j.OutputFile, content)
			},
		},
		{
			name:        "report-submission-tips",
			description: "Generate platform submission tips appendix",
			output:      filepath.Join(ctx.ws.Reports, "submission_tips.md"),
			deps:        []string{markdownID},
			exec: func(_ context.Context, j *engine.Job) error {
				content := strings.Join([]string{
					"# Platform Submission Tips",
					"",
					"- HackerOne: include CWE, impact narrative, and reproducible requests.",
					"- Bugcrowd: align the finding to the VRT category and explain exploit conditions.",
					"- Intigriti: keep the title concise and impact-led.",
					"- YesWeHack: attach clear evidence and remediation notes.",
					"- Immunefi: highlight asset ownership, exploitability, and fund-impact context when relevant.",
					"",
				}, "\n")
				return writeText(j.OutputFile, content)
			},
		},
		{
			name:        "report-pre-submission-checklist",
			description: "Generate pre-submission checklist",
			output:      filepath.Join(ctx.ws.Reports, "pre_submission_checklist.md"),
			deps:        []string{markdownID},
			exec: func(_ context.Context, j *engine.Job) error {
				content := strings.Join([]string{
					"# Pre-Submission Checklist",
					"",
					"- Reproduction steps are numbered and deterministic.",
					"- PoC requests and commands are attached.",
					"- Impact statement is concrete and non-hypothetical.",
					"- Screenshots or terminal evidence are included where useful.",
					"- Remediation guidance is actionable.",
					"- Duplicates and chained findings are marked clearly.",
					"",
				}, "\n")
				return writeText(j.OutputFile, content)
			},
		},
		{
			name:        "report-appendix-a",
			description: "Generate appendix of raw tool output locations",
			output:      filepath.Join(ctx.ws.Reports, "appendix_a_raw_outputs.md"),
			deps:        []string{markdownID},
			exec: func(_ context.Context, j *engine.Job) error {
				roots := []string{ctx.ws.Recon, ctx.ws.Scans, ctx.ws.Vulns, ctx.ws.Loot}
				sort.Strings(roots)
				lines := []string{"# Appendix A - Raw Tool Outputs", ""}
				for _, root := range roots {
					lines = append(lines, "- "+root)
				}
				lines = append(lines, "")
				return writeText(j.OutputFile, strings.Join(lines, "\n"))
			},
		},
		{
			name:        "report-appendix-b",
			description: "Generate remediation checklist appendix from findings",
			output:      filepath.Join(ctx.ws.Reports, "appendix_b_remediation_checklist.md"),
			deps:        []string{markdownID},
			exec: func(_ context.Context, j *engine.Job) error {
				data, err := buildReportData(ctx.target, ctx.ws)
				if err != nil {
					return err
				}
				lines := []string{"# Appendix B - Remediation Checklist", ""}
				for _, finding := range data.Findings {
					title := safeString(finding.Title, safeString(finding.VulnClass, "finding"))
					lines = append(lines, fmt.Sprintf("- [ ] %s - %s", title, safeString(finding.Remediation, "Define remediation steps")))
				}
				lines = append(lines, "")
				return writeText(j.OutputFile, strings.Join(lines, "\n"))
			},
		},
		{
			name:        "report-title-audit",
			description: "Audit finding titles against impact-led report naming",
			output:      filepath.Join(ctx.ws.Reports, "title_audit.txt"),
			deps:        []string{markdownID},
			exec: func(_ context.Context, j *engine.Job) error {
				data, err := buildReportData(ctx.target, ctx.ws)
				if err != nil {
					return err
				}
				lines := make([]string, 0, len(data.Findings))
				for _, finding := range data.Findings {
					lines = append(lines, safeString(finding.Title, safeString(finding.VulnClass, "untitled")))
				}
				sort.Strings(lines)
				return writeText(j.OutputFile, strings.Join(lines, "\n")+"\n")
			},
		},
		{
			name:        "report-html-manifest",
			description: "Record HTML report generation details",
			output:      filepath.Join(ctx.ws.Reports, "html_report_manifest.txt"),
			deps:        []string{htmlID},
			exec: func(_ context.Context, j *engine.Job) error {
				content := fmt.Sprintf("html=%s\nexists=%t\ngenerated_at=%s\n", ctx.htmlReport, fileExists(ctx.htmlReport), time.Now().UTC().Format(time.RFC3339))
				return writeText(j.OutputFile, content)
			},
		},
		{
			name:        "report-pdf-manifest",
			description: "Record PDF renderer availability and output status",
			output:      filepath.Join(ctx.ws.Reports, "pdf_report_manifest.txt"),
			deps:        []string{pdfID},
			exec: func(_ context.Context, j *engine.Job) error {
				content := fmt.Sprintf("pdf=%s\nexists=%t\n", ctx.pdfReport, fileExists(ctx.pdfReport))
				return writeText(j.OutputFile, content)
			},
		},
		{
			name:        "report-executive-manifest",
			description: "Record executive summary artifact status",
			output:      filepath.Join(ctx.ws.Reports, "executive_summary_manifest.txt"),
			deps:        []string{execID},
			exec: func(_ context.Context, j *engine.Job) error {
				content := fmt.Sprintf("executive=%s\nexists=%t\n", ctx.executiveReport, fileExists(ctx.executiveReport))
				return writeText(j.OutputFile, content)
			},
		},
	}

	jobs := make([]*engine.Job, 0, len(specs))
	for _, spec := range specs {
		spec := spec
		job := engine.NewJob(9, spec.name, "", nil)
		job.Description = spec.description
		job.OutputFile = spec.output
		job.DependsOn = append([]string{}, spec.deps...)
		job.Timeout = 30 * time.Second
		job.Execute = spec.exec
		job.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }
		jobs = append(jobs, job)
	}
	return jobs
}
