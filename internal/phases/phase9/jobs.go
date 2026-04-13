package phase9

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/config"
	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/models"
)

type phase9Context struct {
	target          *models.Target
	ws              models.Workspace
	runCfg          *config.RunConfig
	domain          string
	markdownReport  string
	htmlReport      string
	pdfReport       string
	executiveReport string
}

func Jobs(target *models.Target, ws models.Workspace, runCfg *config.RunConfig) []*engine.Job {
	if target == nil || strings.TrimSpace(target.Domain) == "" {
		return []*engine.Job{}
	}
	_ = os.MkdirAll(ws.Reports, 0o755)
	ctx := phase9Context{
		target:          target,
		ws:              ws,
		runCfg:          runCfg,
		domain:          strings.TrimSpace(target.Domain),
		markdownReport:  filepath.Join(ws.Reports, "report.md"),
		htmlReport:      filepath.Join(ws.Reports, "report.html"),
		pdfReport:       filepath.Join(ws.Reports, "report.pdf"),
		executiveReport: filepath.Join(ws.Reports, "executive_summary.md"),
	}

	markdown := engine.NewJob(9, "generate-markdown", "", nil)
	markdown.Description = "Generate markdown report from findings database"
	markdown.OutputFile = ctx.markdownReport
	markdown.Timeout = 2 * time.Minute
	markdown.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		data, err := buildReportData(ctx.target, ctx.ws)
		if err != nil {
			return err
		}
		if data.Summary.TotalFindings == 0 {
			markSkipped(j, "no findings available for report generation")
			return nil
		}
		return generateMarkdown(data, j.OutputFile)
	}
	markdown.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }

	html := engine.NewJob(9, "generate-html", "", nil)
	html.Description = "Generate HTML report from markdown report"
	html.OutputFile = ctx.htmlReport
	html.DependsOn = []string{markdown.ID}
	html.Timeout = 2 * time.Minute
	html.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		if !fileExists(ctx.markdownReport) {
			markSkipped(j, "markdown report missing")
			return nil
		}
		return generateHTML(ctx.markdownReport, j.OutputFile)
	}
	html.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }

	pdf := engine.NewJob(9, "generate-pdf", "", nil)
	pdf.Description = "Generate PDF report from HTML"
	pdf.OutputFile = ctx.pdfReport
	pdf.DependsOn = []string{html.ID}
	pdf.Timeout = 2 * time.Minute
	pdf.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		if !fileExists(ctx.htmlReport) {
			markSkipped(j, "HTML report missing")
			return nil
		}
		if err := generatePDF(ctx.htmlReport, j.OutputFile); err != nil {
			markSkipped(j, err.Error())
			return nil
		}
		return nil
	}
	pdf.ParseOutput = func(j *engine.Job) int {
		if fileExists(j.OutputFile) {
			return 1
		}
		return 0
	}

	execSummary := engine.NewJob(9, "generate-executive-summary", "", nil)
	execSummary.Description = "Generate a concise executive summary report"
	execSummary.OutputFile = ctx.executiveReport
	execSummary.DependsOn = []string{markdown.ID}
	execSummary.Timeout = 1 * time.Minute
	execSummary.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		data, err := buildReportData(ctx.target, ctx.ws)
		if err != nil {
			return err
		}
		if data.Summary.TotalFindings == 0 {
			markSkipped(j, "no findings available for executive summary")
			return nil
		}
		var b strings.Builder
		b.WriteString("# Executive Summary\n\n")
		b.WriteString(fmt.Sprintf("Target: %s\n\n", data.Target.Domain))
		b.WriteString(fmt.Sprintf("Total findings: %d (%d confirmed)\n\n", data.Summary.TotalFindings, data.Summary.ConfirmedFindings))
		b.WriteString("## Severity Breakdown\n")
		for _, sev := range []models.Severity{models.Critical, models.High, models.Medium, models.Low, models.Info} {
			b.WriteString(fmt.Sprintf("- %s: %d\n", strings.ToUpper(string(sev)), data.Summary.BySeverity[sev]))
		}
		b.WriteString("\n## Top Risk Themes\n")
		for _, finding := range data.Summary.TopFindings {
			b.WriteString(fmt.Sprintf("- %s (%.1f) — %s\n", safeString(finding.VulnClass, "unknown"), finding.CVSS, safeString(finding.URL, finding.Host)))
		}
		if len(data.Summary.Chains) > 0 {
			b.WriteString("\n## Chain Opportunities\n")
			for _, chain := range data.Summary.Chains {
				b.WriteString(fmt.Sprintf("- %s: %s\n", chain.Name, chain.Description))
			}
		}
		return writeText(j.OutputFile, b.String())
	}
	execSummary.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }

	jobs := []*engine.Job{markdown, html, pdf, execSummary}
	jobs = append(jobs, buildCoverageJobs(ctx, markdown.ID, html.ID, pdf.ID, execSummary.ID)...)
	return jobs
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func countNonEmptyLines(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func writeText(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func markSkipped(job *engine.Job, reason string) {
	if job == nil {
		return
	}
	job.Status = engine.JobSkipped
	job.ErrorMsg = reason
	job.LogLine("[WARN] " + reason)
}
