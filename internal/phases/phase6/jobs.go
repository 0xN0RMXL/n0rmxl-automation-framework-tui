package phase6

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/config"
	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/models"
	"github.com/n0rmxl/n0rmxl/internal/phases/phase6/exploits"
)

type phase6Context struct {
	target      *models.Target
	ws          models.Workspace
	runCfg      *config.RunConfig
	domain      string
	findingsRaw string
	planFile    string
	playbook    string
	checklist   string
}

type phase6ClassSummary struct {
	Class     string          `json:"class"`
	Severity  models.Severity `json:"severity"`
	Count     int             `json:"count"`
	TopTarget string          `json:"top_target"`
}

func Jobs(target *models.Target, ws models.Workspace, runCfg *config.RunConfig) []*engine.Job {
	if target == nil || strings.TrimSpace(target.Domain) == "" {
		return []*engine.Job{}
	}
	_ = os.MkdirAll(ws.Notes, 0o755)
	_ = os.MkdirAll(ws.Reports, 0o755)

	ctx := phase6Context{
		target:      target,
		ws:          ws,
		runCfg:      runCfg,
		domain:      strings.TrimSpace(target.Domain),
		findingsRaw: filepath.Join(ws.Hidden, "phase6_findings.json"),
		planFile:    filepath.Join(ws.Notes, "phase6_wizard_plan.md"),
		playbook:    filepath.Join(ws.Notes, "phase6_exploit_playbook.md"),
		checklist:   filepath.Join(ws.Notes, "phase6_evidence_checklist.md"),
	}

	load := engine.NewJob(6, "phase6-load-findings", "", nil)
	load.Description = "Load findings from DB for exploitation wizard"
	load.OutputFile = ctx.findingsRaw
	load.Timeout = 2 * time.Minute
	load.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		findings, err := loadFindings(ctx.ws)
		if err != nil {
			return err
		}
		if len(findings) == 0 {
			markSkipped(j, "no findings in database")
			return nil
		}
		sortFindings(findings)
		return writeJSON(j.OutputFile, findings)
	}
	load.ParseOutput = func(j *engine.Job) int {
		findings := readFindingsFile(j.OutputFile)
		return len(findings)
	}

	plan := engine.NewJob(6, "phase6-wizard-plan", "", nil)
	plan.Description = "Generate vulnerability class selection plan for wizard"
	plan.OutputFile = ctx.planFile
	plan.DependsOn = []string{load.ID}
	plan.Timeout = 2 * time.Minute
	plan.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		findings := readFindingsFile(ctx.findingsRaw)
		if len(findings) == 0 {
			markSkipped(j, "no findings available for wizard plan")
			return nil
		}
		summary := summarizeByClass(findings)
		var b strings.Builder
		b.WriteString("# Phase 6 Exploitation Wizard Plan\n\n")
		b.WriteString("Generated from findings DB. Classes are sorted by severity and count.\n\n")
		for i, row := range summary {
			b.WriteString(fmt.Sprintf("%d. [%s] %s (%d targets) — top target: %s\n", i+1, strings.ToUpper(string(row.Severity)), row.Class, row.Count, row.TopTarget))
		}
		b.WriteString("\n## Manual-only classes to consider\n")
		b.WriteString("- xxe\n- ssti\n- request-smuggling\n- race-condition\n- business-logic\n- oauth\n- file-upload\n- graphql\n")
		return writeText(j.OutputFile, b.String())
	}
	plan.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }

	playbook := engine.NewJob(6, "phase6-exploit-playbook", "", nil)
	playbook.Description = "Generate per-finding exploit command playbook"
	playbook.OutputFile = ctx.playbook
	playbook.DependsOn = []string{load.ID}
	playbook.Timeout = 3 * time.Minute
	playbook.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		findings := readFindingsFile(ctx.findingsRaw)
		if len(findings) == 0 {
			markSkipped(j, "no findings available for playbook generation")
			return nil
		}
		modules := exploits.DefaultModules()
		var b strings.Builder
		b.WriteString("# Phase 6 Exploit Playbook\n\n")
		for idx, finding := range findings {
			if idx >= 80 {
				break
			}
			module := exploits.SelectModule(finding.VulnClass, modules)
			steps := module.Steps(ctx.domain, &finding, ctx.runCfg)
			b.WriteString(fmt.Sprintf("## [%s] %s\n\n", strings.ToUpper(string(finding.Severity)), safeTitle(finding)))
			b.WriteString(fmt.Sprintf("- Class: %s\n", finding.VulnClass))
			b.WriteString(fmt.Sprintf("- Host: %s\n", safeString(finding.Host, "n/a")))
			b.WriteString(fmt.Sprintf("- URL: %s\n\n", safeString(finding.URL, "n/a")))
			for i, step := range steps {
				b.WriteString(fmt.Sprintf("%d. **%s** — %s\n", i+1, step.Name, step.Description))
				b.WriteString("```bash\n")
				b.WriteString(step.Command + "\n")
				b.WriteString("```\n\n")
			}
		}
		return writeText(j.OutputFile, b.String())
	}
	playbook.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }

	checklist := engine.NewJob(6, "phase6-evidence-checklist", "", nil)
	checklist.Description = "Generate evidence capture checklist for manual exploitation"
	checklist.OutputFile = ctx.checklist
	checklist.DependsOn = []string{plan.ID, playbook.ID}
	checklist.Timeout = 1 * time.Minute
	checklist.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		content := "# Phase 6 Evidence Checklist\n\n" +
			"- Capture raw request and response pair for every confirmed issue\n" +
			"- Save screenshot or terminal output snippet proving impact\n" +
			"- Record exact payload and parameter used\n" +
			"- Add reproduction curl command to finding record\n" +
			"- Mark duplicate/chained findings appropriately\n" +
			"- Confirm remediation recommendation quality\n"
		return writeText(j.OutputFile, content)
	}
	checklist.ParseOutput = func(j *engine.Job) int { return countNonEmptyLines(j.OutputFile) }

	jobs := []*engine.Job{load, plan, playbook, checklist}
	jobs = append(jobs, buildModuleJobs(ctx, load.ID)...)
	return jobs
}

func loadFindings(ws models.Workspace) ([]models.Finding, error) {
	db, err := models.InitFindingsDB(ws.Root)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return models.GetFindings(db, models.FindingFilter{})
}

func readFindingsFile(path string) []models.Finding {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []models.Finding{}
	}
	var findings []models.Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return []models.Finding{}
	}
	return findings
}

func summarizeByClass(findings []models.Finding) []phase6ClassSummary {
	type aggregate struct {
		count    int
		severity models.Severity
		target   string
	}
	groups := make(map[string]aggregate)
	for _, finding := range findings {
		className := strings.TrimSpace(strings.ToLower(finding.VulnClass))
		if className == "" {
			className = "unknown"
		}
		entry := groups[className]
		entry.count++
		if severityRank(finding.Severity) > severityRank(entry.severity) {
			entry.severity = finding.Severity
		}
		if entry.target == "" {
			entry.target = safeString(finding.Host, safeString(finding.URL, "n/a"))
		}
		groups[className] = entry
	}
	out := make([]phase6ClassSummary, 0, len(groups))
	for className, row := range groups {
		out = append(out, phase6ClassSummary{Class: className, Severity: row.severity, Count: row.count, TopTarget: row.target})
	}
	sort.Slice(out, func(i int, j int) bool {
		if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
			return severityRank(out[i].Severity) > severityRank(out[j].Severity)
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Class < out[j].Class
	})
	return out
}

func sortFindings(findings []models.Finding) {
	sort.SliceStable(findings, func(i int, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		if findings[i].CVSS != findings[j].CVSS {
			return findings[i].CVSS > findings[j].CVSS
		}
		if findings[i].VulnClass != findings[j].VulnClass {
			return findings[i].VulnClass < findings[j].VulnClass
		}
		return findings[i].URL < findings[j].URL
	})
}

func severityRank(severity models.Severity) int {
	switch severity {
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

func markSkipped(job *engine.Job, reason string) {
	if job == nil {
		return
	}
	job.Status = engine.JobSkipped
	job.ErrorMsg = reason
	job.LogLine("[WARN] " + reason)
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func writeText(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
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

func safeString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func safeTitle(f models.Finding) string {
	title := strings.TrimSpace(f.Title)
	if title != "" {
		return title
	}
	if strings.TrimSpace(f.VulnClass) != "" {
		return f.VulnClass
	}
	return "Untitled finding"
}
