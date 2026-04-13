package phase5

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

func buildNucleiScanJobs(ctx phase5Context) []*engine.Job {
	jobs := make([]*engine.Job, 0, 6)
	criticalOut := filepath.Join(ctx.ws.ScansNuclei, "critical_high.json")
	mediumOut := filepath.Join(ctx.ws.ScansNuclei, "medium_low.json")
	cvesOut := filepath.Join(ctx.ws.ScansNuclei, "cves.json")
	exposuresOut := filepath.Join(ctx.ws.ScansNuclei, "exposures.json")
	fuzzOut := filepath.Join(ctx.ws.ScansNuclei, "fuzzing.json")
	summaryOut := filepath.Join(ctx.ws.ScansNuclei, "parsed_summary.json")

	critical := engine.NewJob(5, "nuclei-critical-high", "nuclei", nil)
	critical.ID = "phase5-nuclei-critical-high"
	critical.Description = "Run nuclei for critical/high severity templates"
	critical.OutputFile = criticalOut
	critical.Timeout = 45 * time.Minute
	critical.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		args := []string{"-l", ctx.liveHosts, "-severity", "critical,high", "-silent", "-json", "-o", j.OutputFile, "-rate-limit", fmt.Sprintf("%d", maxInt(20, ctx.nucleiRate)), "-c", fmt.Sprintf("%d", maxInt(10, ctx.threads))}
		if ctx.runCfg != nil && ctx.runCfg.UseBurp {
			args = append(args, "-proxy", "http://127.0.0.1:8080")
		}
		return runCommand(execCtx, ctx.runCfg, "nuclei", args)
	}
	critical.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, critical)

	medium := engine.NewJob(5, "nuclei-medium-low", "nuclei", nil)
	medium.ID = "phase5-nuclei-medium-low"
	medium.Description = "Run nuclei for medium/low severity templates"
	medium.OutputFile = mediumOut
	medium.DependsOn = []string{critical.ID}
	medium.Timeout = 45 * time.Minute
	medium.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		args := []string{"-l", ctx.liveHosts, "-severity", "medium,low", "-silent", "-json", "-o", j.OutputFile, "-rate-limit", fmt.Sprintf("%d", maxInt(20, ctx.nucleiRate)), "-c", fmt.Sprintf("%d", maxInt(10, ctx.threads))}
		if ctx.runCfg != nil && ctx.runCfg.UseBurp {
			args = append(args, "-proxy", "http://127.0.0.1:8080")
		}
		return runCommand(execCtx, ctx.runCfg, "nuclei", args)
	}
	medium.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, medium)

	cves := engine.NewJob(5, "nuclei-cves", "nuclei", nil)
	cves.ID = "phase5-nuclei-cves"
	cves.Description = "Run nuclei CVE templates"
	cves.OutputFile = cvesOut
	cves.DependsOn = []string{critical.ID}
	cves.Timeout = 45 * time.Minute
	cves.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		args := []string{"-l", ctx.liveHosts, "-t", "cves/", "-silent", "-json", "-o", j.OutputFile, "-rate-limit", fmt.Sprintf("%d", maxInt(20, ctx.nucleiRate)), "-c", fmt.Sprintf("%d", maxInt(10, ctx.threads))}
		if ctx.runCfg != nil && ctx.runCfg.UseBurp {
			args = append(args, "-proxy", "http://127.0.0.1:8080")
		}
		return runCommand(execCtx, ctx.runCfg, "nuclei", args)
	}
	cves.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, cves)

	exposures := engine.NewJob(5, "nuclei-exposures", "nuclei", nil)
	exposures.ID = "phase5-nuclei-exposures"
	exposures.Description = "Run nuclei exposure templates"
	exposures.OutputFile = exposuresOut
	exposures.DependsOn = []string{critical.ID}
	exposures.Timeout = 45 * time.Minute
	exposures.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		args := []string{"-l", ctx.liveHosts, "-t", "exposures/", "-silent", "-json", "-o", j.OutputFile, "-rate-limit", fmt.Sprintf("%d", maxInt(20, ctx.nucleiRate)), "-c", fmt.Sprintf("%d", maxInt(10, ctx.threads))}
		if ctx.runCfg != nil && ctx.runCfg.UseBurp {
			args = append(args, "-proxy", "http://127.0.0.1:8080")
		}
		return runCommand(execCtx, ctx.runCfg, "nuclei", args)
	}
	exposures.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, exposures)

	fuzzing := engine.NewJob(5, "nuclei-fuzzing", "nuclei", nil)
	fuzzing.ID = "phase5-nuclei-fuzzing"
	fuzzing.Description = "Run nuclei fuzzing templates on fuzz URL corpus"
	fuzzing.OutputFile = fuzzOut
	fuzzing.DependsOn = []string{critical.ID}
	fuzzing.Timeout = 45 * time.Minute
	fuzzing.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.fuzzXSS) || countFileLines(ctx.fuzzXSS) == 0 {
			markSkipped(j, "fuzz_xss URL list missing")
			return nil
		}
		args := []string{"-l", ctx.fuzzXSS, "-t", "fuzzing/", "-silent", "-json", "-o", j.OutputFile, "-rate-limit", fmt.Sprintf("%d", maxInt(20, ctx.nucleiRate)), "-c", fmt.Sprintf("%d", maxInt(10, ctx.threads))}
		if ctx.runCfg != nil && ctx.runCfg.UseBurp {
			args = append(args, "-proxy", "http://127.0.0.1:8080")
		}
		return runCommand(execCtx, ctx.runCfg, "nuclei", args)
	}
	fuzzing.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, fuzzing)

	parse := engine.NewJob(5, "nuclei-parse", "", nil)
	parse.ID = "phase5-nuclei-parse"
	parse.Description = "Parse nuclei JSON outputs and save findings"
	parse.OutputFile = summaryOut
	parse.DependsOn = []string{critical.ID, medium.ID, cves.ID, exposures.ID, fuzzing.ID}
	parse.Timeout = 10 * time.Minute
	parse.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		inputs := []string{criticalOut, mediumOut, cvesOut, exposuresOut, fuzzOut}
		findings := make([]models.Finding, 0, 256)
		seen := make(map[string]struct{}, 512)
		for _, input := range inputs {
			if !fileExists(input) {
				continue
			}
			raw, err := os.ReadFile(input)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || !strings.HasPrefix(line, "{") {
					continue
				}
				var row struct {
					TemplateID string `json:"template-id"`
					Host       string `json:"host"`
					MatchedAt  string `json:"matched-at"`
					Type       string `json:"type"`
					Timestamp  string `json:"timestamp"`
					Info       struct {
						Name     string `json:"name"`
						Severity string `json:"severity"`
					} `json:"info"`
				}
				if err := json.Unmarshal([]byte(line), &row); err != nil {
					continue
				}
				idKey := strings.ToLower(strings.TrimSpace(row.TemplateID + "|" + row.Host + "|" + row.MatchedAt))
				if idKey == "||" {
					continue
				}
				if _, ok := seen[idKey]; ok {
					continue
				}
				seen[idKey] = struct{}{}

				title := strings.TrimSpace(row.Info.Name)
				if title == "" {
					title = strings.TrimSpace(row.TemplateID)
				}
				host := hostFromAny(row.MatchedAt)
				if host == "" {
					host = hostFromAny(row.Host)
				}
				finding := models.Finding{
					Phase:       5,
					Target:      ctx.domain,
					Host:        host,
					URL:         strings.TrimSpace(row.MatchedAt),
					VulnClass:   strings.TrimSpace(row.TemplateID),
					Severity:    parseSeverity(row.Info.Severity),
					Title:       title,
					Description: "Nuclei template match: " + strings.TrimSpace(row.TemplateID),
					Evidence:    line,
					Tool:        "nuclei",
					Tags:        []string{"nuclei", strings.TrimSpace(row.Type)},
				}
				if ts, err := time.Parse(time.RFC3339, strings.TrimSpace(row.Timestamp)); err == nil {
					finding.Timestamp = ts
				}
				findings = append(findings, finding)
			}
		}
		saveFindings(ctx.ws, findings)
		summary := map[string]any{"findings": len(findings), "inputs": inputs, "saved_at": time.Now().UTC().Format(time.RFC3339)}
		return writeJSON(j.OutputFile, summary)
	}
	parse.ParseOutput = func(j *engine.Job) int {
		raw, err := os.ReadFile(j.OutputFile)
		if err != nil {
			return 0
		}
		var summary struct {
			Findings int `json:"findings"`
		}
		if err := json.Unmarshal(raw, &summary); err != nil {
			return 0
		}
		return summary.Findings
	}
	jobs = append(jobs, parse)

	return jobs
}

