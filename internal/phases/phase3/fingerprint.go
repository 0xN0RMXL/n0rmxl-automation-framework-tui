package phase3

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
)

func buildFingerprintJobs(ctx phase3Context) []*engine.Job {
	jobs := make([]*engine.Job, 0, 5)

	whatweb := engine.NewJob(3, "whatweb", "whatweb", nil)
	whatweb.Description = "Technology fingerprinting with WhatWeb"
	whatweb.OutputFile = filepath.Join(ctx.ws.ScansTech, "whatweb.json")
	whatweb.Timeout = 10 * time.Minute
	whatweb.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing; skipping whatweb")
			return nil
		}
		ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
		args := []string{"--input-file", ctx.liveHosts, "--log-json", j.OutputFile, "--aggression", "3", "--user-agent", ua}
		return runCommand(execCtx, ctx.runCfg, "whatweb", args)
	}
	whatweb.ParseOutput = func(j *engine.Job) int { return parseWhatwebUniqueTech(j.OutputFile) }
	jobs = append(jobs, whatweb)

	wafw00f := engine.NewJob(3, "wafw00f", "wafw00f", nil)
	wafw00f.Description = "WAF detection via wafw00f"
	wafw00f.OutputFile = filepath.Join(ctx.ws.ScansTech, "wafs.txt")
	wafw00f.Timeout = 10 * time.Minute
	wafw00f.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing; skipping wafw00f")
			return nil
		}
		args := []string{"-i", ctx.liveHosts, "-o", j.OutputFile, "-f", "json"}
		return runCommand(execCtx, ctx.runCfg, "wafw00f", args)
	}
	wafw00f.ParseOutput = func(j *engine.Job) int {
		raw, err := os.ReadFile(j.OutputFile)
		if err != nil {
			return 0
		}
		var payload []map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			return countFileLines(j.OutputFile)
		}
		count := 0
		for _, row := range payload {
			if detected, ok := row["detected"].(bool); ok && detected {
				count++
				continue
			}
			if waf, ok := row["firewall"]; ok && strings.TrimSpace(fmt.Sprint(waf)) != "" {
				count++
			}
		}
		return count
	}
	jobs = append(jobs, wafw00f)

	cors := engine.NewJob(3, "corsscanner", "python3", nil)
	cors.Description = "CORS misconfiguration scanning with Corsy"
	cors.OutputFile = filepath.Join(ctx.ws.ScansTech, "cors_scan.json")
	cors.Timeout = 15 * time.Minute
	cors.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing; skipping CORS scanner")
			return nil
		}
		script := filepath.Join(expandHome("~"), ".local", "share", "n0rmxl", "tools", "Corsy", "corsy.py")
		if !fileExists(script) {
			markSkipped(j, "Corsy script not found")
			return nil
		}
		args := []string{script, "-i", ctx.liveHosts, "-t", fmt.Sprintf("%d", ctx.threads), "-o", j.OutputFile}
		return runCommand(execCtx, ctx.runCfg, "python3", args)
	}
	cors.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, cors)

	subzy := engine.NewJob(3, "subzy", "subzy", nil)
	subzy.Description = "Subdomain takeover detection"
	subzy.OutputFile = filepath.Join(ctx.ws.VulnDir("takeover"), "subzy.json")
	subzy.Timeout = 10 * time.Minute
	subzy.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.allSubsMerged) || countFileLines(ctx.allSubsMerged) == 0 {
			markSkipped(j, "merged subdomain file missing; skipping subzy")
			return nil
		}
		args := []string{"run", "--targets", ctx.allSubsMerged, "--concurrency", fmt.Sprintf("%d", ctx.threads), "--hide-fails", "--output", j.OutputFile}
		return runCommand(execCtx, ctx.runCfg, "subzy", args)
	}
	subzy.ParseOutput = func(j *engine.Job) int {
		count := 0
		for _, row := range readNonEmptyLines(j.OutputFile) {
			lower := strings.ToLower(row)
			if strings.Contains(lower, "vulnerable") || strings.Contains(lower, "takeover") {
				count++
			}
		}
		return count
	}
	jobs = append(jobs, subzy)

	nucleiTech := engine.NewJob(3, "nuclei-tech", "nuclei", nil)
	nucleiTech.Description = "Nuclei technology template scan"
	nucleiTech.OutputFile = filepath.Join(ctx.ws.ScansNuclei, "tech.json")
	nucleiTech.Timeout = 15 * time.Minute
	nucleiTech.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing; skipping nuclei tech")
			return nil
		}
		rate := ctx.nucleiRate
		if rate <= 0 {
			rate = 50
		}
		args := []string{"-l", ctx.liveHosts, "-t", "technologies/", "-silent", "-json", "-o", j.OutputFile, "-rate-limit", fmt.Sprintf("%d", rate), "-c", fmt.Sprintf("%d", ctx.threads)}
		return runCommand(execCtx, ctx.runCfg, "nuclei", args)
	}
	nucleiTech.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, nucleiTech)

	return jobs
}
