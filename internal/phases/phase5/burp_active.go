package phase5

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	burppkg "github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/integrations/burp"
)

func buildBurpActiveJobs(ctx phase5Context) []*engine.Job {
	job := engine.NewJob(5, "burp-active", "", nil)
	job.ID = "phase5-burp-active-scan"
	job.Description = "Attempt Burp API active scan trigger when Burp mode is enabled"
	job.OutputFile = filepath.Join(ctx.ws.ScansBurp, "active_scan_results.json")
	job.Timeout = 5 * time.Minute
	job.Execute = func(execCtx context.Context, j *engine.Job) error {
		_ = execCtx
		if ctx.runCfg == nil || !ctx.runCfg.UseBurp {
			markSkipped(j, "Burp integration disabled in run config")
			return nil
		}
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "live hosts file missing")
			return nil
		}

		baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("BURP_API_URL")), "/")
		if baseURL == "" {
			baseURL = "http://127.0.0.1:1337"
		}
		apiKey := strings.TrimSpace(os.Getenv("BURP_API_KEY"))
		client := burppkg.NewBurpClient(baseURL, apiKey)
		if _, err := client.Ping(); err != nil {
			markSkipped(j, "Burp API unreachable at "+baseURL)
			return nil
		}

		targets := readNonEmptyLines(ctx.liveHosts)
		if len(targets) == 0 {
			markSkipped(j, "no live targets available for Burp API")
			return nil
		}
		if len(targets) > 50 {
			targets = targets[:50]
		}

		scope := burppkg.BurpScope{Include: targets}
		_ = client.SetScope(scope)
		scanCfg := burppkg.BurpScanConfig{
			Scope:              scope,
			ScanConfigurations: []burppkg.BurpNamedConfig{{Name: "Crawl and Audit - Lightweight"}},
		}
		taskID, err := client.StartScan(scanCfg)
		if err != nil {
			result := map[string]any{"base_url": baseURL, "targets": targets, "queued": 0, "error": err.Error(), "timestamp": time.Now().UTC().Format(time.RFC3339)}
			return writeJSON(j.OutputFile, result)
		}
		result := map[string]any{
			"base_url":  baseURL,
			"targets":   targets,
			"queued":    len(targets),
			"task_id":   taskID,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}

		pollSeconds := 0
		if rawPoll := strings.TrimSpace(os.Getenv("BURP_POLL_SECONDS")); rawPoll != "" {
			if n, parseErr := strconv.Atoi(rawPoll); parseErr == nil && n > 0 {
				pollSeconds = n
			}
		}
		if pollSeconds > 180 {
			pollSeconds = 180
		}

		issues := make([]burppkg.BurpIssue, 0)
		issuesErrMsg := ""
		if fetched, fetchErr := client.GetIssues(taskID); fetchErr == nil {
			issues = fetched
		} else {
			issuesErrMsg = fetchErr.Error()
		}

		scanStatus := ""
		if scan, scanErr := client.GetScan(taskID); scanErr == nil {
			scanStatus = strings.ToLower(strings.TrimSpace(scan.ScanStatus))
			result["scan_status"] = scan.ScanStatus
		}

		if len(issues) == 0 && pollSeconds > 0 {
			deadline := time.Now().Add(time.Duration(pollSeconds) * time.Second)
			for time.Now().Before(deadline) {
				if execCtx.Err() != nil {
					break
				}
				time.Sleep(5 * time.Second)

				if scan, scanErr := client.GetScan(taskID); scanErr == nil {
					scanStatus = strings.ToLower(strings.TrimSpace(scan.ScanStatus))
					result["scan_status"] = scan.ScanStatus
				}

				if fetched, fetchErr := client.GetIssues(taskID); fetchErr == nil {
					issues = fetched
					issuesErrMsg = ""
				} else {
					issuesErrMsg = fetchErr.Error()
				}

				if len(issues) > 0 {
					break
				}
				if scanStatus == "succeeded" || scanStatus == "completed" || scanStatus == "finished" || scanStatus == "failed" || scanStatus == "error" || scanStatus == "cancelled" || scanStatus == "canceled" {
					break
				}
			}
		}

		findings := client.IssuesToFindings(issues, ctx.domain)
		saveFindings(ctx.ws, findings)

		result["issues_count"] = len(issues)
		result["findings_saved"] = len(findings)
		if issuesErrMsg != "" {
			result["issues_error"] = issuesErrMsg
		}
		return writeJSON(j.OutputFile, result)
	}
	job.ParseOutput = func(j *engine.Job) int {
		raw, err := os.ReadFile(j.OutputFile)
		if err != nil {
			return 0
		}
		var payload struct {
			Queued int `json:"queued"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return 0
		}
		return payload.Queued
	}
	return []*engine.Job{job}
}

