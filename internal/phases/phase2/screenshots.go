package phase2

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
)

func buildScreenshotJobs(ctx phase2Context, extractLiveID string, naabuID string) []*engine.Job {
	jobs := make([]*engine.Job, 0, 4)

	gowitness := engine.NewJob(2, "gowitness-screenshot", "gowitness", nil)
	gowitness.Description = "Capture screenshots for live hosts"
	gowitness.OutputFile = filepath.Join(ctx.ws.Screenshots, "gowitness.log")
	if strings.TrimSpace(extractLiveID) != "" {
		gowitness.DependsOn = []string{extractLiveID}
	}
	gowitness.Timeout = 10 * time.Minute
	gowitness.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "no live hosts file available for gowitness")
			return nil
		}
		args := []string{"file", "-f", ctx.liveHosts, "-P", ctx.ws.Screenshots, "--threads", fmt.Sprintf("%d", ctx.threads)}
		return runStdoutToFile(execCtx, "gowitness", args, j.OutputFile)
	}
	gowitness.ParseOutput = func(_ *engine.Job) int { return countFiles(ctx.ws.Screenshots) }
	jobs = append(jobs, gowitness)

	eyewitness := engine.NewJob(2, "eyewitness", "python3", nil)
	eyewitness.Description = "Alternative screenshot pipeline via EyeWitness"
	eyewitness.OutputFile = filepath.Join(ctx.ws.Screenshots, "eyewitness.log")
	eyewitness.DependsOn = []string{gowitness.ID}
	eyewitness.Timeout = 10 * time.Minute
	eyewitness.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) {
			markSkipped(j, "no live hosts file available for EyeWitness")
			return nil
		}
		if _, err := exec.LookPath("gowitness"); err == nil {
			markSkipped(j, "gowitness available; skipping EyeWitness fallback")
			return nil
		}
		script := filepath.Join(expandHome("~"), ".local", "share", "n0rmxl", "tools", "EyeWitness", "EyeWitness.py")
		if !fileExists(script) {
			markSkipped(j, "EyeWitness script not found")
			return nil
		}
		args := []string{script, "-f", ctx.liveHosts, "-d", filepath.Join(ctx.ws.Screenshots, "eyewitness"), "--no-prompt"}
		return runStdoutToFile(execCtx, "python3", args, j.OutputFile)
	}
	eyewitness.ParseOutput = func(_ *engine.Job) int { return countFiles(filepath.Join(ctx.ws.Screenshots, "eyewitness")) }
	jobs = append(jobs, eyewitness)

	webanalyze := engine.NewJob(2, "webanalyze", "webanalyze", nil)
	webanalyze.Description = "Technology fingerprinting with webanalyze"
	webanalyze.OutputFile = filepath.Join(ctx.ws.ScansTech, "webanalyze.json")
	if strings.TrimSpace(extractLiveID) != "" {
		webanalyze.DependsOn = []string{extractLiveID}
	}
	webanalyze.Timeout = 10 * time.Minute
	webanalyze.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) {
			markSkipped(j, "no live hosts file available for webanalyze")
			return nil
		}
		return runCommand(execCtx, "webanalyze", []string{"-hosts", ctx.liveHosts, "-output", "json", "-worker", fmt.Sprintf("%d", ctx.threads), "-silent", "-o", j.OutputFile})
	}
	webanalyze.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, webanalyze)

	fingerprintx := engine.NewJob(2, "fingerprintx", "fingerprintx", nil)
	fingerprintx.Description = "Service fingerprinting from naabu output"
	fingerprintx.OutputFile = filepath.Join(ctx.ws.ScansTech, "fingerprintx.json")
	if strings.TrimSpace(naabuID) != "" {
		fingerprintx.DependsOn = []string{naabuID}
	}
	fingerprintx.Timeout = 10 * time.Minute
	fingerprintx.Execute = func(execCtx context.Context, j *engine.Job) error {
		naabuOut := filepath.Join(ctx.ws.ScansPorts, "naabu_top1000.txt")
		if !fileExists(naabuOut) || countFileLines(naabuOut) == 0 {
			markSkipped(j, "no naabu output available for fingerprintx")
			return nil
		}
		return runCommand(execCtx, "fingerprintx", []string{"-l", naabuOut, "--json", "-o", j.OutputFile})
	}
	fingerprintx.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, fingerprintx)

	return jobs
}
