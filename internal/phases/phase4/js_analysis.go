package phase4

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/models"
)

func buildJSAnalysisJobs(ctx phase4Context, mergeURLsID string) []*engine.Job {
	jobs := make([]*engine.Job, 0, 8)
	subjsOut := filepath.Join(ctx.ws.ReconJS, "subjs.txt")
	linkfinderOut := filepath.Join(ctx.ws.ReconJS, "endpoints.txt")
	secretfinderOut := filepath.Join(ctx.jsSecretsDir, "secretfinder.txt")
	jsleakOut := filepath.Join(ctx.jsSecretsDir, "jsleak.txt")
	mantraOut := filepath.Join(ctx.jsSecretsDir, "mantra.txt")
	trufflehogOut := filepath.Join(ctx.jsSecretsDir, "trufflehog.json")

	extract := engine.NewJob(4, "extract-js", "", nil)
	extract.ID = "phase4-extract-js-urls"
	extract.Description = "Extract JS files from merged URL set"
	extract.OutputFile = ctx.allJS
	extract.DependsOn = []string{mergeURLsID}
	extract.Timeout = 3 * time.Minute
	extract.Execute = func(execCtx context.Context, j *engine.Job) error {
		input := ctx.urlsDeduped
		if !fileExists(input) {
			input = ctx.urlsMerged
		}
		if !fileExists(input) {
			markSkipped(j, "no URL corpus found")
			return nil
		}
		rows := readNonEmptyLines(input)
		jsURLs := make([]string, 0, len(rows)/5)
		for _, row := range rows {
			if strings.Contains(strings.ToLower(row), ".js") {
				jsURLs = append(jsURLs, row)
			}
		}
		sort.Strings(jsURLs)
		jsURLs = dedupSorted(jsURLs)
		return writeLines(j.OutputFile, jsURLs)
	}
	extract.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, extract)

	subjs := engine.NewJob(4, "subjs", "subjs", nil)
	subjs.ID = "phase4-subjs"
	subjs.Description = "Discover additional JS assets from hosts"
	subjs.OutputFile = subjsOut
	subjs.DependsOn = []string{extract.ID}
	subjs.Timeout = 12 * time.Minute
	subjs.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		if err := runCommandWithInputFileToOutput(execCtx, ctx.runCfg, "subjs", nil, ctx.liveHosts, j.OutputFile); err != nil {
			return err
		}
		all := append(readNonEmptyLines(ctx.allJS), readNonEmptyLines(j.OutputFile)...)
		sort.Strings(all)
		all = dedupSorted(all)
		return writeLines(ctx.allJS, all)
	}
	subjs.ParseOutput = func(j *engine.Job) int { return countFileLines(ctx.allJS) }
	jobs = append(jobs, subjs)

	linkfinder := engine.NewJob(4, "linkfinder", selectPythonBinary(), nil)
	linkfinder.ID = "phase4-linkfinder"
	linkfinder.Description = "Extract hardcoded endpoints from JS files"
	linkfinder.OutputFile = linkfinderOut
	linkfinder.DependsOn = []string{subjs.ID}
	linkfinder.Timeout = 25 * time.Minute
	linkfinder.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.allJS) {
			markSkipped(j, "all_js corpus missing")
			return nil
		}
		script := expandHome("~/.local/share/n0rmxl/tools/LinkFinder/linkfinder.py")
		if !fileExists(script) {
			script = expandHome("~/.local/share/n0rmxl/tools/linkfinder/linkfinder.py")
		}
		if !fileExists(script) {
			markSkipped(j, "linkfinder.py not found")
			return nil
		}
		jsURLs := readNonEmptyLines(ctx.allJS)
		if len(jsURLs) == 0 {
			markSkipped(j, "all_js is empty")
			return nil
		}
		workers := minInt(20, maxInt(2, ctx.threads/2))
		in := make(chan string)
		out := make(chan []string, workers)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for jsURL := range in {
					rows, err := collectCommandLines(execCtx, ctx.runCfg, selectPythonBinary(), []string{script, "-i", jsURL, "-o", "cli"}, "")
					if err == nil {
						out <- rows
					}
				}
			}()
		}
		go func() {
			for _, jsURL := range jsURLs {
				in <- jsURL
			}
			close(in)
			wg.Wait()
			close(out)
		}()
		endpoints := make([]string, 0, 512)
		for rows := range out {
			for _, row := range rows {
				if isLikelyURL(row) || strings.HasPrefix(row, "/") {
					endpoints = append(endpoints, row)
				}
			}
		}
		sort.Strings(endpoints)
		endpoints = dedupSorted(endpoints)
		return writeLines(j.OutputFile, endpoints)
	}
	linkfinder.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, linkfinder)

	secretfinder := engine.NewJob(4, "secretfinder", selectPythonBinary(), nil)
	secretfinder.ID = "phase4-secretfinder"
	secretfinder.Description = "Scan JavaScript files for exposed secrets"
	secretfinder.OutputFile = secretfinderOut
	secretfinder.DependsOn = []string{subjs.ID}
	secretfinder.Timeout = 25 * time.Minute
	secretfinder.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.allJS) {
			markSkipped(j, "all_js corpus missing")
			return nil
		}
		script := expandHome("~/.local/share/n0rmxl/tools/SecretFinder/SecretFinder.py")
		if !fileExists(script) {
			markSkipped(j, "SecretFinder.py not found")
			return nil
		}
		jsURLs := readNonEmptyLines(ctx.allJS)
		if len(jsURLs) == 0 {
			markSkipped(j, "all_js is empty")
			return nil
		}
		secrets := make([]string, 0, 256)
		findings := make([]models.Finding, 0, 64)
		for _, jsURL := range jsURLs {
			rows, err := collectCommandLines(execCtx, ctx.runCfg, selectPythonBinary(), []string{script, "-i", jsURL, "-o", "cli"}, "")
			if err != nil {
				continue
			}
			for _, row := range rows {
				lower := strings.ToLower(row)
				if strings.Contains(lower, "token") || strings.Contains(lower, "apikey") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") {
					secrets = append(secrets, jsURL+" :: "+row)
					findings = append(findings, models.Finding{Host: hostFromAny(jsURL), URL: jsURL, VulnClass: "secret-exposure", Severity: models.High, Evidence: row, Tool: "secretfinder"})
				}
			}
		}
		sort.Strings(secrets)
		secrets = dedupSorted(secrets)
		if err := writeLines(j.OutputFile, secrets); err != nil {
			return err
		}
		saveFindings(ctx.ws, findings)
		return nil
	}
	secretfinder.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, secretfinder)

	jsleak := engine.NewJob(4, "jsleak", "jsleak", nil)
	jsleak.ID = "phase4-jsleak"
	jsleak.Description = "Run jsleak against discovered JS assets"
	jsleak.OutputFile = jsleakOut
	jsleak.DependsOn = []string{subjs.ID}
	jsleak.Timeout = 20 * time.Minute
	jsleak.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.allJS) {
			markSkipped(j, "all_js corpus missing")
			return nil
		}
		return runCommandWithInputFileToOutput(execCtx, ctx.runCfg, "jsleak", []string{"-s", "-c", fmt.Sprintf("%d", maxInt(4, ctx.threads/2))}, ctx.allJS, j.OutputFile)
	}
	jsleak.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, jsleak)

	mantra := engine.NewJob(4, "mantra", "mantra", nil)
	mantra.ID = "phase4-mantra"
	mantra.Description = "Run mantra against discovered URL corpus"
	mantra.OutputFile = mantraOut
	mantra.DependsOn = []string{mergeURLsID}
	mantra.Timeout = 20 * time.Minute
	mantra.Execute = func(execCtx context.Context, j *engine.Job) error {
		input := ctx.urlsDeduped
		if !fileExists(input) {
			markSkipped(j, "deduped URLs missing")
			return nil
		}
		return runCommandWithInputFileToOutput(execCtx, ctx.runCfg, "mantra", nil, input, j.OutputFile)
	}
	mantra.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, mantra)

	trufflehog := engine.NewJob(4, "trufflehog", "trufflehog", nil)
	trufflehog.ID = "phase4-trufflehog-web"
	trufflehog.Description = "Scan dumped web artifacts for leaked credentials"
	trufflehog.OutputFile = trufflehogOut
	trufflehog.Timeout = 15 * time.Minute
	trufflehog.Execute = func(execCtx context.Context, j *engine.Job) error {
		gitDumpDir := filepath.Join(ctx.ws.Loot, "git_dumps")
		if !fileExists(gitDumpDir) {
			markSkipped(j, "git dump directory missing")
			return nil
		}
		if err := runStdoutToFile(execCtx, ctx.runCfg, "trufflehog", []string{"filesystem", "--directory", gitDumpDir, "--json", "--no-verification"}, j.OutputFile); err != nil {
			markSkipped(j, "trufflehog scan failed: "+err.Error())
			return nil
		}
		return nil
	}
	trufflehog.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, trufflehog)

	return jobs
}

func selectPythonBinary() string {
	if _, err := exec.LookPath("python3"); err == nil {
		return "python3"
	}
	return "python"
}
