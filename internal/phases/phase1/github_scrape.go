package phase1

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
)

func buildGithubScrapeJobs(ctx phase1Context) []*engine.Job {
	jobs := make([]*engine.Job, 0, 3)

	githubSubs := engine.NewJob(1, "github-subdomains", "github-subdomains", nil)
	githubSubs.Description = "Subdomain discovery from GitHub code search"
	githubSubs.OutputFile = filepath.Join(ctx.subsDir, "github_subdomains.txt")
	githubSubs.Timeout = 10 * time.Minute
	githubSubs.Execute = func(execCtx context.Context, j *engine.Job) error {
		token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
		if token == "" {
			markSkipped(j, "GITHUB_TOKEN not set, skipping github-subdomains")
			return nil
		}
		return runCommand(execCtx, ctx.runCfg, "github-subdomains", []string{"-d", ctx.domain, "-t", token, "-o", j.OutputFile})
	}
	githubSubs.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, githubSubs)

	gitlabSubs := engine.NewJob(1, "gitlab-subdomains", "gitlab-subdomains", nil)
	gitlabSubs.Description = "Subdomain discovery from GitLab code search"
	gitlabSubs.OutputFile = filepath.Join(ctx.subsDir, "gitlab_subdomains.txt")
	gitlabSubs.Timeout = 10 * time.Minute
	gitlabSubs.Execute = func(execCtx context.Context, j *engine.Job) error {
		token := strings.TrimSpace(os.Getenv("GITLAB_TOKEN"))
		if token == "" {
			markSkipped(j, "GITLAB_TOKEN not set, skipping gitlab-subdomains")
			return nil
		}
		return runCommand(execCtx, ctx.runCfg, "gitlab-subdomains", []string{"-d", ctx.domain, "-t", token, "-o", j.OutputFile})
	}
	gitlabSubs.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, gitlabSubs)

	gitdorker := engine.NewJob(1, "gitdorker", "python3", nil)
	gitdorker.Description = "Subdomain discovery via GitDorker"
	gitdorker.OutputFile = filepath.Join(ctx.subsDir, "gitdorker.txt")
	gitdorker.Timeout = 10 * time.Minute
	gitdorker.Execute = func(execCtx context.Context, j *engine.Job) error {
		token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
		if token == "" {
			markSkipped(j, "GITHUB_TOKEN not set, skipping GitDorker")
			return nil
		}
		toolsDir := filepath.Join(expandHome("~"), ".local", "share", "n0rmxl", "tools", "GitDorker")
		script := filepath.Join(toolsDir, "GitDorker.py")
		dorks := filepath.Join(toolsDir, "dorks", "BHEH_subdomain_dorks.txt")
		if !fileExists(script) || !fileExists(dorks) {
			markSkipped(j, "GitDorker script or dorks file missing")
			return nil
		}
		return runCommand(execCtx, ctx.runCfg, "python3", []string{script, "-tf", token, "-q", ctx.domain, "-d", dorks, "-o", j.OutputFile})
	}
	gitdorker.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, gitdorker)

	return jobs
}

