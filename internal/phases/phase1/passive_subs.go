package phase1

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
)

func buildPassiveSubsJobs(ctx phase1Context) []*engine.Job {
	jobs := make([]*engine.Job, 0, 8)

	subfinder := engine.NewJob(1, "subfinder", "subfinder", []string{"-d", ctx.domain, "-all", "-recursive", "-silent", "-o", filepath.Join(ctx.subsDir, "subfinder.txt")})
	subfinder.Description = "Passive subdomain enumeration with subfinder"
	subfinder.OutputFile = filepath.Join(ctx.subsDir, "subfinder.txt")
	subfinder.Timeout = 10 * time.Minute
	subfinder.Execute = func(execCtx context.Context, j *engine.Job) error {
		args := []string{"-d", ctx.domain, "-all", "-recursive", "-silent", "-o", j.OutputFile}
		if len(ctx.target.Explicit) > 0 {
			domainList := filepath.Join(ctx.ws.Hidden, "phase1_subfinder_domains.txt")
			if err := os.WriteFile(domainList, []byte(strings.Join(ctx.target.Explicit, "\n")+"\n"), 0o644); err == nil {
				args = []string{"-dL", domainList, "-all", "-recursive", "-silent", "-o", j.OutputFile}
			}
		}
		return runCommand(execCtx, ctx.runCfg, "subfinder", args)
	}
	subfinder.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, subfinder)

	assetfinder := engine.NewJob(1, "assetfinder", "assetfinder", []string{"--subs-only", ctx.domain})
	assetfinder.Description = "Passive subdomain enumeration with assetfinder"
	assetfinder.OutputFile = filepath.Join(ctx.subsDir, "assetfinder.txt")
	assetfinder.Timeout = 10 * time.Minute
	assetfinder.Execute = func(execCtx context.Context, j *engine.Job) error {
		return runStdoutToFile(execCtx, ctx.runCfg, "assetfinder", []string{"--subs-only", ctx.domain}, j.OutputFile)
	}
	assetfinder.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, assetfinder)

	findomain := engine.NewJob(1, "findomain", "findomain", []string{"-t", ctx.domain, "-u", filepath.Join(ctx.subsDir, "findomain.txt")})
	findomain.Description = "Passive subdomain enumeration with findomain"
	findomain.OutputFile = filepath.Join(ctx.subsDir, "findomain.txt")
	findomain.Timeout = 10 * time.Minute
	findomain.Execute = func(execCtx context.Context, j *engine.Job) error {
		return runCommand(execCtx, ctx.runCfg, "findomain", []string{"-t", ctx.domain, "-u", j.OutputFile})
	}
	findomain.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, findomain)

	chaos := engine.NewJob(1, "chaos", "chaos", []string{"-d", ctx.domain, "-silent", "-o", filepath.Join(ctx.subsDir, "chaos.txt")})
	chaos.Description = "Chaos passive subdomain enumeration"
	chaos.OutputFile = filepath.Join(ctx.subsDir, "chaos.txt")
	chaos.Timeout = 10 * time.Minute
	chaos.Execute = func(execCtx context.Context, j *engine.Job) error {
		if strings.TrimSpace(os.Getenv("PDCP_API_KEY")) == "" {
			markSkipped(j, "PDCP_API_KEY not set, skipping chaos")
			return nil
		}
		return runCommand(execCtx, ctx.runCfg, "chaos", []string{"-d", ctx.domain, "-silent", "-o", j.OutputFile})
	}
	chaos.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, chaos)

	amass := engine.NewJob(1, "amass-passive", "amass", []string{"enum", "-passive", "-d", ctx.domain, "-o", filepath.Join(ctx.subsDir, "amass_passive.txt")})
	amass.Description = "Passive subdomain enumeration with amass"
	amass.OutputFile = filepath.Join(ctx.subsDir, "amass_passive.txt")
	amass.Timeout = 15 * time.Minute
	amass.Execute = func(execCtx context.Context, j *engine.Job) error {
		return runCommand(execCtx, ctx.runCfg, "amass", []string{"enum", "-passive", "-d", ctx.domain, "-o", j.OutputFile})
	}
	amass.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, amass)

	bbotDir := filepath.Join(ctx.subsDir, "bbot")
	bbot := engine.NewJob(1, "bbot", "bbot", []string{"-t", ctx.domain, "-f", "subdomain-enum", "-o", bbotDir})
	bbot.Description = "Passive subdomain enumeration with bbot"
	bbot.OutputFile = filepath.Join(ctx.subsDir, "bbot.txt")
	bbot.Timeout = 30 * time.Minute
	bbot.Execute = func(execCtx context.Context, j *engine.Job) error {
		return runCommand(execCtx, ctx.runCfg, "bbot", []string{"-t", ctx.domain, "-f", "subdomain-enum", "-o", bbotDir})
	}
	bbot.ParseOutput = func(_ *engine.Job) int { return countLinesInDir(bbotDir) }
	jobs = append(jobs, bbot)

	subdominator := engine.NewJob(1, "subdominator", "subdominator", []string{"-d", ctx.domain, "-o", filepath.Join(ctx.subsDir, "subdominator.txt")})
	subdominator.Description = "Passive subdomain enumeration with subdominator"
	subdominator.OutputFile = filepath.Join(ctx.subsDir, "subdominator.txt")
	subdominator.Timeout = 10 * time.Minute
	subdominator.Execute = func(execCtx context.Context, j *engine.Job) error {
		return runCommand(execCtx, ctx.runCfg, "subdominator", []string{"-d", ctx.domain, "-o", j.OutputFile})
	}
	subdominator.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, subdominator)

	haktrails := engine.NewJob(1, "haktrails", "haktrails", []string{"subdomains", ctx.domain})
	haktrails.Description = "Passive subdomain enumeration with haktrails"
	haktrails.OutputFile = filepath.Join(ctx.subsDir, "haktrails.txt")
	haktrails.Timeout = 10 * time.Minute
	haktrails.Execute = func(execCtx context.Context, j *engine.Job) error {
		securityTrailsKey := firstNonEmptyEnv("SECURITYTRAILS_API_KEY", "SECURITYTRAILS_KEY")
		if securityTrailsKey == "" {
			markSkipped(j, "SECURITYTRAILS key not set, skipping haktrails")
			return nil
		}
		return runStdoutToFile(execCtx, ctx.runCfg, "haktrails", []string{"subdomains", ctx.domain}, j.OutputFile)
	}
	haktrails.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, haktrails)

	return jobs
}
