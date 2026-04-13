package phase2

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
)

func buildDNSBruteJobs(ctx phase2Context) dnsBruteOutput {
	jobs := make([]*engine.Job, 0, 5)

	puredns := engine.NewJob(2, "puredns-brute", "puredns", []string{"bruteforce", ctx.wordlist, ctx.domain, "-r", ctx.resolvers, "-w", filepath.Join(ctx.ws.ReconSubs, "puredns_brute.txt")})
	puredns.Description = "DNS bruteforce via puredns"
	puredns.OutputFile = filepath.Join(ctx.ws.ReconSubs, "puredns_brute.txt")
	puredns.Timeout = 10 * time.Minute
	puredns.Execute = func(execCtx context.Context, j *engine.Job) error {
		if strings.TrimSpace(ctx.wordlist) == "" || !fileExists(ctx.wordlist) {
			markSkipped(j, "dns wordlist not found, skipping puredns")
			return nil
		}
		if strings.TrimSpace(ctx.resolvers) == "" || !fileExists(ctx.resolvers) {
			markSkipped(j, "resolver list not found, skipping puredns")
			return nil
		}
		return runCommand(execCtx, "puredns", []string{"bruteforce", ctx.wordlist, ctx.domain, "-r", ctx.resolvers, "--resolvers-trusted", ctx.trustedResolvers, "-w", j.OutputFile})
	}
	puredns.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, puredns)

	shuffledns := engine.NewJob(2, "shuffledns", "shuffledns", []string{"-d", ctx.domain, "-w", ctx.wordlist, "-r", ctx.resolvers, "-o", filepath.Join(ctx.ws.ReconSubs, "shuffledns.txt")})
	shuffledns.Description = "Secondary DNS bruteforce via shuffledns"
	shuffledns.OutputFile = filepath.Join(ctx.ws.ReconSubs, "shuffledns.txt")
	shuffledns.Timeout = 10 * time.Minute
	shuffledns.Execute = func(execCtx context.Context, j *engine.Job) error {
		if strings.TrimSpace(ctx.wordlist) == "" || !fileExists(ctx.wordlist) {
			markSkipped(j, "dns wordlist not found, skipping shuffledns")
			return nil
		}
		if strings.TrimSpace(ctx.resolvers) == "" || !fileExists(ctx.resolvers) {
			markSkipped(j, "resolver list not found, skipping shuffledns")
			return nil
		}
		return runCommand(execCtx, "shuffledns", []string{"-d", ctx.domain, "-w", ctx.wordlist, "-r", ctx.resolvers, "-o", j.OutputFile})
	}
	shuffledns.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, shuffledns)

	gotator := engine.NewJob(2, "gotator", "gotator", []string{"-sub", ctx.phase1Merged, "-perm", ctx.wordlist, "-depth", "2", "-silent"})
	gotator.Description = "Permutation generation and resolution via gotator + puredns"
	gotator.OutputFile = filepath.Join(ctx.ws.ReconSubs, "permutations_resolved.txt")
	gotator.Timeout = 10 * time.Minute
	gotator.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.phase1Merged) {
			markSkipped(j, "phase1 merged subdomains not found, skipping gotator")
			return nil
		}
		rawOutput := filepath.Join(ctx.ws.ReconSubs, "gotator_raw.txt")
		if err := runStdoutToFile(execCtx, "gotator", []string{"-sub", ctx.phase1Merged, "-perm", ctx.wordlist, "-depth", "2", "-silent"}, rawOutput); err != nil {
			return err
		}
		if !fileExists(rawOutput) || countFileLines(rawOutput) == 0 {
			markSkipped(j, "gotator produced no permutations")
			return nil
		}
		if _, err := exec.LookPath("puredns"); err != nil {
			j.LogLine("[WARN] puredns not found, writing unresolved gotator permutations")
			rows := readNonEmptyLines(rawOutput)
			sort.Strings(rows)
			rows = dedupSorted(rows)
			return writeLines(j.OutputFile, rows)
		}
		if strings.TrimSpace(ctx.resolvers) == "" || !fileExists(ctx.resolvers) {
			j.LogLine("[WARN] resolver list not found, writing unresolved gotator permutations")
			rows := readNonEmptyLines(rawOutput)
			sort.Strings(rows)
			rows = dedupSorted(rows)
			return writeLines(j.OutputFile, rows)
		}
		return runCommand(execCtx, "puredns", []string{"resolve", rawOutput, "-r", ctx.resolvers, "--resolvers-trusted", ctx.trustedResolvers, "-w", j.OutputFile})
	}
	gotator.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, gotator)

	alterx := engine.NewJob(2, "alterx", "alterx", []string{"-l", ctx.phase1Merged, "-enrich", "-silent"})
	alterx.Description = "Permutation generation and resolution via alterx + dnsx"
	alterx.OutputFile = filepath.Join(ctx.ws.ReconSubs, "alterx_resolved.txt")
	alterx.Timeout = 10 * time.Minute
	alterx.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.phase1Merged) {
			markSkipped(j, "phase1 merged subdomains not found, skipping alterx")
			return nil
		}
		candidates, err := collectCommandLines(execCtx, "alterx", []string{"-l", ctx.phase1Merged, "-enrich", "-silent"}, "")
		if err != nil {
			return err
		}
		if len(candidates) == 0 {
			markSkipped(j, "alterx produced no permutations")
			return nil
		}
		resolved := candidates
		if _, err := exec.LookPath("dnsx"); err == nil {
			stream := strings.Join(candidates, "\n") + "\n"
			rows, dnsxErr := collectCommandLines(execCtx, "dnsx", []string{"-silent"}, stream)
			if dnsxErr != nil {
				j.LogLine("[WARN] dnsx resolution failed, writing unresolved alterx output: " + dnsxErr.Error())
			} else if len(rows) > 0 {
				resolved = rows
			}
		} else {
			j.LogLine("[WARN] dnsx not found, writing unresolved alterx output")
		}
		sort.Strings(resolved)
		resolved = dedupSorted(resolved)
		return writeLines(j.OutputFile, resolved)
	}
	alterx.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, alterx)

	mergePhase2 := engine.NewJob(2, "merge-subs-phase2", "", nil)
	mergePhase2.Description = "Merge phase1 and phase2 subdomain outputs into final_subs"
	mergePhase2.OutputFile = ctx.phase2Merged
	mergePhase2.DependsOn = []string{puredns.ID, shuffledns.ID, gotator.ID, alterx.ID}
	mergePhase2.Execute = func(execCtx context.Context, j *engine.Job) error {
		if err := execCtx.Err(); err != nil {
			return err
		}
		inputs := []string{ctx.phase1Merged, puredns.OutputFile, shuffledns.OutputFile, gotator.OutputFile, alterx.OutputFile}
		available := existingFiles(inputs)
		if len(available) == 0 {
			markSkipped(j, "no input subdomain files available for merge")
			return nil
		}
		manager := engine.NewOutputManager(ctx.ws)
		if _, err := manager.MergeAndDedup(available, j.OutputFile); err != nil {
			return err
		}
		if ctx.runCfg != nil && ctx.runCfg.Scope != nil {
			tmp := j.OutputFile + ".tmp"
			if _, err := manager.ScopeFilter(j.OutputFile, tmp, ctx.runCfg.Scope); err == nil {
				_ = os.Remove(j.OutputFile)
				_ = os.Rename(tmp, j.OutputFile)
			}
		}
		j.LogLine("[DONE] built phase2 final_subs file")
		return nil
	}
	mergePhase2.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, mergePhase2)

	return dnsBruteOutput{Jobs: jobs, MergeJobID: mergePhase2.ID}
}

