package phase2

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
)

func buildHTTPProbeJobs(ctx phase2Context, mergeJobID string) httpProbeOutput {
	jobs := make([]*engine.Job, 0, 4)

	httpxProbe := engine.NewJob(2, "httpx-probe", "httpx", nil)
	httpxProbe.Description = "Probe live hosts with httpx"
	httpxProbe.OutputFile = ctx.httpxJSON
	if strings.TrimSpace(mergeJobID) != "" {
		httpxProbe.DependsOn = []string{mergeJobID}
	}
	httpxProbe.Timeout = 10 * time.Minute
	httpxProbe.Execute = func(execCtx context.Context, j *engine.Job) error {
		input := pickExisting(ctx.phase2Merged, ctx.phase1Merged)
		if input == "" {
			markSkipped(j, "no subdomain input available for httpx")
			return nil
		}
		args := []string{"-l", input, "-title", "-tech-detect", "-status-code", "-content-length", "-follow-redirects", "-random-agent", "-json", "-o", j.OutputFile, "-threads", fmt.Sprintf("%d", ctx.threads)}
		if ctx.rateLimit > 0 {
			args = append(args, "-rate-limit", fmt.Sprintf("%d", ctx.rateLimit))
		}
		return runCommand(execCtx, "httpx", args)
	}
	httpxProbe.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, httpxProbe)

	httpxInteresting := engine.NewJob(2, "httpx-interesting", "", nil)
	httpxInteresting.Description = "Extract interesting endpoints from httpx JSON"
	httpxInteresting.OutputFile = filepath.Join(ctx.ws.ScansHTTP, "interesting_hosts.txt")
	httpxInteresting.DependsOn = []string{httpxProbe.ID}
	httpxInteresting.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.httpxJSON) {
			markSkipped(j, "httpx results not available")
			return nil
		}
		records, err := parseHTTPXLines(ctx.httpxJSON)
		if err != nil {
			return err
		}
		interesting := make([]string, 0, len(records))
		for _, row := range records {
			if isInterestingHTTPX(row) {
				interesting = append(interesting, row.URL)
			}
		}
		sort.Strings(interesting)
		interesting = dedupSorted(interesting)
		return writeLines(j.OutputFile, interesting)
	}
	httpxInteresting.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, httpxInteresting)

	extractLive := engine.NewJob(2, "extract-live-hosts", "", nil)
	extractLive.Description = "Extract live host URLs from httpx output"
	extractLive.OutputFile = ctx.liveHosts
	extractLive.DependsOn = []string{httpxProbe.ID}
	extractLive.Execute = func(execCtx context.Context, j *engine.Job) error {
		if err := execCtx.Err(); err != nil {
			return err
		}
		if !fileExists(ctx.httpxJSON) {
			markSkipped(j, "httpx results not available")
			return nil
		}
		records, err := parseHTTPXLines(ctx.httpxJSON)
		if err != nil {
			return err
		}
		urls := make([]string, 0, len(records))
		for _, row := range records {
			if strings.TrimSpace(row.URL) != "" {
				urls = append(urls, row.URL)
			}
		}
		sort.Strings(urls)
		urls = dedupSorted(urls)
		return writeLines(j.OutputFile, urls)
	}
	extractLive.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, extractLive)

	extractIPs := engine.NewJob(2, "extract-ips", "", nil)
	extractIPs.Description = "Extract IPs from httpx output"
	extractIPs.OutputFile = filepath.Join(ctx.ws.ReconIPs, "http_ips.txt")
	extractIPs.DependsOn = []string{httpxProbe.ID}
	extractIPs.Execute = func(execCtx context.Context, j *engine.Job) error {
		if err := execCtx.Err(); err != nil {
			return err
		}
		if !fileExists(ctx.httpxJSON) {
			markSkipped(j, "httpx results not available")
			return nil
		}
		records, err := parseHTTPXLines(ctx.httpxJSON)
		if err != nil {
			return err
		}
		ips := make([]string, 0, len(records))
		for _, row := range records {
			if strings.TrimSpace(row.IP) != "" {
				ips = append(ips, row.IP)
			}
		}
		sort.Strings(ips)
		ips = dedupSorted(ips)
		if err := writeLines(j.OutputFile, ips); err != nil {
			return err
		}
		asnIPs := filepath.Join(ctx.ws.ReconIPs, "asn_ips.txt")
		if fileExists(asnIPs) {
			manager := engine.NewOutputManager(ctx.ws)
			_, _ = manager.MergeAndDedup([]string{asnIPs, j.OutputFile}, asnIPs)
		}
		return nil
	}
	extractIPs.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, extractIPs)

	return httpProbeOutput{Jobs: jobs, ProbeID: httpxProbe.ID, ExtractLiveID: extractLive.ID}
}

