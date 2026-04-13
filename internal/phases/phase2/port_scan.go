package phase2

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

func buildPortScanJobs(ctx phase2Context, extractLiveID string) portScanOutput {
	jobs := make([]*engine.Job, 0, 3)

	naabu := engine.NewJob(2, "naabu-quick", "naabu", nil)
	naabu.Description = "Top-port scan with naabu"
	naabu.OutputFile = filepath.Join(ctx.ws.ScansPorts, "naabu_top1000.txt")
	if strings.TrimSpace(extractLiveID) != "" {
		naabu.DependsOn = []string{extractLiveID}
	}
	naabu.Timeout = 10 * time.Minute
	naabu.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "no live hosts file available for naabu")
			return nil
		}
		args := []string{"-l", ctx.liveHosts, "-top-ports", "1000", "-silent", "-o", j.OutputFile}
		if ctx.rateLimit > 0 {
			args = append(args, "-rate", fmt.Sprintf("%d", ctx.rateLimit))
		}
		return runCommand(execCtx, "naabu", args)
	}
	naabu.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, naabu)

	nmap := engine.NewJob(2, "nmap-services", "nmap", nil)
	nmap.Description = "Service/version scan with nmap"
	nmap.OutputFile = filepath.Join(ctx.ws.ScansPorts, "nmap_services.txt")
	nmap.DependsOn = []string{naabu.ID}
	nmap.Timeout = 20 * time.Minute
	nmap.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(naabu.OutputFile) || countFileLines(naabu.OutputFile) == 0 {
			markSkipped(j, "no naabu output available for nmap")
			return nil
		}
		timing := "T3"
		if ctx.runCfg != nil && strings.TrimSpace(ctx.runCfg.Settings.NmapTiming) != "" {
			timing = strings.TrimSpace(ctx.runCfg.Settings.NmapTiming)
		}
		args := []string{"-sV", "-sC", "-" + timing, "-iL", naabu.OutputFile, "-oN", j.OutputFile}
		return runCommand(execCtx, "nmap", args)
	}
	nmap.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, nmap)

	rustscan := engine.NewJob(2, "rustscan", "rustscan", nil)
	rustscan.Description = "Aggressive full-port scan with rustscan on discovered live hosts"
	rustscan.OutputFile = filepath.Join(ctx.ws.ScansPorts, "rustscan.txt")
	if strings.TrimSpace(extractLiveID) != "" {
		rustscan.DependsOn = []string{extractLiveID}
	}
	rustscan.Timeout = 10 * time.Minute
	rustscan.Execute = func(execCtx context.Context, j *engine.Job) error {
		if ctx.runCfg == nil || ctx.runCfg.Profile != models.Aggressive {
			markSkipped(j, "rustscan enabled only for aggressive profile")
			return nil
		}
		if !fileExists(ctx.liveHosts) || countFileLines(ctx.liveHosts) == 0 {
			markSkipped(j, "no live hosts file available for rustscan")
			return nil
		}
		hosts := extractRustscanHosts(ctx.liveHosts)
		if len(hosts) == 0 {
			markSkipped(j, "no valid hosts parsed from live hosts for rustscan")
			return nil
		}
		combined := make([]string, 0, 2048)
		for _, host := range hosts {
			rows, err := collectCommandLines(execCtx, "rustscan", []string{"-a", host, "--ulimit", "5000", "-b", "1000", "--range", "1-65535"}, "")
			if err != nil {
				j.LogLine("[WARN] rustscan failed for host " + host + ": " + err.Error())
				continue
			}
			combined = append(combined, rows...)
		}
		if len(combined) == 0 {
			markSkipped(j, "rustscan produced no output for live hosts")
			return nil
		}
		sort.Strings(combined)
		combined = dedupSorted(combined)
		return writeLines(j.OutputFile, combined)
	}
	rustscan.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, rustscan)

	return portScanOutput{Jobs: jobs, NaabuID: naabu.ID}
}

