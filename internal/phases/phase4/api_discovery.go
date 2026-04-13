package phase4

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
)

func buildAPIDiscoveryJobs(ctx phase4Context, mergeURLsID string) apiDiscoveryOutput {
	jobs := make([]*engine.Job, 0, 6)
	kiterunnerOut := filepath.Join(ctx.ws.ReconURLs, "kiterunner.txt")
	arjunOut := filepath.Join(ctx.ws.ReconParams, "arjun_results.json")
	graphqlOut := filepath.Join(ctx.ws.ScansTech, "graphql.txt")
	graphqlSchemaOut := filepath.Join(ctx.ws.ReconURLs, "graphql_schema.json")
	ffufDirsSummary := filepath.Join(ctx.ws.ScansFuzz, "dirs", "ffuf_dirs_summary.txt")
	ffufVhostsSummary := filepath.Join(ctx.ws.ScansFuzz, "vhosts", "ffuf_vhosts_summary.txt")

	kiterunner := engine.NewJob(4, "kiterunner", "kr", nil)
	kiterunner.ID = "phase4-kiterunner"
	kiterunner.Description = "Bruteforce API route paths on live hosts"
	kiterunner.OutputFile = kiterunnerOut
	kiterunner.Timeout = 25 * time.Minute
	kiterunner.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		if !fileExists(ctx.apiRoutesWordlist) {
			markSkipped(j, "API routes wordlist missing")
			return nil
		}
		args := []string{"scan", ctx.liveHosts, "-w", ctx.apiRoutesWordlist, "-o", j.OutputFile, "-j", "-x", fmt.Sprintf("%d", maxInt(10, ctx.threads))}
		return runCommand(execCtx, ctx.runCfg, "kr", args)
	}
	kiterunner.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, kiterunner)

	arjun := engine.NewJob(4, "arjun", "arjun", nil)
	arjun.ID = "phase4-arjun"
	arjun.Description = "Identify hidden HTTP parameters on API endpoints"
	arjun.OutputFile = arjunOut
	arjun.DependsOn = []string{mergeURLsID}
	arjun.Timeout = 25 * time.Minute
	arjun.Execute = func(execCtx context.Context, j *engine.Job) error {
		targetsFile := filepath.Join(ctx.ws.Hidden, "phase4_arjun_targets.txt")
		targets := readNonEmptyLines(filepath.Join(ctx.interestingDir, "api.txt"))
		if len(targets) == 0 {
			for _, row := range readNonEmptyLines(ctx.urlsDeduped) {
				lower := strings.ToLower(row)
				if strings.Contains(lower, "/api") || strings.Contains(lower, "graphql") || strings.Contains(lower, "/v1/") || strings.Contains(lower, "/v2/") {
					targets = append(targets, row)
				}
			}
		}
		sort.Strings(targets)
		targets = dedupSorted(targets)
		if len(targets) == 0 {
			markSkipped(j, "no API-like URLs for arjun")
			return nil
		}
		if err := writeLines(targetsFile, targets); err != nil {
			return err
		}
		args := []string{"-i", targetsFile, "-oJ", j.OutputFile, "-t", fmt.Sprintf("%d", maxInt(10, ctx.threads)), "--rate-limit", fmt.Sprintf("%d", maxInt(20, ctx.rateLimit))}
		return runCommand(execCtx, ctx.runCfg, "arjun", args)
	}
	arjun.ParseOutput = func(j *engine.Job) int {
		if fileExists(j.OutputFile) {
			return 1
		}
		return 0
	}
	jobs = append(jobs, arjun)

	graphql := engine.NewJob(4, "graphql", "graphw00f", nil)
	graphql.ID = "phase4-graphql-detect"
	graphql.Description = "Detect GraphQL services on in-scope hosts"
	graphql.OutputFile = graphqlOut
	graphql.Timeout = 12 * time.Minute
	graphql.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		if err := runCommand(execCtx, ctx.runCfg, "graphw00f", []string{"-f", ctx.liveHosts, "-o", j.OutputFile}); err != nil {
			return err
		}
		endpoints := make([]string, 0, 64)
		for _, row := range readNonEmptyLines(j.OutputFile) {
			if isLikelyURL(row) {
				endpoints = append(endpoints, row)
				continue
			}
			if strings.Contains(strings.ToLower(row), "graphql") {
				host := hostFromAny(row)
				if host != "" {
					endpoints = append(endpoints, "https://"+host+"/graphql")
				}
			}
		}
		sort.Strings(endpoints)
		endpoints = dedupSorted(endpoints)
		return writeJSON(graphqlSchemaOut, map[string]any{"endpoints": endpoints})
	}
	graphql.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, graphql)

	clairvoyance := engine.NewJob(4, "clairvoyance", selectPythonBinary(), nil)
	clairvoyance.ID = "phase4-clairvoyance"
	clairvoyance.Description = "Attempt GraphQL schema extraction from discovered endpoints"
	clairvoyance.OutputFile = filepath.Join(ctx.ws.ReconURLs, "graphql", "summary.txt")
	clairvoyance.DependsOn = []string{graphql.ID}
	clairvoyance.Timeout = 20 * time.Minute
	clairvoyance.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(graphqlSchemaOut) {
			markSkipped(j, "graphql schema seed file missing")
			return nil
		}
		script := expandHome("~/.local/share/n0rmxl/tools/clairvoyance/clairvoyance.py")
		useBinary := false
		if _, err := exec.LookPath("clairvoyance"); err == nil {
			useBinary = true
		} else if !fileExists(script) {
			markSkipped(j, "clairvoyance binary/script not found")
			return nil
		}
		var payload struct {
			Endpoints []string `json:"endpoints"`
		}
		raw, err := os.ReadFile(graphqlSchemaOut)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return err
		}
		if len(payload.Endpoints) == 0 {
			markSkipped(j, "no GraphQL endpoints found")
			return nil
		}
		outDir := filepath.Join(ctx.ws.ReconURLs, "graphql")
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
		summary := make([]string, 0, len(payload.Endpoints))
		for _, endpoint := range payload.Endpoints {
			host := hostFromAny(endpoint)
			if host == "" {
				continue
			}
			outFile := filepath.Join(outDir, sanitizeFileName(host)+".json")
			var err error
			if useBinary {
				err = runCommand(execCtx, ctx.runCfg, "clairvoyance", []string{"-u", endpoint, "-o", outFile})
			} else {
				err = runCommand(execCtx, ctx.runCfg, selectPythonBinary(), []string{script, "-u", endpoint, "-o", outFile})
			}
			if err == nil {
				summary = append(summary, fmt.Sprintf("%s -> %s", endpoint, outFile))
			}
		}
		return writeLines(j.OutputFile, summary)
	}
	clairvoyance.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, clairvoyance)

	ffufDirs := engine.NewJob(4, "ffuf-dirs", "ffuf", nil)
	ffufDirs.ID = "phase4-ffuf-dirs"
	ffufDirs.Description = "Discover hidden directories on interesting hosts"
	ffufDirs.OutputFile = ffufDirsSummary
	ffufDirs.Timeout = 35 * time.Minute
	ffufDirs.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.dirWordlist) {
			markSkipped(j, "directory wordlist missing")
			return nil
		}
		hostFile := filepath.Join(ctx.ws.ScansHTTP, "interesting_hosts.txt")
		if !fileExists(hostFile) {
			hostFile = ctx.liveHosts
		}
		if !fileExists(hostFile) {
			markSkipped(j, "no host file for ffuf dirs")
			return nil
		}
		hosts := readNonEmptyLines(hostFile)
		if len(hosts) == 0 {
			markSkipped(j, "host list is empty")
			return nil
		}
		limit := minInt(200, len(hosts))
		summary := make([]string, 0, limit)
		for _, host := range hosts[:limit] {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
				host = "https://" + host
			}
			outFile := filepath.Join(ctx.ws.ScansFuzz, "dirs", sanitizeFileName(host)+".json")
			args := []string{"-u", strings.TrimRight(host, "/") + "/FUZZ", "-w", ctx.dirWordlist, "-mc", "200,204,301,302,307,401,403", "-ac", "-t", fmt.Sprintf("%d", maxInt(10, ctx.threads)), "-rate", fmt.Sprintf("%d", maxInt(20, ctx.rateLimit)), "-of", "json", "-o", outFile, "-H", "User-Agent: N0RMXL/1.0"}
			if ctx.runCfg != nil && ctx.runCfg.UseBurp {
				args = append(args, "-replay-proxy", "http://127.0.0.1:8080")
			}
			if err := runCommand(execCtx, ctx.runCfg, "ffuf", args); err == nil {
				summary = append(summary, fmt.Sprintf("%s -> %s", host, outFile))
			}
		}
		return writeLines(j.OutputFile, summary)
	}
	ffufDirs.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, ffufDirs)

	ffufVhosts := engine.NewJob(4, "ffuf-vhosts", "ffuf", nil)
	ffufVhosts.ID = "phase4-ffuf-vhosts"
	ffufVhosts.Description = "Enumerate virtual hosts on in-scope IPs"
	ffufVhosts.OutputFile = ffufVhostsSummary
	ffufVhosts.Timeout = 30 * time.Minute
	ffufVhosts.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.vhostWordlist) {
			markSkipped(j, "vhost wordlist missing")
			return nil
		}
		ipFile := filepath.Join(ctx.ws.ReconIPs, "http_ips.txt")
		if !fileExists(ipFile) {
			ipFile = filepath.Join(ctx.ws.ReconIPs, "asn_ips.txt")
		}
		if !fileExists(ipFile) {
			markSkipped(j, "no IP input available for vhost discovery")
			return nil
		}
		ips := readNonEmptyLines(ipFile)
		if len(ips) == 0 {
			markSkipped(j, "IP list is empty")
			return nil
		}
		limit := minInt(80, len(ips))
		summary := make([]string, 0, limit)
		for _, ip := range ips[:limit] {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			outFile := filepath.Join(ctx.ws.ScansFuzz, "vhosts", sanitizeFileName(ip)+".json")
			args := []string{"-u", "http://" + ip + "/", "-H", "Host: FUZZ." + ctx.rootDomain, "-w", ctx.vhostWordlist, "-mc", "200,204,301,302,307,401,403", "-ac", "-t", fmt.Sprintf("%d", maxInt(10, ctx.threads)), "-rate", fmt.Sprintf("%d", maxInt(20, ctx.rateLimit)), "-of", "json", "-o", outFile}
			if err := runCommand(execCtx, ctx.runCfg, "ffuf", args); err == nil {
				summary = append(summary, fmt.Sprintf("%s -> %s", ip, outFile))
			}
		}
		return writeLines(j.OutputFile, summary)
	}
	ffufVhosts.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, ffufVhosts)

	return apiDiscoveryOutput{Jobs: jobs, ArjunOutput: arjunOut}
}

