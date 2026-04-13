package phase4

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
)

func buildURLDiscoveryJobs(ctx phase4Context) urlDiscoveryOutput {
	jobs := make([]*engine.Job, 0, 8)
	katanaOut := filepath.Join(ctx.ws.ReconURLs, "katana.txt")
	hakrawlerOut := filepath.Join(ctx.ws.ReconURLs, "hakrawler.txt")
	gauOut := filepath.Join(ctx.ws.ReconURLs, "gau.txt")
	gauplusOut := filepath.Join(ctx.ws.ReconURLs, "gauplus.txt")
	waybackOut := filepath.Join(ctx.ws.ReconURLs, "wayback.txt")

	katana := engine.NewJob(4, "katana", "katana", nil)
	katana.ID = "phase4-katana-crawl"
	katana.Description = "Crawl live hosts for endpoint discovery"
	katana.OutputFile = katanaOut
	katana.Timeout = 25 * time.Minute
	katana.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		args := []string{
			"-list", ctx.liveHosts,
			"-d", "5",
			"-jc",
			"-silent",
			"-c", fmt.Sprintf("%d", maxInt(10, ctx.threads)),
			"-rl", fmt.Sprintf("%d", maxInt(20, ctx.rateLimit)),
			"-o", j.OutputFile,
			"-H", "User-Agent: N0RMXL/1.0",
		}
		if ctx.runCfg != nil && ctx.runCfg.UseBurp {
			args = append(args, "-proxy", "http://127.0.0.1:8080")
		}
		return runCommand(execCtx, ctx.runCfg, "katana", args)
	}
	katana.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, katana)

	hakrawler := engine.NewJob(4, "hakrawler", "hakrawler", nil)
	hakrawler.ID = "phase4-hakrawler"
	hakrawler.Description = "Collect endpoint paths from host crawling"
	hakrawler.OutputFile = hakrawlerOut
	hakrawler.Timeout = 20 * time.Minute
	hakrawler.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.liveHosts) {
			markSkipped(j, "live hosts file missing")
			return nil
		}
		return runCommandWithInputFileToOutput(execCtx, ctx.runCfg, "hakrawler", []string{"-d", "3", "-u", "-s", "-timeout", "10"}, ctx.liveHosts, j.OutputFile)
	}
	hakrawler.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, hakrawler)

	gau := engine.NewJob(4, "gau", "gau", nil)
	gau.ID = "phase4-gau"
	gau.Description = "Fetch known URLs from archival sources"
	gau.OutputFile = gauOut
	gau.Timeout = 15 * time.Minute
	gau.Execute = func(execCtx context.Context, j *engine.Job) error {
		if strings.TrimSpace(ctx.rootDomain) == "" {
			markSkipped(j, "target domain not set")
			return nil
		}
		args := []string{"--subs", "--threads", fmt.Sprintf("%d", maxInt(10, ctx.threads)), "--blacklist", "png,jpg,jpeg,gif,svg,woff,woff2,ttf,ico", ctx.rootDomain}
		return runStdoutToFile(execCtx, ctx.runCfg, "gau", args, j.OutputFile)
	}
	gau.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, gau)

	gauplus := engine.NewJob(4, "gauplus", "gauplus", nil)
	gauplus.ID = "phase4-gauplus"
	gauplus.Description = "Fetch archival URLs with gauplus"
	gauplus.OutputFile = gauplusOut
	gauplus.Timeout = 15 * time.Minute
	gauplus.Execute = func(execCtx context.Context, j *engine.Job) error {
		if strings.TrimSpace(ctx.rootDomain) == "" {
			markSkipped(j, "target domain not set")
			return nil
		}
		return runCommandWithInputTextToOutput(execCtx, ctx.runCfg, "gauplus", []string{"-threads", fmt.Sprintf("%d", maxInt(10, ctx.threads)), "-random-agent"}, ctx.rootDomain+"\n", j.OutputFile)
	}
	gauplus.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, gauplus)

	wayback := engine.NewJob(4, "wayback", "", nil)
	wayback.ID = "phase4-wayback-urls"
	wayback.Description = "Collect historical URLs directly from Wayback CDX API"
	wayback.OutputFile = waybackOut
	wayback.Timeout = 10 * time.Minute
	wayback.Execute = func(execCtx context.Context, j *engine.Job) error {
		if strings.TrimSpace(ctx.rootDomain) == "" {
			markSkipped(j, "target domain not set")
			return nil
		}
		rows, err := fetchWaybackURLs(execCtx, ctx.rootDomain)
		if err != nil {
			markSkipped(j, "wayback request failed: "+err.Error())
			return nil
		}
		sort.Strings(rows)
		rows = dedupSorted(rows)
		return writeLines(j.OutputFile, rows)
	}
	wayback.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, wayback)

	merge := engine.NewJob(4, "merge-urls", "", nil)
	merge.ID = "phase4-merge-urls"
	merge.Description = "Merge URL sources and normalize to unique in-scope set"
	merge.OutputFile = ctx.urlsDeduped
	merge.DependsOn = []string{katana.ID, hakrawler.ID, gau.ID, gauplus.ID, wayback.ID}
	merge.Timeout = 8 * time.Minute
	merge.Execute = func(execCtx context.Context, j *engine.Job) error {
		mgr := engine.NewOutputManager(ctx.ws)
		inputs := make([]string, 0, 5)
		for _, candidate := range []string{katanaOut, hakrawlerOut, gauOut, gauplusOut, waybackOut} {
			if fileExists(candidate) {
				inputs = append(inputs, candidate)
			}
		}
		if len(inputs) == 0 {
			markSkipped(j, "no URL discovery outputs found")
			return nil
		}
		if _, err := mgr.MergeAndDedup(inputs, ctx.urlsMerged); err != nil {
			return err
		}
		if _, err := exec.LookPath("urldedupe"); err == nil {
			if err := runCommand(execCtx, ctx.runCfg, "urldedupe", []string{"-s", ctx.urlsMerged, "-o", ctx.urlsDeduped}); err == nil {
				return nil
			}
		}
		rows := readNonEmptyLines(ctx.urlsMerged)
		clean := make([]string, 0, len(rows))
		for _, row := range rows {
			parsed, err := url.Parse(strings.TrimSpace(row))
			if err != nil || parsed.Hostname() == "" {
				continue
			}
			host := strings.ToLower(parsed.Hostname())
			if ctx.rootDomain != "" && !strings.HasSuffix(host, ctx.rootDomain) {
				continue
			}
			clean = append(clean, parsed.String())
		}
		sort.Strings(clean)
		clean = dedupSorted(clean)
		return writeLines(ctx.urlsDeduped, clean)
	}
	merge.ParseOutput = func(j *engine.Job) int { return countFileLines(ctx.urlsDeduped) }
	jobs = append(jobs, merge)

	gf := engine.NewJob(4, "gf", "gf", nil)
	gf.ID = "phase4-gf-categorize"
	gf.Description = "Tag discovered URLs into sensitive categories"
	gf.OutputFile = ctx.interestingDir
	gf.DependsOn = []string{merge.ID}
	gf.Timeout = 6 * time.Minute
	gf.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.urlsDeduped) {
			markSkipped(j, "deduped URL list missing")
			return nil
		}
		if _, err := exec.LookPath("gf"); err != nil {
			markSkipped(j, "gf not found")
			return nil
		}
		mgr := engine.NewOutputManager(ctx.ws)
		patterns := []string{"xss", "sqli", "ssrf", "lfi", "rce", "idor", "redirect", "debug_logic", "api"}
		for _, pattern := range patterns {
			out := filepath.Join(ctx.interestingDir, pattern+".txt")
			if err := mgr.GFFilter(ctx.urlsDeduped, pattern, out); err != nil {
				j.LogLine(fmt.Sprintf("[WARN] gf pattern %s failed: %v", pattern, err))
			}
		}
		return ensureInterestingAPIFile(ctx)
	}
	gf.ParseOutput = func(j *engine.Job) int {
		files, _ := filepath.Glob(filepath.Join(ctx.interestingDir, "*.txt"))
		total := 0
		for _, f := range files {
			total += countFileLines(f)
		}
		return total
	}
	jobs = append(jobs, gf)

	return urlDiscoveryOutput{Jobs: jobs, MergeURLsID: merge.ID, GFCategorize: gf.ID}
}

func fetchWaybackURLs(ctx context.Context, domain string) ([]string, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return []string{}, nil
	}
	endpoint := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("wayback API returned %s", resp.Status)
	}
	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, err
	}
	urls := make([]string, 0, len(rows))
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue
		}
		u := strings.TrimSpace(row[0])
		if isLikelyURL(u) {
			urls = append(urls, u)
		}
	}
	return urls, nil
}

func ensureInterestingAPIFile(ctx phase4Context) error {
	apiFile := filepath.Join(ctx.interestingDir, "api.txt")
	if fileExists(apiFile) && countFileLines(apiFile) > 0 {
		return nil
	}
	if !fileExists(ctx.urlsDeduped) {
		return nil
	}
	rows := readNonEmptyLines(ctx.urlsDeduped)
	apiRows := make([]string, 0, len(rows)/3)
	for _, row := range rows {
		lower := strings.ToLower(row)
		if strings.Contains(lower, "/api") || strings.Contains(lower, "graphql") || strings.Contains(lower, "/v1/") || strings.Contains(lower, "/v2/") || strings.Contains(lower, "/rest/") {
			apiRows = append(apiRows, row)
		}
	}
	sort.Strings(apiRows)
	apiRows = dedupSorted(apiRows)
	return writeLines(apiFile, apiRows)
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
