package phase4

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/engine"
)

func buildParamDiscoveryJobs(ctx phase4Context, mergeURLsID string, arjunOutput string) []*engine.Job {
	jobs := make([]*engine.Job, 0, 4)
	paramspiderOut := filepath.Join(ctx.ws.ReconParams, "paramspider.txt")
	x8Out := filepath.Join(ctx.ws.ReconParams, "x8_results.txt")

	paramspider := engine.NewJob(4, "paramspider", "paramspider", nil)
	paramspider.ID = "phase4-paramspider"
	paramspider.Description = "Collect historical parameterized URLs for target"
	paramspider.OutputFile = paramspiderOut
	paramspider.Timeout = 20 * time.Minute
	paramspider.Execute = func(execCtx context.Context, j *engine.Job) error {
		if strings.TrimSpace(ctx.rootDomain) == "" {
			markSkipped(j, "target domain missing")
			return nil
		}
		return runCommand(execCtx, ctx.runCfg, "paramspider", []string{"-d", ctx.rootDomain, "-o", j.OutputFile})
	}
	paramspider.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, paramspider)

	x8 := engine.NewJob(4, "x8", "x8", nil)
	x8.ID = "phase4-x8-params"
	x8.Description = "Probe API-like endpoints for hidden parameters"
	x8.OutputFile = x8Out
	x8.DependsOn = []string{mergeURLsID}
	x8.Timeout = 25 * time.Minute
	x8.Execute = func(execCtx context.Context, j *engine.Job) error {
		apiList := filepath.Join(ctx.interestingDir, "api.txt")
		if !fileExists(apiList) || countFileLines(apiList) == 0 {
			targets := make([]string, 0, 64)
			for _, row := range readNonEmptyLines(ctx.urlsDeduped) {
				lower := strings.ToLower(row)
				if strings.Contains(lower, "/api") || strings.Contains(lower, "graphql") || strings.Contains(lower, "/v1/") || strings.Contains(lower, "/v2/") {
					targets = append(targets, row)
				}
			}
			sort.Strings(targets)
			targets = dedupSorted(targets)
			if err := writeLines(apiList, targets); err != nil {
				return err
			}
		}
		if !fileExists(apiList) || countFileLines(apiList) == 0 {
			markSkipped(j, "no API URL list for x8")
			return nil
		}
		if !fileExists(ctx.paramsWordlist) {
			markSkipped(j, "params wordlist missing")
			return nil
		}
		args := []string{"-u", apiList, "-w", ctx.paramsWordlist, "-o", j.OutputFile, "-t", fmt.Sprintf("%d", maxInt(10, ctx.threads))}
		return runCommand(execCtx, ctx.runCfg, "x8", args)
	}
	x8.ParseOutput = func(j *engine.Job) int { return countFileLines(j.OutputFile) }
	jobs = append(jobs, x8)

	merge := engine.NewJob(4, "merge-params", "", nil)
	merge.ID = "phase4-merge-params"
	merge.Description = "Combine parameter sources into consolidated URL and name lists"
	merge.OutputFile = ctx.allParams
	merge.DependsOn = []string{paramspider.ID, x8.ID, "phase4-arjun"}
	merge.Timeout = 8 * time.Minute
	merge.Execute = func(execCtx context.Context, j *engine.Job) error {
		paramURLs := make([]string, 0, 512)
		paramNames := make([]string, 0, 256)

		for _, row := range readNonEmptyLines(paramspiderOut) {
			if isLikelyURL(row) {
				paramURLs = append(paramURLs, row)
				paramNames = append(paramNames, parseURLQueryParamNames(row)...)
			}
		}
		for _, row := range readNonEmptyLines(x8Out) {
			if isLikelyURL(row) {
				paramURLs = append(paramURLs, row)
				paramNames = append(paramNames, parseURLQueryParamNames(row)...)
				continue
			}
			parts := strings.Fields(strings.NewReplacer(":", " ", "=", " ", ",", " ").Replace(strings.ToLower(row)))
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if len(part) >= 2 && len(part) <= 40 && strings.IndexFunc(part, func(r rune) bool { return !(r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) }) == -1 {
					paramNames = append(paramNames, part)
				}
			}
		}
		arjunURLs, arjunNames := parseArjunOutput(arjunOutput)
		paramURLs = append(paramURLs, arjunURLs...)
		paramNames = append(paramNames, arjunNames...)

		sort.Strings(paramURLs)
		paramURLs = dedupSorted(paramURLs)
		sort.Strings(paramNames)
		paramNames = dedupSorted(paramNames)

		if err := writeLines(ctx.allParams, paramURLs); err != nil {
			return err
		}
		return writeLines(ctx.paramNames, paramNames)
	}
	merge.ParseOutput = func(j *engine.Job) int { return countFileLines(ctx.paramNames) }
	jobs = append(jobs, merge)

	fuzz := engine.NewJob(4, "build-fuzz-urls", "", nil)
	fuzz.ID = "phase4-build-fuzz-urls"
	fuzz.Description = "Generate categorized FUZZ URL lists for phase 5 scans"
	fuzz.OutputFile = filepath.Join(ctx.ws.ReconURLs, "fuzz_xss.txt")
	fuzz.DependsOn = []string{merge.ID}
	fuzz.Timeout = 5 * time.Minute
	fuzz.Execute = func(execCtx context.Context, j *engine.Job) error {
		if !fileExists(ctx.allParams) || countFileLines(ctx.allParams) == 0 {
			markSkipped(j, "all_params list missing or empty")
			return nil
		}
		allURLs := readNonEmptyLines(ctx.allParams)
		xssList := make([]string, 0, len(allURLs))
		sqliList := make([]string, 0, len(allURLs))
		ssrfList := make([]string, 0, len(allURLs))
		lfiList := make([]string, 0, len(allURLs))

		for _, rawURL := range allURLs {
			parsed, err := url.Parse(rawURL)
			if err != nil {
				continue
			}
			query := parsed.Query()
			if len(query) == 0 {
				continue
			}
			for key := range query {
				copyURL := *parsed
				copyQuery := parsed.Query()
				copyQuery.Set(key, "FUZZ")
				copyURL.RawQuery = copyQuery.Encode()
				candidate := copyURL.String()
				lower := strings.ToLower(key)
				switch {
				case strings.Contains(lower, "url") || strings.Contains(lower, "uri") || strings.Contains(lower, "redirect") || strings.Contains(lower, "next") || strings.Contains(lower, "dest") || strings.Contains(lower, "callback"):
					ssrfList = append(ssrfList, candidate)
				case strings.Contains(lower, "file") || strings.Contains(lower, "path") || strings.Contains(lower, "page") || strings.Contains(lower, "template") || strings.Contains(lower, "doc"):
					lfiList = append(lfiList, candidate)
				case strings.Contains(lower, "id") || strings.Contains(lower, "query") || strings.Contains(lower, "search") || strings.Contains(lower, "where") || strings.Contains(lower, "sort"):
					sqliList = append(sqliList, candidate)
				default:
					xssList = append(xssList, candidate)
				}
			}
		}

		sort.Strings(xssList)
		sort.Strings(sqliList)
		sort.Strings(ssrfList)
		sort.Strings(lfiList)
		xssList = dedupSorted(xssList)
		sqliList = dedupSorted(sqliList)
		ssrfList = dedupSorted(ssrfList)
		lfiList = dedupSorted(lfiList)

		if err := writeLines(filepath.Join(ctx.ws.ReconURLs, "fuzz_xss.txt"), xssList); err != nil {
			return err
		}
		if err := writeLines(filepath.Join(ctx.ws.ReconURLs, "fuzz_sqli.txt"), sqliList); err != nil {
			return err
		}
		if err := writeLines(filepath.Join(ctx.ws.ReconURLs, "fuzz_ssrf.txt"), ssrfList); err != nil {
			return err
		}
		return writeLines(filepath.Join(ctx.ws.ReconURLs, "fuzz_lfi.txt"), lfiList)
	}
	fuzz.ParseOutput = func(j *engine.Job) int {
		return countFileLines(filepath.Join(ctx.ws.ReconURLs, "fuzz_xss.txt")) +
			countFileLines(filepath.Join(ctx.ws.ReconURLs, "fuzz_sqli.txt")) +
			countFileLines(filepath.Join(ctx.ws.ReconURLs, "fuzz_ssrf.txt")) +
			countFileLines(filepath.Join(ctx.ws.ReconURLs, "fuzz_lfi.txt"))
	}
	jobs = append(jobs, fuzz)

	return jobs
}

func parseArjunOutput(path string) ([]string, []string) {
	if !fileExists(path) {
		return []string{}, []string{}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{}, []string{}
	}

	urls := make([]string, 0, 128)
	names := make([]string, 0, 128)
	var objectMap map[string]any
	if err := json.Unmarshal(raw, &objectMap); err == nil {
		for key, value := range objectMap {
			if isLikelyURL(key) {
				urls = append(urls, key)
				names = append(names, parseURLQueryParamNames(key)...)
			}
			switch typed := value.(type) {
			case []any:
				for _, item := range typed {
					if s, ok := item.(string); ok {
						names = append(names, strings.ToLower(strings.TrimSpace(s)))
					}
				}
			case map[string]any:
				for nestedKey := range typed {
					names = append(names, strings.ToLower(strings.TrimSpace(nestedKey)))
				}
			}
		}
	}

	for _, row := range readNonEmptyLines(path) {
		if isLikelyURL(row) {
			urls = append(urls, row)
			names = append(names, parseURLQueryParamNames(row)...)
		}
	}

	sort.Strings(urls)
	urls = dedupSorted(urls)
	sort.Strings(names)
	names = dedupSorted(names)
	return urls, names
}
