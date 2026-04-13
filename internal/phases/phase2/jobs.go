package phase2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/n0rmxl/n0rmxl/internal/config"
	"github.com/n0rmxl/n0rmxl/internal/engine"
	"github.com/n0rmxl/n0rmxl/internal/models"
)

type phase2Context struct {
	target           *models.Target
	ws               models.Workspace
	runCfg           *config.RunConfig
	domain           string
	wordlist         string
	resolvers        string
	trustedResolvers string
	threads          int
	rateLimit        int
	phase1Merged     string
	phase2Merged     string
	liveHosts        string
	httpxJSON        string
}

type dnsBruteOutput struct {
	Jobs       []*engine.Job
	MergeJobID string
}

type httpProbeOutput struct {
	Jobs          []*engine.Job
	ProbeID       string
	ExtractLiveID string
}

type portScanOutput struct {
	Jobs    []*engine.Job
	NaabuID string
}

func Jobs(target *models.Target, ws models.Workspace, runCfg *config.RunConfig) []*engine.Job {
	if target == nil || strings.TrimSpace(target.Domain) == "" {
		return []*engine.Job{}
	}
	domain := strings.TrimSpace(target.Domain)
	_ = os.MkdirAll(ws.ReconSubs, 0o755)
	_ = os.MkdirAll(ws.ScansHTTP, 0o755)
	_ = os.MkdirAll(ws.ScansPorts, 0o755)
	_ = os.MkdirAll(ws.ScansTech, 0o755)
	_ = os.MkdirAll(ws.Screenshots, 0o755)

	defaults := config.DefaultConfig()
	wordlist := selectDNSWordlist(runCfg, defaults.Wordlists)
	resolvers := strings.TrimSpace(defaults.Wordlists.Resolvers)
	ctx := phase2Context{
		target:           target,
		ws:               ws,
		runCfg:           runCfg,
		domain:           domain,
		wordlist:         wordlist,
		resolvers:        resolvers,
		trustedResolvers: resolvers,
		threads:          phase2Threads(runCfg),
		rateLimit:        phase2RateLimit(runCfg),
		phase1Merged:     filepath.Join(ws.ReconSubs, "all_subs_merged.txt"),
		phase2Merged:     filepath.Join(ws.ReconSubs, "final_subs.txt"),
		liveHosts:        filepath.Join(ws.ScansHTTP, "live_hosts.txt"),
		httpxJSON:        filepath.Join(ws.ScansHTTP, "httpx_results.json"),
	}

	dnsOut := buildDNSBruteJobs(ctx)
	httpOut := buildHTTPProbeJobs(ctx, dnsOut.MergeJobID)
	portOut := buildPortScanJobs(ctx, httpOut.ExtractLiveID)
	screenshotJobs := buildScreenshotJobs(ctx, httpOut.ExtractLiveID, portOut.NaabuID)
	gowitnessID := ""
	if len(screenshotJobs) > 0 && screenshotJobs[0] != nil {
		gowitnessID = screenshotJobs[0].ID
	}
	coverageJobs := buildCoverageJobs(ctx, httpOut.ProbeID, httpOut.ExtractLiveID, portOut.NaabuID, gowitnessID)

	jobs := make([]*engine.Job, 0, 24)
	jobs = append(jobs, dnsOut.Jobs...)
	jobs = append(jobs, httpOut.Jobs...)
	jobs = append(jobs, portOut.Jobs...)
	jobs = append(jobs, screenshotJobs...)
	jobs = append(jobs, coverageJobs...)
	return jobs
}

type httpxRecord struct {
	URL        string `json:"url"`
	Host       string `json:"host"`
	IP         string `json:"ip"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"title"`
}

func parseHTTPXLines(path string) ([]httpxRecord, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rows := strings.Split(string(raw), "\n")
	parsed := make([]httpxRecord, 0, len(rows))
	for _, line := range rows {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var record httpxRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if strings.TrimSpace(record.URL) == "" {
			continue
		}
		parsed = append(parsed, record)
	}
	return parsed, nil
}

func isInterestingHTTPX(row httpxRecord) bool {
	if strings.TrimSpace(row.URL) == "" {
		return false
	}
	title := strings.ToLower(strings.TrimSpace(row.Title))
	u := strings.ToLower(strings.TrimSpace(row.URL))
	if row.StatusCode == 401 || row.StatusCode == 403 {
		return true
	}
	if row.StatusCode == 200 {
		for _, needle := range []string{"/admin", "/api", "/graphql", "/swagger", "/.git", "/debug"} {
			if strings.Contains(u, needle) {
				return true
			}
		}
		for _, needle := range []string{"admin", "dashboard", "internal", "jenkins", "phpmyadmin"} {
			if strings.Contains(title, needle) {
				return true
			}
		}
	}
	return false
}

func selectDNSWordlist(runCfg *config.RunConfig, words config.Wordlists) string {
	if runCfg == nil {
		return strings.TrimSpace(words.DNSMedium)
	}
	switch runCfg.Profile {
	case models.Slow:
		return strings.TrimSpace(words.DNSLarge)
	case models.Aggressive:
		return strings.TrimSpace(words.DNSSmall)
	default:
		return strings.TrimSpace(words.DNSMedium)
	}
}

func phase2Threads(runCfg *config.RunConfig) int {
	if runCfg != nil && runCfg.Settings.Threads > 0 {
		return runCfg.Settings.Threads
	}
	return 50
}

func phase2RateLimit(runCfg *config.RunConfig) int {
	if runCfg != nil && runCfg.Settings.RateLimit > 0 {
		return runCfg.Settings.RateLimit
	}
	return 100
}

func runCommand(ctx context.Context, binary string, args []string) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil && len(output) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return err
}

func collectCommandLines(ctx context.Context, binary string, args []string, stdinText string) ([]string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	if strings.TrimSpace(stdinText) != "" {
		cmd.Stdin = strings.NewReader(stdinText)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) > 0 {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil, err
	}
	rows := make([]string, 0, 128)
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			rows = append(rows, line)
		}
	}
	return rows, nil
}

func runStdoutToFile(ctx context.Context, binary string, args []string, outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = f
	cmd.Stderr = f
	return cmd.Run()
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func existingFiles(paths []string) []string {
	filtered := make([]string, 0, len(paths))
	for _, p := range paths {
		if fileExists(p) {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func pickExisting(paths ...string) string {
	for _, path := range paths {
		if fileExists(path) {
			return path
		}
	}
	return ""
}

func markSkipped(job *engine.Job, reason string) {
	if job == nil {
		return
	}
	job.Status = engine.JobSkipped
	job.ErrorMsg = reason
	job.LogLine("[WARN] " + reason)
}

func countFileLines(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func countFiles(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	total := 0
	for _, entry := range entries {
		if entry.IsDir() {
			total += countFiles(filepath.Join(dir, entry.Name()))
			continue
		}
		total++
	}
	return total
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func dedupSorted(lines []string) []string {
	if len(lines) <= 1 {
		return lines
	}
	out := lines[:1]
	for i := 1; i < len(lines); i++ {
		if lines[i] != lines[i-1] {
			out = append(out, lines[i])
		}
	}
	return out
}

func readNonEmptyLines(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{}
	}
	rows := strings.Split(string(raw), "\n")
	clean := make([]string, 0, len(rows))
	for _, row := range rows {
		row = strings.TrimSpace(row)
		if row != "" {
			clean = append(clean, row)
		}
	}
	return clean
}

func extractRustscanHosts(liveHostsPath string) []string {
	rows := readNonEmptyLines(liveHostsPath)
	hosts := make([]string, 0, len(rows))
	for _, row := range rows {
		host := hostFromCandidate(row)
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return dedupSorted(hosts)
}

func hostFromCandidate(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			return strings.TrimSpace(parsed.Hostname())
		}
	}
	if idx := strings.Index(value, "/"); idx > -1 {
		value = value[:idx]
	}
	if idx := strings.Index(value, ":"); idx > -1 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

func expandHome(input string) string {
	input = strings.TrimSpace(input)
	if input == "" || !strings.HasPrefix(input, "~") {
		return input
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return input
	}
	if input == "~" {
		return home
	}
	return filepath.Join(home, strings.TrimPrefix(input, "~/"))
}

func basePath(urlStr string) string {
	urlStr = strings.TrimSpace(urlStr)
	if urlStr == "" {
		return ""
	}
	if idx := strings.Index(urlStr, "?"); idx >= 0 {
		urlStr = urlStr[:idx]
	}
	return strings.ToLower(path.Clean(urlStr))
}
