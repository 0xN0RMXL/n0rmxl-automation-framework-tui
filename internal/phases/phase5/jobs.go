package phase5

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/config"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/engine"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

type phase5Context struct {
	target        *models.Target
	ws            models.Workspace
	runCfg        *config.RunConfig
	domain        string
	rootDomain    string
	threads       int
	rateLimit     int
	nucleiRate    int
	liveHosts     string
	allSubsMerged string
	urlsDeduped   string
	httpxJSON     string
	fuzzXSS       string
	fuzzSQLI      string
	fuzzSSRF      string
	fuzzLFI       string
}

func Jobs(target *models.Target, ws models.Workspace, runCfg *config.RunConfig) []*engine.Job {
	if target == nil || strings.TrimSpace(target.Domain) == "" {
		return []*engine.Job{}
	}
	_ = os.MkdirAll(ws.ScansNuclei, 0o755)
	_ = os.MkdirAll(ws.ScansBurp, 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Vulns, "xss"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Vulns, "sqli"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Vulns, "ssrf"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Vulns, "cors"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Vulns, "takeover"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Vulns, "misc"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Vulns, "smuggling"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Vulns, "jwt"), 0o755)

	threads := 50
	rateLimit := 100
	nucleiRate := 50
	if runCfg != nil {
		if runCfg.Settings.Threads > 0 {
			threads = runCfg.Settings.Threads
		}
		if runCfg.Settings.RateLimit > 0 {
			rateLimit = runCfg.Settings.RateLimit
		}
		if runCfg.Settings.NucleiRate > 0 {
			nucleiRate = runCfg.Settings.NucleiRate
		}
	}

	ctx := phase5Context{
		target:        target,
		ws:            ws,
		runCfg:        runCfg,
		domain:        strings.TrimSpace(target.Domain),
		rootDomain:    rootDomain(strings.TrimSpace(target.Domain)),
		threads:       threads,
		rateLimit:     rateLimit,
		nucleiRate:    nucleiRate,
		liveHosts:     filepath.Join(ws.ScansHTTP, "live_hosts.txt"),
		allSubsMerged: filepath.Join(ws.ReconSubs, "all_subs_merged.txt"),
		urlsDeduped:   filepath.Join(ws.ReconURLs, "all_urls_deduped.txt"),
		httpxJSON:     filepath.Join(ws.ScansHTTP, "httpx_results.json"),
		fuzzXSS:       filepath.Join(ws.ReconURLs, "fuzz_xss.txt"),
		fuzzSQLI:      filepath.Join(ws.ReconURLs, "fuzz_sqli.txt"),
		fuzzSSRF:      filepath.Join(ws.ReconURLs, "fuzz_ssrf.txt"),
		fuzzLFI:       filepath.Join(ws.ReconURLs, "fuzz_lfi.txt"),
	}

	jobs := make([]*engine.Job, 0, 20)
	jobs = append(jobs, buildNucleiScanJobs(ctx)...)
	jobs = append(jobs, buildVulnSpecificJobs(ctx)...)
	jobs = append(jobs, buildBurpActiveJobs(ctx)...)
	return jobs
}

func runCommand(ctx context.Context, runCfg *config.RunConfig, binary string, args []string) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	applyProxyEnv(cmd, runCfg)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) > 0 {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
		}
		return err
	}
	return nil
}

func runStdoutToFile(ctx context.Context, runCfg *config.RunConfig, binary string, args []string, outputPath string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, binary, args...)
	applyProxyEnv(cmd, runCfg)
	cmd.Stdout = f
	cmd.Stderr = f
	return cmd.Run()
}

func runCommandWithInputFileToOutput(ctx context.Context, runCfg *config.RunConfig, binary string, args []string, inputPath string, outputPath string) error {
	in, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()
	cmd := exec.CommandContext(ctx, binary, args...)
	applyProxyEnv(cmd, runCfg)
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

func applyProxyEnv(cmd *exec.Cmd, runCfg *config.RunConfig) {
	if cmd == nil || runCfg == nil || !runCfg.UseBurp {
		return
	}
	proxy := "http://127.0.0.1:8080"
	cmd.Env = append(os.Environ(), "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy)
}

func markSkipped(job *engine.Job, reason string) {
	if job == nil {
		return
	}
	job.Status = engine.JobSkipped
	job.ErrorMsg = reason
	job.LogLine("[WARN] " + reason)
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
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

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if len(lines) == 0 {
		return os.WriteFile(path, []byte(""), 0o644)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

func dedupSorted(values []string) []string {
	if len(values) <= 1 {
		return values
	}
	out := values[:1]
	for i := 1; i < len(values); i++ {
		if values[i] != values[i-1] {
			out = append(out, values[i])
		}
	}
	return out
}

func rootDomain(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func hostFromAny(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if parsed, err := url.Parse(raw); err == nil {
			return strings.ToLower(strings.TrimSpace(parsed.Hostname()))
		}
	}
	if idx := strings.Index(raw, "/"); idx > 0 {
		raw = raw[:idx]
	}
	if idx := strings.Index(raw, ":"); idx > 0 {
		raw = raw[:idx]
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func sanitizeFileName(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		"?", "_",
		"*", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	return replacer.Replace(value)
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

func parseSeverity(raw string) models.Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return models.Critical
	case "high":
		return models.High
	case "medium":
		return models.Medium
	case "low":
		return models.Low
	default:
		return models.Info
	}
}

func saveFindings(workspace models.Workspace, findings []models.Finding) {
	if len(findings) == 0 {
		return
	}
	db, err := models.InitFindingsDB(workspace.Root)
	if err != nil {
		return
	}
	defer db.Close()
	_ = models.SaveFindingsBatch(db, findings)
}

func expandHome(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || !strings.HasPrefix(path, "~") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, strings.TrimPrefix(path, "~/"))
}

func selectPythonBinary() string {
	if _, err := exec.LookPath("python3"); err == nil {
		return "python3"
	}
	return "python"
}

func parseHTTPXProtectedURLs(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{}
	}
	rows := strings.Split(string(raw), "\n")
	urls := make([]string, 0, len(rows)/8)
	for _, row := range rows {
		row = strings.TrimSpace(row)
		if row == "" || !strings.HasPrefix(row, "{") {
			continue
		}
		var rec struct {
			URL        string `json:"url"`
			StatusCode int    `json:"status_code"`
		}
		if err := json.Unmarshal([]byte(row), &rec); err != nil {
			continue
		}
		if (rec.StatusCode == 401 || rec.StatusCode == 403) && strings.TrimSpace(rec.URL) != "" {
			urls = append(urls, rec.URL)
		}
	}
	sort.Strings(urls)
	return dedupSorted(urls)
}

func httpClientForRun(runCfg *config.RunConfig) *http.Client {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if runCfg != nil && runCfg.UseBurp {
		if proxyURL, err := url.Parse("http://127.0.0.1:8080"); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: transport}
}

