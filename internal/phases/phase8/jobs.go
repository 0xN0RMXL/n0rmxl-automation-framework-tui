package phase8

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

type phase8Context struct {
	target        *models.Target
	ws            models.Workspace
	runCfg        *config.RunConfig
	domain        string
	rootDomain    string
	threads       int
	rateLimit     int
	nucleiRate    int
	liveHosts     string
	urlsDeduped   string
	whatwebOutput string
	s3Candidates  string
}

func Jobs(target *models.Target, ws models.Workspace, runCfg *config.RunConfig) []*engine.Job {
	if target == nil || strings.TrimSpace(target.Domain) == "" {
		return []*engine.Job{}
	}
	_ = os.MkdirAll(filepath.Join(ws.Vulns, "cloud"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Scans, "mobile"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Scans, "thick_client"), 0o755)

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

	ctx := phase8Context{
		target:        target,
		ws:            ws,
		runCfg:        runCfg,
		domain:        strings.TrimSpace(target.Domain),
		rootDomain:    rootDomain(strings.TrimSpace(target.Domain)),
		threads:       threads,
		rateLimit:     rateLimit,
		nucleiRate:    nucleiRate,
		liveHosts:     filepath.Join(ws.ScansHTTP, "live_hosts.txt"),
		urlsDeduped:   filepath.Join(ws.ReconURLs, "all_urls_deduped.txt"),
		whatwebOutput: filepath.Join(ws.ScansTech, "whatweb.json"),
		s3Candidates:  filepath.Join(ws.ReconURLs, "potential_s3.txt"),
	}

	jobs := make([]*engine.Job, 0, 16)
	jobs = append(jobs, buildCloudJobs(ctx)...)
	jobs = append(jobs, buildMobileJobs(ctx)...)
	jobs = append(jobs, buildThickClientJobs(ctx)...)
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

func applyProxyEnv(cmd *exec.Cmd, runCfg *config.RunConfig) {
	if cmd == nil || runCfg == nil || !runCfg.UseBurp {
		return
	}
	proxy := "http://127.0.0.1:8080"
	cmd.Env = append(os.Environ(), "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy)
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
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

func countNonEmptyLines(path string) int {
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

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if len(lines) == 0 {
		return os.WriteFile(path, []byte(""), 0o644)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func writeText(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
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

func rootDomain(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
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

func markSkipped(job *engine.Job, reason string) {
	if job == nil {
		return
	}
	job.Status = engine.JobSkipped
	job.ErrorMsg = reason
	job.LogLine("[WARN] " + reason)
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

func httpClientForRun(runCfg *config.RunConfig) *http.Client {
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if runCfg != nil && runCfg.UseBurp {
		if proxyURL, err := url.Parse("http://127.0.0.1:8080"); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	return &http.Client{Timeout: 20 * time.Second, Transport: transport}
}

func sortUnique(lines []string) []string {
	sort.Strings(lines)
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

