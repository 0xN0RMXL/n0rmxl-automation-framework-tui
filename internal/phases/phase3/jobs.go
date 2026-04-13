package phase3

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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

type phase3Context struct {
	target        *models.Target
	ws            models.Workspace
	runCfg        *config.RunConfig
	domain        string
	threads       int
	rateLimit     int
	nucleiRate    int
	liveHosts     string
	httpxJSON     string
	allSubsMerged string
	naabuTop      string
}

func Jobs(target *models.Target, ws models.Workspace, runCfg *config.RunConfig) []*engine.Job {
	if target == nil || strings.TrimSpace(target.Domain) == "" {
		return []*engine.Job{}
	}
	_ = os.MkdirAll(ws.ScansTech, 0o755)
	_ = os.MkdirAll(ws.ScansNuclei, 0o755)
	_ = os.MkdirAll(filepath.Join(ws.ScansPorts, "nmap"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Vulns, "takeover"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Vulns, "misc"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Vulns, "cloud"), 0o755)
	_ = os.MkdirAll(filepath.Join(ws.Loot, "git_dumps"), 0o755)

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

	ctx := phase3Context{
		target:        target,
		ws:            ws,
		runCfg:        runCfg,
		domain:        strings.TrimSpace(target.Domain),
		threads:       threads,
		rateLimit:     rateLimit,
		nucleiRate:    nucleiRate,
		liveHosts:     filepath.Join(ws.ScansHTTP, "live_hosts.txt"),
		httpxJSON:     filepath.Join(ws.ScansHTTP, "httpx_results.json"),
		allSubsMerged: filepath.Join(ws.ReconSubs, "all_subs_merged.txt"),
		naabuTop:      filepath.Join(ws.ScansPorts, "naabu_top1000.txt"),
	}

	jobs := make([]*engine.Job, 0, 16)
	jobs = append(jobs, buildFingerprintJobs(ctx)...)
	jobs = append(jobs, buildServiceAnalysisJobs(ctx)...)
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

func rootDomain(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func parseHTTPXURLs(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return []string{}
	}
	rows := strings.Split(string(raw), "\n")
	urls := make([]string, 0, len(rows))
	for _, row := range rows {
		row = strings.TrimSpace(row)
		if row == "" || !strings.HasPrefix(row, "{") {
			continue
		}
		var record struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(row), &record); err != nil {
			continue
		}
		if strings.TrimSpace(record.URL) != "" {
			urls = append(urls, record.URL)
		}
	}
	sort.Strings(urls)
	return dedupSorted(urls)
}

func parseWhatwebUniqueTech(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	unique := make(map[string]struct{})

	consume := func(row map[string]any) {
		pluginsRaw, ok := row["plugins"]
		if !ok {
			return
		}
		plugins, ok := pluginsRaw.(map[string]any)
		if !ok {
			return
		}
		for name := range plugins {
			unique[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
		}
	}

	var asArray []map[string]any
	if err := json.Unmarshal(raw, &asArray); err == nil {
		for _, row := range asArray {
			consume(row)
		}
		return len(unique)
	}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		consume(row)
	}
	return len(unique)
}

func parseNaabuHostPorts(path string) map[string][]string {
	rows := readNonEmptyLines(path)
	hostPorts := make(map[string]map[string]struct{})
	for _, row := range rows {
		host, port := extractHostPortFromNaabuLine(row)
		if host == "" || port == "" {
			continue
		}
		if _, ok := hostPorts[host]; !ok {
			hostPorts[host] = make(map[string]struct{})
		}
		hostPorts[host][port] = struct{}{}
	}

	out := make(map[string][]string, len(hostPorts))
	for host, ports := range hostPorts {
		list := make([]string, 0, len(ports))
		for port := range ports {
			list = append(list, port)
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i] < list[j]
		})
		out[host] = list
	}
	return out
}

func extractHostPortFromNaabuLine(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ""
	}
	if strings.Contains(line, "://") {
		parsed, err := url.Parse(line)
		if err == nil {
			host := strings.TrimSpace(parsed.Hostname())
			port := parsed.Port()
			return host, port
		}
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		host := strings.TrimSpace(fields[0])
		port := strings.TrimSpace(fields[1])
		if net.ParseIP(host) != nil || strings.Contains(host, ".") {
			return host, strings.TrimPrefix(port, ":")
		}
	}
	idx := strings.LastIndex(line, ":")
	if idx > 0 {
		host := strings.TrimSpace(line[:idx])
		port := strings.TrimSpace(line[idx+1:])
		if host != "" && port != "" {
			return host, port
		}
	}
	return "", ""
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

