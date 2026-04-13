package engine

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/n0rmxl/n0rmxl/internal/config"
	"github.com/n0rmxl/n0rmxl/internal/models"
)

type OutputManager struct {
	workspace models.Workspace
	mu        sync.Mutex
	seenLines map[string]map[string]struct{}
}

func NewOutputManager(workspace models.Workspace) *OutputManager {
	return &OutputManager{
		workspace: workspace,
		seenLines: make(map[string]map[string]struct{}),
	}
}

func (o *OutputManager) MergeAndDedup(inputs []string, output string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return 0, err
	}
	if shouldUseExternalSort(inputs) {
		if err := mergeAndDedupExternal(inputs, output); err == nil {
			return o.CountLines(output), nil
		}
	}
	seen := make(map[string]struct{}, 4096)
	for _, input := range inputs {
		if strings.TrimSpace(input) == "" {
			continue
		}
		if err := readLines(input, func(line string) {
			if line == "" {
				return
			}
			seen[line] = struct{}{}
		}); err != nil {
			return 0, err
		}
	}
	rows := make([]string, 0, len(seen))
	for line := range seen {
		rows = append(rows, line)
	}
	sort.Strings(rows)
	if err := writeLines(output, rows); err != nil {
		return 0, err
	}
	return len(rows), nil
}

func (o *OutputManager) AppendUnique(file string, line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	seen, err := o.loadSeenLines(file)
	if err != nil {
		return err
	}
	if _, exists := seen[line]; exists {
		return nil
	}
	f, err := openAppendFile(file)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		return err
	}
	o.mu.Lock()
	seen[line] = struct{}{}
	o.mu.Unlock()
	return nil
}

func (o *OutputManager) GFFilter(input string, pattern string, output string) error {
	if strings.TrimSpace(pattern) == "" {
		return fmt.Errorf("pattern is required")
	}
	if _, err := exec.LookPath("gf"); err != nil {
		return fmt.Errorf("gf is not installed or not in PATH")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return err
	}
	outFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer outFile.Close()

	cmd := exec.Command("gf", pattern)
	inFile, err := os.Open(input)
	if err != nil {
		return err
	}
	defer inFile.Close()
	cmd.Stdin = inFile
	cmd.Stdout = outFile
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gf filter failed: %w", err)
	}
	return nil
}

func (o *OutputManager) ScopeFilter(input string, output string, scope *config.Scope) (int, error) {
	if scope == nil {
		return 0, fmt.Errorf("scope is required")
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return 0, err
	}
	kept := make([]string, 0, 1024)
	err := readLines(input, func(line string) {
		host := hostFromAny(line)
		if host == "" {
			return
		}
		if scope.IsInScope(host) {
			kept = append(kept, line)
		}
	})
	if err != nil {
		return 0, err
	}
	sort.Strings(kept)
	kept = dedupSorted(kept)
	if err := writeLines(output, kept); err != nil {
		return 0, err
	}
	return len(kept), nil
}

func (o *OutputManager) CountLines(file string) int {
	count := 0
	_ = readLines(file, func(_ string) { count++ })
	return count
}

func (o *OutputManager) SplitByExtension(input string, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	groups := make(map[string][]string)
	err := readLines(input, func(line string) {
		u, parseErr := url.Parse(strings.TrimSpace(line))
		if parseErr != nil || u.Path == "" {
			groups["none"] = append(groups["none"], line)
			return
		}
		ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(u.Path)), ".")
		if ext == "" {
			ext = "none"
		}
		groups[ext] = append(groups[ext], line)
	})
	if err != nil {
		return err
	}
	for ext, lines := range groups {
		sort.Strings(lines)
		lines = dedupSorted(lines)
		outPath := filepath.Join(outputDir, ext+".txt")
		if err := writeLines(outPath, lines); err != nil {
			return err
		}
	}
	return nil
}

func (o *OutputManager) ExtractURLs(jsonFile string, output string) error {
	urls := make([]string, 0, 2048)
	err := readLines(jsonFile, func(line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			urls = append(urls, line)
			return
		}
		if !strings.HasPrefix(line, "{") {
			return
		}
		var row map[string]any
		if unmarshalErr := json.Unmarshal([]byte(line), &row); unmarshalErr != nil {
			return
		}
		for _, key := range []string{"url", "input", "host"} {
			if value, ok := row[key]; ok {
				raw := strings.TrimSpace(fmt.Sprint(value))
				if raw == "" {
					continue
				}
				if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
					raw = "https://" + raw
				}
				urls = append(urls, raw)
				break
			}
		}
	})
	if err != nil {
		return err
	}
	sort.Strings(urls)
	urls = dedupSorted(urls)
	return writeLines(output, urls)
}

func (o *OutputManager) MergeSubdomains(phase1Dir string) error {
	files, err := filepath.Glob(filepath.Join(phase1Dir, "*.txt"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return nil
	}
	output := filepath.Join(phase1Dir, "all_subs_merged.txt")
	_, err = o.MergeAndDedup(files, output)
	return err
}

func (o *OutputManager) MergeURLs() error {
	files, err := filepath.Glob(filepath.Join(o.workspace.ReconURLs, "*.txt"))
	if err != nil {
		return err
	}
	filtered := make([]string, 0, len(files))
	for _, file := range files {
		base := filepath.Base(file)
		if base == "all_urls_merged.txt" {
			continue
		}
		filtered = append(filtered, file)
	}
	if len(filtered) == 0 {
		return nil
	}
	_, err = o.MergeAndDedup(filtered, filepath.Join(o.workspace.ReconURLs, "all_urls_merged.txt"))
	return err
}

func (o *OutputManager) ExtractInterestingParams() error {
	input := filepath.Join(o.workspace.ReconURLs, "all_urls_merged.txt")
	if _, err := os.Stat(input); err != nil {
		return nil
	}
	interestingDir := filepath.Join(o.workspace.ReconURLs, "interesting")
	if err := os.MkdirAll(interestingDir, 0o755); err != nil {
		return err
	}
	buckets := map[string][]string{
		"xss.txt":        {},
		"sqli.txt":       {},
		"ssrf.txt":       {},
		"redirect.txt":   {},
		"debug.txt":      {},
		"sensitive.txt":  {},
		"all_params.txt": {},
	}

	keywords := map[string][]string{
		"xss.txt":       {"q", "search", "query", "keyword", "term", "message", "name"},
		"sqli.txt":      {"id", "uid", "item", "cat", "sort", "order", "where", "filter"},
		"ssrf.txt":      {"url", "uri", "dest", "destination", "feed", "image", "avatar", "proxy"},
		"redirect.txt":  {"next", "return", "redirect", "redir", "continue", "callback"},
		"debug.txt":     {"debug", "test", "admin", "trace", "env"},
		"sensitive.txt": {"token", "api", "key", "secret", "session", "auth", "password", "pass"},
	}

	err := readLines(input, func(line string) {
		u, parseErr := url.Parse(strings.TrimSpace(line))
		if parseErr != nil {
			return
		}
		query := u.Query()
		if len(query) == 0 {
			return
		}
		buckets["all_params.txt"] = append(buckets["all_params.txt"], line)
		for param := range query {
			name := strings.ToLower(param)
			for file, words := range keywords {
				if containsAny(name, words) {
					buckets[file] = append(buckets[file], line)
				}
			}
		}
	})
	if err != nil {
		return err
	}

	for name, lines := range buckets {
		sort.Strings(lines)
		lines = dedupSorted(lines)
		if err := writeLines(filepath.Join(interestingDir, name), lines); err != nil {
			return err
		}
	}
	return nil
}

func hostFromAny(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err == nil {
			return strings.ToLower(u.Hostname())
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

func readLines(path string, fn func(string)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fn(line)
	}
	return scanner.Err()
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := w.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
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

func containsAny(value string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(value, keyword) {
			return true
		}
	}
	return false
}

func shouldUseExternalSort(inputs []string) bool {
	const threshold = int64(100 * 1024 * 1024)
	if len(inputs) == 0 {
		return false
	}
	total := int64(0)
	for _, input := range inputs {
		info, err := os.Stat(strings.TrimSpace(input))
		if err != nil {
			continue
		}
		total += info.Size()
		if total >= threshold {
			break
		}
	}
	if total < threshold {
		return false
	}
	_, err := exec.LookPath("sort")
	return err == nil
}

func mergeAndDedupExternal(inputs []string, output string) error {
	args := []string{"-u"}
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		args = append(args, input)
	}
	if len(args) == 1 {
		return writeLines(output, []string{})
	}
	cmd := exec.Command("sort", args...)
	outFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer outFile.Close()
	cmd.Stdout = outFile
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (o *OutputManager) loadSeenLines(file string) (map[string]struct{}, error) {
	if o == nil {
		return nil, fmt.Errorf("output manager is nil")
	}
	file = strings.TrimSpace(file)
	if file == "" {
		return nil, fmt.Errorf("output file is empty")
	}
	o.mu.Lock()
	if seen, ok := o.seenLines[file]; ok {
		o.mu.Unlock()
		return seen, nil
	}
	o.mu.Unlock()

	seen := make(map[string]struct{}, 128)
	if _, err := os.Stat(file); err == nil {
		if err := readLines(file, func(existing string) {
			seen[existing] = struct{}{}
		}); err != nil {
			return nil, err
		}
	}

	o.mu.Lock()
	if cached, ok := o.seenLines[file]; ok {
		o.mu.Unlock()
		return cached, nil
	}
	o.seenLines[file] = seen
	o.mu.Unlock()
	return seen, nil
}
