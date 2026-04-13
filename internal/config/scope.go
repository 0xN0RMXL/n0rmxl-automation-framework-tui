package config

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Scope struct {
	Wildcards  []string `yaml:"wildcards"`
	Explicit   []string `yaml:"explicit"`
	IPRanges   []string `yaml:"ip_ranges"`
	OutOfScope []string `yaml:"out_of_scope"`
}

func (s *Scope) IsInScope(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}

	for _, excluded := range s.OutOfScope {
		if matchHost(host, excluded) {
			return false
		}
	}

	if ip := net.ParseIP(host); ip != nil {
		for _, cidr := range s.IPRanges {
			_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err == nil && network.Contains(ip) {
				return true
			}
		}
	}

	for _, explicit := range s.Explicit {
		if strings.EqualFold(host, normalizeHost(explicit)) {
			return true
		}
	}

	for _, wildcard := range s.Wildcards {
		if matchHost(host, wildcard) {
			return true
		}
	}

	return false
}

func (s *Scope) FilterFile(inputPath string, outputPath string) (int, error) {
	in, err := os.Open(inputPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open scope input file: %w", err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return 0, fmt.Errorf("failed to create output path: %w", err)
	}
	out, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("failed to create scope output file: %w", err)
	}
	defer out.Close()

	scanner := bufio.NewScanner(in)
	writer := bufio.NewWriter(out)
	count := 0
	seen := make(map[string]struct{})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		normalized := normalizeHost(line)
		if normalized == "" || !s.IsInScope(normalized) {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		if _, err := writer.WriteString(normalized + "\n"); err != nil {
			return count, fmt.Errorf("failed to write filtered line: %w", err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("failed reading scope input file: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return count, fmt.Errorf("failed to flush scope output file: %w", err)
	}
	return count, nil
}

func (s *Scope) ToHackerScopeFilter() string {
	parts := make([]string, 0, 4)
	if len(s.Wildcards) > 0 {
		parts = append(parts, "wildcards="+strings.Join(s.Wildcards, ","))
	}
	if len(s.Explicit) > 0 {
		parts = append(parts, "explicit="+strings.Join(s.Explicit, ","))
	}
	if len(s.IPRanges) > 0 {
		parts = append(parts, "cidr="+strings.Join(s.IPRanges, ","))
	}
	if len(s.OutOfScope) > 0 {
		parts = append(parts, "exclude="+strings.Join(s.OutOfScope, ","))
	}
	return strings.Join(parts, ";")
}

func (s *Scope) SaveToFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create scope file path: %w", err)
	}
	content, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("failed to serialize scope file: %w", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return fmt.Errorf("failed to write scope file: %w", err)
	}
	return nil
}

func (s *Scope) LoadFromFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read scope file: %w", err)
	}
	if err := yaml.Unmarshal(content, s); err != nil {
		return fmt.Errorf("failed to decode scope file: %w", err)
	}
	return nil
}

func matchHost(host string, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	host = strings.ToLower(strings.TrimSpace(host))
	if pattern == "" || host == "" {
		return false
	}
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		root := strings.TrimPrefix(pattern, "*.")
		if host == root {
			return true
		}
		return strings.HasSuffix(host, "."+root)
	}
	return false
}

func normalizeHost(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if strings.Contains(input, "://") {
		if parsed, err := url.Parse(input); err == nil {
			input = parsed.Hostname()
		}
	}
	input = strings.Split(input, "/")[0]
	input = strings.Split(input, ":")[0]
	input = strings.TrimPrefix(input, "*.")
	return strings.ToLower(strings.TrimSpace(input))
}
