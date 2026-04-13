package burp

import (
	"fmt"
	"strings"

	"github.com/n0rmxl/n0rmxl/internal/models"
)

type Scanner struct {
	client *BurpClient
}

func NewScanner(client *BurpClient) *Scanner {
	return &Scanner{client: client}
}

func (s *Scanner) ActiveScanURLs(target string, urls []string, progress chan<- float64) ([]models.Finding, error) {
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("burp scanner is not configured")
	}
	target = strings.TrimSpace(target)
	scopeURLs := make([]string, 0, len(urls))
	for _, candidate := range urls {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" {
			scopeURLs = append(scopeURLs, candidate)
		}
	}
	if len(scopeURLs) == 0 {
		return []models.Finding{}, nil
	}

	cfg := BurpScanConfig{
		Scope: BurpScope{Include: scopeURLs},
		ScanConfigurations: []BurpNamedConfig{
			{Name: "Crawl and Audit - Balanced"},
		},
	}
	taskID, err := s.client.StartScan(cfg)
	if err != nil {
		return nil, err
	}
	if err := s.client.PollUntilDone(taskID, progress); err != nil {
		return nil, err
	}
	issues, err := s.client.GetIssues(taskID)
	if err != nil {
		return nil, err
	}
	return s.client.IssuesToFindings(issues, target), nil
}
