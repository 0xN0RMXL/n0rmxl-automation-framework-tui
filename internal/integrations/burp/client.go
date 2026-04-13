package burp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/n0rmxl/n0rmxl/internal/models"
)

type BurpClient struct {
	APIURL string
	APIKey string
	client *http.Client
}

type BurpVersion struct {
	APIVersion string `json:"api_version"`
	Edition    string `json:"edition"`
	Version    string `json:"version"`
}

type BurpScope struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

type BurpNamedConfig struct {
	Name string `json:"name"`
}

type BurpCredential struct {
	Label    string `json:"label,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type BurpScanConfig struct {
	Scope              BurpScope         `json:"scope"`
	ScanConfigurations []BurpNamedConfig `json:"scan_configurations,omitempty"`
	ResourcePool       *string           `json:"resource_pool,omitempty"`
	Credentials        []BurpCredential  `json:"application_logins,omitempty"`
}

type BurpScanStatus struct {
	TaskID     string          `json:"task_id"`
	ScanStatus string          `json:"scan_status"`
	Metrics    BurpScanMetrics `json:"scan_metrics"`
	Error      string          `json:"error,omitempty"`
}

type BurpScanMetrics struct {
	TotalElapsedRequests int `json:"total_elapsed_requests"`
	MaxRequests          int `json:"max_requests"`
}

type BurpIssue struct {
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	Severity        string            `json:"severity"`
	Confidence      string            `json:"confidence"`
	Path            string            `json:"path"`
	URL             string            `json:"url"`
	Host            string            `json:"host"`
	Detail          string            `json:"issue_detail"`
	Description     string            `json:"description"`
	Remediation     string            `json:"remediation"`
	RequestResponse []BurpHTTPMessage `json:"request_response"`
}

type BurpHTTPMessage struct {
	Request  string `json:"request"`
	Response string `json:"response"`
}

type BurpSitemapEntry struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Method     string `json:"method"`
	MIMEType   string `json:"mime_type"`
}

func NewBurpClient(apiURL string, apiKey string) *BurpClient {
	apiURL = strings.TrimSpace(apiURL)
	if apiURL == "" {
		apiURL = "http://127.0.0.1:1337"
	}
	apiURL = strings.TrimRight(apiURL, "/")
	return &BurpClient{
		APIURL: apiURL,
		APIKey: strings.TrimSpace(apiKey),
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (b *BurpClient) Ping() (*BurpVersion, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out BurpVersion
	if err := b.doJSON(ctx, http.MethodGet, "/v0.1/", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (b *BurpClient) StartScan(cfg BurpScanConfig) (string, error) {
	raw, err := b.doRaw(context.Background(), http.MethodPost, "/v0.1/scan", cfg)
	if err != nil {
		return "", err
	}
	var taskResp struct {
		TaskID string `json:"task_id"`
		ID     string `json:"id"`
		ScanID string `json:"scan_id"`
	}
	if err := json.Unmarshal(raw, &taskResp); err == nil {
		if taskID := firstNonEmpty(taskResp.TaskID, taskResp.ID, taskResp.ScanID); taskID != "" {
			return taskID, nil
		}
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err == nil {
		for _, key := range []string{"task_id", "id", "scan_id"} {
			if v, ok := generic[key]; ok {
				if s := strings.TrimSpace(fmt.Sprint(v)); s != "" {
					return s, nil
				}
			}
		}
	}
	return "", fmt.Errorf("burp start scan response did not include task id")
}

func (b *BurpClient) GetScan(taskID string) (*BurpScanStatus, error) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, fmt.Errorf("task id is required")
	}
	var out BurpScanStatus
	if err := b.doJSON(context.Background(), http.MethodGet, path.Join("/v0.1/scan", taskID), nil, &out); err != nil {
		return nil, err
	}
	if out.TaskID == "" {
		out.TaskID = taskID
	}
	return &out, nil
}

func (b *BurpClient) GetIssues(taskID string) ([]BurpIssue, error) {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return nil, fmt.Errorf("task id is required")
	}
	raw, err := b.doRaw(context.Background(), http.MethodGet, path.Join("/v0.1/scan", taskID, "issues"), nil)
	if err != nil {
		return nil, err
	}
	issues := make([]BurpIssue, 0)
	if err := json.Unmarshal(raw, &issues); err == nil {
		return issues, nil
	}
	var wrapped struct {
		Issues []BurpIssue `json:"issues"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil {
		return wrapped.Issues, nil
	}
	return issues, nil
}

func (b *BurpClient) GetSitemap() ([]BurpSitemapEntry, error) {
	raw, err := b.doRaw(context.Background(), http.MethodGet, "/v0.1/target/sitemap", nil)
	if err != nil {
		return nil, err
	}
	entries := make([]BurpSitemapEntry, 0)
	if err := json.Unmarshal(raw, &entries); err == nil {
		return entries, nil
	}
	var wrapped struct {
		Items []BurpSitemapEntry `json:"items"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil {
		return wrapped.Items, nil
	}
	return entries, nil
}

func (b *BurpClient) SetScope(scope BurpScope) error {
	return b.doJSON(context.Background(), http.MethodPut, "/v0.1/target/scope", scope, nil)
}

func (b *BurpClient) PollUntilDone(taskID string, progress chan<- float64) error {
	taskID = strings.TrimSpace(taskID)
	if taskID == "" {
		return fmt.Errorf("task id is required")
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		scan, err := b.GetScan(taskID)
		if err != nil {
			return err
		}
		if progress != nil {
			select {
			case progress <- scan.Metrics.progress():
			default:
			}
		}
		status := strings.ToLower(strings.TrimSpace(scan.ScanStatus))
		switch status {
		case "succeeded", "completed", "finished":
			if progress != nil {
				select {
				case progress <- 1.0:
				default:
				}
			}
			return nil
		case "failed", "cancelled", "canceled", "error":
			if scan.Error != "" {
				return fmt.Errorf("burp scan failed: %s", scan.Error)
			}
			return fmt.Errorf("burp scan status: %s", scan.ScanStatus)
		}
		<-ticker.C
	}
}

func (b *BurpClient) IssuesToFindings(issues []BurpIssue, target string) []models.Finding {
	out := make([]models.Finding, 0, len(issues))
	now := time.Now().UTC()
	for idx, issue := range issues {
		issueURL := firstNonEmpty(issue.URL, issue.Path)
		host := firstNonEmpty(issue.Host, hostFromURL(issueURL), target)
		severity := mapSeverity(issue.Severity)
		finding := models.Finding{
			ID:          fmt.Sprintf("burp-%d", idx+1),
			Phase:       5,
			VulnClass:   mapIssueClass(issue),
			Target:      target,
			Host:        host,
			URL:         issueURL,
			Severity:    severity,
			Title:       firstNonEmpty(issue.Name, issue.Type, "Burp Issue"),
			Description: firstNonEmpty(issue.Detail, issue.Description),
			Evidence:    buildEvidence(issue.RequestResponse),
			Tool:        "burp-active-scan",
			Timestamp:   now,
			Remediation: issue.Remediation,
			Confirmed:   strings.EqualFold(issue.Confidence, "certain") || strings.EqualFold(issue.Confidence, "firm"),
			CVSS:        defaultCVSSForSeverity(severity),
		}
		out = append(out, finding)
	}
	return out
}

func (b *BurpClient) doJSON(ctx context.Context, method string, endpoint string, payload any, out any) error {
	raw, err := b.doRaw(ctx, method, endpoint, payload)
	if err != nil {
		return err
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("failed to decode burp response: %w", err)
	}
	return nil
}

func (b *BurpClient) doRaw(ctx context.Context, method string, endpoint string, payload any) ([]byte, error) {
	if b == nil {
		return nil, fmt.Errorf("burp client is nil")
	}
	apiURL := strings.TrimRight(strings.TrimSpace(b.APIURL), "/")
	if apiURL == "" {
		return nil, fmt.Errorf("burp api url is empty")
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to encode request payload: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	req, err := http.NewRequestWithContext(ctx, method, apiURL+endpoint, body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(b.APIKey) != "" {
		req.Header.Set("Authorization", b.APIKey)
		req.Header.Set("X-API-Key", b.APIKey)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if readErr != nil {
		return nil, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := strings.TrimSpace(string(raw))
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("burp api %s %s failed: %s", method, endpoint, msg)
	}
	return raw, nil
}

func (m BurpScanMetrics) progress() float64 {
	if m.MaxRequests <= 0 || m.TotalElapsedRequests <= 0 {
		return 0
	}
	p := float64(m.TotalElapsedRequests) / float64(m.MaxRequests)
	if p < 0 {
		return 0
	}
	if p > 1 {
		return 1
	}
	return p
}

func mapSeverity(raw string) models.Severity {
	raw = strings.ToLower(strings.TrimSpace(raw))
	switch raw {
	case "critical":
		return models.Critical
	case "high":
		return models.High
	case "medium", "moderate":
		return models.Medium
	case "low":
		return models.Low
	default:
		return models.Info
	}
}

func mapIssueClass(issue BurpIssue) string {
	needle := strings.ToLower(firstNonEmpty(issue.Name, issue.Type))
	switch {
	case strings.Contains(needle, "sql"):
		return "sqli"
	case strings.Contains(needle, "cross-site scripting") || strings.Contains(needle, "xss"):
		return "xss"
	case strings.Contains(needle, "request forgery") || strings.Contains(needle, "ssrf"):
		return "ssrf"
	case strings.Contains(needle, "directory traversal") || strings.Contains(needle, "file path"):
		return "lfi"
	case strings.Contains(needle, "access control") || strings.Contains(needle, "idor"):
		return "idor"
	case strings.Contains(needle, "jwt") || strings.Contains(needle, "json web token"):
		return "jwt"
	case strings.Contains(needle, "cors"):
		return "cors"
	default:
		if needle == "" {
			return "unknown"
		}
		return strings.ReplaceAll(needle, " ", "-")
	}
}

func buildEvidence(rr []BurpHTTPMessage) string {
	if len(rr) == 0 {
		return ""
	}
	first := rr[0]
	parts := make([]string, 0, 2)
	if req := strings.TrimSpace(first.Request); req != "" {
		parts = append(parts, "Request:\n"+req)
	}
	if resp := strings.TrimSpace(first.Response); resp != "" {
		parts = append(parts, "Response:\n"+resp)
	}
	return strings.TrimSpace(strings.Join(parts, "\n\n"))
}

func hostFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Hostname())
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func defaultCVSSForSeverity(sev models.Severity) float64 {
	switch sev {
	case models.Critical:
		return 9.0
	case models.High:
		return 7.5
	case models.Medium:
		return 5.5
	case models.Low:
		return 3.0
	default:
		return 0
	}
}
