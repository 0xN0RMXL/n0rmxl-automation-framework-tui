package burp

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func ProxyEnvVars(host string, port int) []string {
	host = strings.TrimSpace(host)
	if host == "" {
		host = "127.0.0.1"
	}
	if port <= 0 || port > 65535 {
		port = 8080
	}
	proxyURL := "http://" + host + ":" + strconv.Itoa(port)
	return []string{
		"HTTP_PROXY=" + proxyURL,
		"HTTPS_PROXY=" + proxyURL,
		"http_proxy=" + proxyURL,
		"https_proxy=" + proxyURL,
	}
}

func (b *BurpClient) VerifyProxy() error {
	if b == nil {
		return fmt.Errorf("burp client is nil")
	}
	if _, err := b.Ping(); err != nil {
		return fmt.Errorf("burp api ping failed: %w", err)
	}
	proxyURL, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		return err
	}
	_, _ = client.Do(req)
	entries, err := b.GetSitemap()
	if err != nil {
		return fmt.Errorf("burp sitemap query failed: %w", err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("burp proxy verification inconclusive: no sitemap entries visible")
	}
	return nil
}
