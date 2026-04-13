package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

func newNotifierHTTPClient() *http.Client {
	return &http.Client{Timeout: 15 * time.Second}
}

func postJSONWithRetry(client *http.Client, targetURL string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return doWithRetry(client, func() (*http.Response, error) {
		req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return client.Do(req)
	})
}

func postMultipartWithRetry(client *http.Client, targetURL string, fields map[string]string, fileField string, fileName string, fileReader io.Reader) error {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			_ = writer.Close()
			return err
		}
	}
	if fileField != "" && fileReader != nil {
		part, err := writer.CreateFormFile(fileField, fileName)
		if err != nil {
			_ = writer.Close()
			return err
		}
		if _, err := io.Copy(part, fileReader); err != nil {
			_ = writer.Close()
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}

	contentType := writer.FormDataContentType()
	return doWithRetry(client, func() (*http.Response, error) {
		req, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body.Bytes()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", contentType)
		return client.Do(req)
	})
}

func doWithRetry(client *http.Client, fn func() (*http.Response, error)) error {
	if client == nil {
		client = newNotifierHTTPClient()
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		resp, err := fn()
		if err == nil {
			if resp != nil {
				defer resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
					return nil
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				lastErr = fmt.Errorf("webhook failed: %s", strings.TrimSpace(string(body)))
				if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
					time.Sleep(time.Duration(attempt+1) * 300 * time.Millisecond)
					continue
				}
				return lastErr
			}
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(attempt+1) * 300 * time.Millisecond)
	}
	return lastErr
}
