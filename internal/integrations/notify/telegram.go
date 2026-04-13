package notify

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

type TelegramNotifier struct {
	token  string
	chatID string
	client *http.Client
}

func NewTelegramNotifier(token string, chatID string) *TelegramNotifier {
	return &TelegramNotifier{
		token:  strings.TrimSpace(token),
		chatID: strings.TrimSpace(chatID),
		client: newNotifierHTTPClient(),
	}
}

func (t *TelegramNotifier) Send(message string) error {
	if t == nil {
		return nil
	}
	if strings.TrimSpace(t.token) == "" || strings.TrimSpace(t.chatID) == "" {
		return fmt.Errorf("telegram notifier is not configured")
	}
	payload := map[string]any{
		"chat_id":    t.chatID,
		"text":       strings.TrimSpace(message),
		"parse_mode": "Markdown",
	}
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.token)
	return postJSONWithRetry(t.client, endpoint, payload)
}

func (t *TelegramNotifier) SendFinding(f models.Finding) error {
	if err := t.Send(formatFindingMessage(f)); err != nil {
		return err
	}
	if strings.TrimSpace(f.Screenshot) == "" {
		return nil
	}
	return t.sendPhoto(f.Screenshot, fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Severity)), safe(f.Title, f.VulnClass)))
}

func (t *TelegramNotifier) Test() error {
	return t.Send("n0rmxl test message")
}

func (t *TelegramNotifier) sendPhoto(filePath string, caption string) error {
	if strings.TrimSpace(t.token) == "" || strings.TrimSpace(t.chatID) == "" {
		return fmt.Errorf("telegram notifier is not configured")
	}
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	fields := map[string]string{
		"chat_id":    t.chatID,
		"parse_mode": "Markdown",
	}
	if strings.TrimSpace(caption) != "" {
		fields["caption"] = caption
	}
	endpoint := fmt.Sprintf("https://api.telegram.org/bot%s/sendPhoto", t.token)
	return postMultipartWithRetry(t.client, endpoint, fields, "photo", filepath.Base(filePath), file)
}

