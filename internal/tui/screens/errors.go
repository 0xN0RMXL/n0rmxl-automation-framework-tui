package screens

import (
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
)

type ErrorMsg struct {
	Err error
}

func renderScreenErrorOverlay(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	return theme.Panel.Render(strings.Join([]string{
		theme.Badge("ERROR", theme.Danger).Render("ERROR"),
		message,
	}, "\n"))
}

