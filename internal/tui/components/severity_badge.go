package components

import (
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
)

func SeverityBadge(s models.Severity) string {
	return theme.SeverityBadge(string(s))
}

