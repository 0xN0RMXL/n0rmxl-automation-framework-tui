package components

import (
	"github.com/n0rmxl/n0rmxl/internal/models"
	"github.com/n0rmxl/n0rmxl/internal/tui/theme"
)

func SeverityBadge(s models.Severity) string {
	return theme.SeverityBadge(string(s))
}
