package theme

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

var (
	Background = lipgloss.Color("#0D0F14")
	Surface    = lipgloss.Color("#161B22")
	Border     = lipgloss.Color("#30363D")
	Accent     = lipgloss.Color("#58A6FF")
	Accent2    = lipgloss.Color("#3FB950")
	Warning    = lipgloss.Color("#D29922")
	Danger     = lipgloss.Color("#F85149")
	Muted      = lipgloss.Color("#8B949E")
	Text       = lipgloss.Color("#E6EDF3")
	Subtle     = lipgloss.Color("#484F58")
)

var (
	BaseText   = lipgloss.NewStyle().Foreground(Text)
	MutedText  = lipgloss.NewStyle().Foreground(Muted)
	SubtleText = lipgloss.NewStyle().Foreground(Subtle)
	BoldText   = lipgloss.NewStyle().Foreground(Text).Bold(true)
)

var (
	AppFrame = lipgloss.NewStyle().
			Foreground(Text).
			Background(Background).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(Accent).
			Padding(0, 1)

	Panel = lipgloss.NewStyle().
		Foreground(Text).
		Background(Surface).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(Border).
		Padding(0, 1)

	PanelTitle = lipgloss.NewStyle().
			Foreground(Accent).
			Bold(true)

	SectionHeader = lipgloss.NewStyle().
			Foreground(Accent2).
			Underline(true).
			Bold(true)
)

var (
	TableHeader = lipgloss.NewStyle().
			Foreground(Accent).
			Bold(true)

	TableRow = lipgloss.NewStyle().
			Foreground(Text)

	TableRowAlt = lipgloss.NewStyle().
			Foreground(Text).
			Background(lipgloss.Color("#121820"))

	TableSelected = lipgloss.NewStyle().
			Foreground(Text).
			Background(Accent).
			Bold(true)
)

var (
	InputFocused = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(Accent).
			Padding(0, 1)

	InputBlurred = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(Border).
			Padding(0, 1)
)

var (
	ProgressEmpty = lipgloss.NewStyle().Foreground(Subtle)
	ProgressFull  = lipgloss.NewStyle().Foreground(Accent2).Bold(true)
)

func Badge(text string, color lipgloss.Color) lipgloss.Style {
	return lipgloss.NewStyle().
		Foreground(color).
		Bold(true).
		Padding(0, 1).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(color)
}

func SeverityBadge(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return Badge("CRITICAL", lipgloss.Color("#FF0000")).Render("CRITICAL")
	case "high":
		return Badge("HIGH", Danger).Render("HIGH")
	case "medium":
		return Badge("MEDIUM", Warning).Render("MEDIUM")
	case "low":
		return Badge("LOW", Accent).Render("LOW")
	default:
		return Badge("INFO", Muted).Render("INFO")
	}
}

func StatusBadge(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		return Badge("RUNNING", Warning).Render("RUNNING")
	case "done", "success":
		return Badge("DONE", Accent2).Render("DONE")
	case "failed", "error":
		return Badge("FAILED", Danger).Render("FAILED")
	case "skipped":
		return Badge("SKIPPED", Muted).Render("SKIPPED")
	default:
		return Badge("PENDING", Accent).Render("PENDING")
	}
}

func Separator() string {
	width := 80
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		width = w
	}
	return strings.Repeat("-", width)
}

func Logo() string {
	logo := strings.Join([]string{
		" _   _  ___  ____  __  __ __  __ _      _ ",
		"| \\ | |/ _ \\|  _ \\|  \\/  |  \\/  | |    | |",
		"|  \\| | | | | |_) | |\\/| | |\\/| | |    | |",
		"| |\\  | |_| |  _ <| |  | | |  | | |___ | |",
		"|_| \\_|\\___/|_| \\_\\_|  |_|_|  |_|_____|___|",
		"      Bug Bounty Automation Framework v1.0",
	}, "\n")
	return lipgloss.NewStyle().Foreground(Accent).Bold(true).Render(logo)
}

func Divider() string {
	line := lipgloss.NewStyle().Foreground(Border).Render(strings.Repeat("-", 48))
	return lipgloss.NewStyle().Padding(0, 1).Render(line)
}

func RenderTitle(text string, width int) string {
	if width <= 0 {
		return PanelTitle.Render(text)
	}
	return PanelTitle.Width(width).Align(lipgloss.Center).Render(text)
}

func RenderKeyValue(key string, value string) string {
	return fmt.Sprintf("%s: %s", MutedText.Render(key), BaseText.Render(value))
}
