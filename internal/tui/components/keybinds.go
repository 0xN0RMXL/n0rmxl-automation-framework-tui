package components

import (
	"strings"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/tui/theme"
	"github.com/charmbracelet/bubbles/key"
)

type GlobalKeyMap struct {
	Quit       key.Binding
	Back       key.Binding
	Help       key.Binding
	NewTarget  key.Binding
	Campaign   key.Binding
	Settings   key.Binding
	Dashboard  key.Binding
	Installer  key.Binding
	ScrollUp   key.Binding
	ScrollDown key.Binding
	PageUp     key.Binding
	PageDown   key.Binding
	Top        key.Binding
	Bottom     key.Binding
	Select     key.Binding
	Filter     key.Binding
	Confirm    key.Binding
	Cancel     key.Binding
}

type PhaseKeyMap struct {
	RunAll    key.Binding
	RunPhase  key.Binding
	Skip      key.Binding
	Pause     key.Binding
	Resume    key.Binding
	Stop      key.Binding
	ViewLog   key.Binding
	ViewFinds key.Binding
}

func NewGlobalKeyMap() GlobalKeyMap {
	return GlobalKeyMap{
		Quit:       key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "quit")),
		Back:       key.NewBinding(key.WithKeys("esc", "q"), key.WithHelp("esc/q", "back")),
		Help:       key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		NewTarget:  key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "new target")),
		Campaign:   key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "campaign")),
		Settings:   key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "settings")),
		Dashboard:  key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "dashboard")),
		Installer:  key.NewBinding(key.WithKeys("i"), key.WithHelp("i", "installer")),
		ScrollUp:   key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("up/k", "scroll up")),
		ScrollDown: key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("down/j", "scroll down")),
		PageUp:     key.NewBinding(key.WithKeys("pgup"), key.WithHelp("pgup", "page up")),
		PageDown:   key.NewBinding(key.WithKeys("pgdown"), key.WithHelp("pgdn", "page down")),
		Top:        key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "top")),
		Bottom:     key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "bottom")),
		Select:     key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
		Filter:     key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
		Confirm:    key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "confirm")),
		Cancel:     key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "cancel")),
	}
}

func NewPhaseKeyMap() PhaseKeyMap {
	return PhaseKeyMap{
		RunAll:    key.NewBinding(key.WithKeys("R"), key.WithHelp("R", "run all")),
		RunPhase:  key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "run phase")),
		Skip:      key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "skip")),
		Pause:     key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "pause")),
		Resume:    key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "resume")),
		Stop:      key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "stop")),
		ViewLog:   key.NewBinding(key.WithKeys("l"), key.WithHelp("l", "view log")),
		ViewFinds: key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "findings")),
	}
}

func RenderHelpBar(keys ...key.Binding) string {
	if len(keys) == 0 {
		return ""
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		help := k.Help()
		if help.Key == "" {
			continue
		}
		parts = append(parts, theme.MutedText.Render(help.Key)+" "+theme.BaseText.Render(help.Desc))
	}
	return strings.Join(parts, "  ")
}
