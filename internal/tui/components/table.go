package components

import (
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/n0rmxl/n0rmxl/internal/tui/theme"
)

type Column = table.Column
type Row = table.Row

type TableModel struct {
	table      table.Model
	allRows    []table.Row
	filtering  bool
	filterText string
}

func NewTable(columns []Column, rows []Row) TableModel {
	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(12),
	)
	styles := table.DefaultStyles()
	styles.Header = styles.Header.Foreground(theme.Accent).Bold(true)
	styles.Selected = styles.Selected.Foreground(theme.Text).Background(theme.Accent).Bold(true)
	t.SetStyles(styles)
	return TableModel{table: t, allRows: rows}
}

func (m TableModel) Init() tea.Cmd {
	return nil
}

func (m TableModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if keyMsg, ok := msg.(tea.KeyMsg); ok {
		if m.filtering {
			switch keyMsg.String() {
			case "enter":
				m.filtering = false
				m.applyFilter()
				return m, nil
			case "esc":
				m.filtering = false
				m.filterText = ""
				m.table.SetRows(m.allRows)
				return m, nil
			case "backspace":
				if len(m.filterText) > 0 {
					m.filterText = m.filterText[:len(m.filterText)-1]
				}
				return m, nil
			default:
				if len(keyMsg.String()) == 1 {
					m.filterText += keyMsg.String()
				}
				return m, nil
			}
		}

		switch keyMsg.String() {
		case "/":
			m.filtering = true
			return m, nil
		case "s":
			m.sortRows()
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m TableModel) View() string {
	view := m.table.View()
	if m.filtering {
		view += "\n" + theme.MutedText.Render("Filter: "+m.filterText+"_")
	}
	return view
}

func (m *TableModel) SetRows(rows []Row) {
	m.allRows = rows
	m.table.SetRows(rows)
}

func (m *TableModel) SetHeight(height int) {
	m.table.SetHeight(height)
}

func (m *TableModel) SetWidth(width int) {
	m.table.SetWidth(width)
}

func (m *TableModel) applyFilter() {
	query := strings.ToLower(strings.TrimSpace(m.filterText))
	if query == "" {
		m.table.SetRows(m.allRows)
		return
	}
	filtered := make([]table.Row, 0, len(m.allRows))
	for _, row := range m.allRows {
		joined := strings.ToLower(strings.Join(row, " "))
		if strings.Contains(joined, query) {
			filtered = append(filtered, row)
		}
	}
	m.table.SetRows(filtered)
}

func (m *TableModel) sortRows() {
	sorted := append([]table.Row(nil), m.table.Rows()...)
	sort.SliceStable(sorted, func(i int, j int) bool {
		if len(sorted[i]) == 0 || len(sorted[j]) == 0 {
			return len(sorted[i]) > len(sorted[j])
		}
		return sorted[i][0] < sorted[j][0]
	})
	m.table.SetRows(sorted)
}
