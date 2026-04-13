package engine

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xN0RMXL/n0rmxl-automation-framework-tui/internal/models"
)

type Checkpoint struct {
	db *sql.DB
}

func NewCheckpoint(workspaceDir string) (*Checkpoint, error) {
	db, err := models.InitCheckpointDB(workspaceDir)
	if err != nil {
		return nil, err
	}
	cp := &Checkpoint{db: db}
	if err := cp.ensureSchemaCompatibility(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return cp, nil
}

func (c *Checkpoint) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Close()
}

func (c *Checkpoint) GetPhaseStatus(phase int) (models.PhaseStatus, error) {
	if c == nil || c.db == nil {
		return models.PhasePending, errors.New("checkpoint db is nil")
	}
	return models.GetPhaseStatus(c.db, phase)
}

func (c *Checkpoint) SetPhaseStatus(phase int, status models.PhaseStatus) error {
	if c == nil || c.db == nil {
		return errors.New("checkpoint db is nil")
	}
	return models.UpdatePhaseStatus(c.db, phase, status)
}

func (c *Checkpoint) GetToolStatus(phase int, tool string) (models.ToolResult, error) {
	if c == nil || c.db == nil {
		return models.ToolResult{}, errors.New("checkpoint db is nil")
	}
	var (
		status     string
		outputFile string
		startedAt  sql.NullString
		finishedAt sql.NullString
		itemsFound int
		errText    sql.NullString
	)
	query := `SELECT status, output_file, started_at, finished_at, items_found, error
		FROM tool_status WHERE phase = ? AND tool_name = ?`
	err := c.db.QueryRow(query, phase, tool).Scan(&status, &outputFile, &startedAt, &finishedAt, &itemsFound, &errText)
	if errors.Is(err, sql.ErrNoRows) {
		return models.ToolResult{ToolName: tool, Status: models.PhasePending}, nil
	}
	if err != nil {
		return models.ToolResult{}, fmt.Errorf("failed to get tool status for %s: %w", tool, err)
	}
	result := models.ToolResult{
		ToolName:   tool,
		Status:     models.PhaseStatus(status),
		OutputFile: outputFile,
		ItemsFound: itemsFound,
		Error:      strings.TrimSpace(errText.String),
	}
	if startedAt.Valid {
		if parsed, parseErr := time.Parse(time.RFC3339, startedAt.String); parseErr == nil {
			result.StartedAt = parsed
		}
	}
	if finishedAt.Valid {
		if parsed, parseErr := time.Parse(time.RFC3339, finishedAt.String); parseErr == nil {
			result.FinishedAt = parsed
		}
	}
	return result, nil
}

func (c *Checkpoint) SetToolStatus(phase int, tool string, result models.ToolResult) error {
	if c == nil || c.db == nil {
		return errors.New("checkpoint db is nil")
	}
	if result.ToolName == "" {
		result.ToolName = tool
	}
	return models.UpdateToolStatus(c.db, phase, tool, result)
}

func (c *Checkpoint) GetAllStatuses() (map[int]models.PhaseStatus, error) {
	if c == nil || c.db == nil {
		return nil, errors.New("checkpoint db is nil")
	}
	return models.GetAllPhaseStatuses(c.db)
}

func (c *Checkpoint) GetToolStatuses(phase int) ([]models.ToolResult, error) {
	if c == nil || c.db == nil {
		return nil, errors.New("checkpoint db is nil")
	}
	rows, err := c.db.Query(`SELECT tool_name, status, output_file, started_at, finished_at, items_found, error
		FROM tool_status WHERE phase = ? ORDER BY tool_name ASC`, phase)
	if err != nil {
		return nil, fmt.Errorf("failed to query tool statuses for phase %d: %w", phase, err)
	}
	defer rows.Close()

	results := make([]models.ToolResult, 0, 32)
	for rows.Next() {
		var (
			tool       string
			status     string
			outputFile string
			startedAt  sql.NullString
			finishedAt sql.NullString
			itemsFound int
			errText    sql.NullString
		)
		if err := rows.Scan(&tool, &status, &outputFile, &startedAt, &finishedAt, &itemsFound, &errText); err != nil {
			return nil, err
		}
		res := models.ToolResult{ToolName: tool, Status: models.PhaseStatus(status), OutputFile: outputFile, ItemsFound: itemsFound, Error: errText.String}
		if startedAt.Valid {
			if parsed, parseErr := time.Parse(time.RFC3339, startedAt.String); parseErr == nil {
				res.StartedAt = parsed
			}
		}
		if finishedAt.Valid {
			if parsed, parseErr := time.Parse(time.RFC3339, finishedAt.String); parseErr == nil {
				res.FinishedAt = parsed
			}
		}
		results = append(results, res)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func (c *Checkpoint) Reset(phase int) error {
	if c == nil || c.db == nil {
		return errors.New("checkpoint db is nil")
	}
	if _, err := c.db.Exec(`DELETE FROM phase_status WHERE phase = ?`, phase); err != nil {
		return fmt.Errorf("failed to reset phase status for %d: %w", phase, err)
	}
	if _, err := c.db.Exec(`DELETE FROM tool_status WHERE phase = ?`, phase); err != nil {
		return fmt.Errorf("failed to reset tool statuses for phase %d: %w", phase, err)
	}
	return nil
}

func (c *Checkpoint) ResetAll() error {
	if c == nil || c.db == nil {
		return errors.New("checkpoint db is nil")
	}
	if _, err := c.db.Exec(`DELETE FROM phase_status`); err != nil {
		return err
	}
	if _, err := c.db.Exec(`DELETE FROM tool_status`); err != nil {
		return err
	}
	return nil
}

func (c *Checkpoint) IsToolDone(phase int, tool string) bool {
	result, err := c.GetToolStatus(phase, tool)
	if err != nil {
		return false
	}
	return result.Status == models.PhaseDone
}

func (c *Checkpoint) ensureSchemaCompatibility() error {
	if c.db == nil {
		return errors.New("checkpoint db is nil")
	}
	if _, err := c.db.Exec(`ALTER TABLE phase_status ADD COLUMN tool_results TEXT`); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	return nil
}

