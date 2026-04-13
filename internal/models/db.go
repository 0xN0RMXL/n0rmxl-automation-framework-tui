package models

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type FindingFilter struct {
	Phase     *int
	Severity  *Severity
	VulnClass *string
	Confirmed *bool
}

func InitCheckpointDB(workspaceDir string) (*sql.DB, error) {
	dbPath := filepath.Join(workspaceDir, ".n0rmxl", "checkpoint.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create checkpoint path: %w", err)
	}

	db, err := openSQLite(dbPath)
	if err != nil {
		return nil, err
	}

	schema := []string{
		`CREATE TABLE IF NOT EXISTS phase_status (
			phase INTEGER PRIMARY KEY,
			status TEXT NOT NULL,
			started_at TEXT,
			finished_at TEXT,
			updated_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS tool_status (
			phase INTEGER NOT NULL,
			tool_name TEXT NOT NULL,
			status TEXT NOT NULL,
			output_file TEXT,
			started_at TEXT,
			finished_at TEXT,
			items_found INTEGER DEFAULT 0,
			error TEXT,
			PRIMARY KEY (phase, tool_name)
		);`,
	}

	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("failed to initialize checkpoint schema: %w", err)
		}
	}
	if _, err := db.Exec(`PRAGMA synchronous = NORMAL;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to tune checkpoint db synchronous mode: %w", err)
	}
	if _, err := db.Exec(`PRAGMA cache_size = 10000;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to tune checkpoint db cache size: %w", err)
	}
	return db, nil
}

func InitFindingsDB(workspaceDir string) (*sql.DB, error) {
	dbPath := filepath.Join(workspaceDir, ".n0rmxl", "findings.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create findings path: %w", err)
	}

	db, err := openSQLite(dbPath)
	if err != nil {
		return nil, err
	}

	stmt := `CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		fingerprint TEXT,
		phase INTEGER NOT NULL,
		vuln_class TEXT,
		target TEXT,
		host TEXT,
		url TEXT,
		method TEXT,
		parameter TEXT,
		payload TEXT,
		severity TEXT,
		cvss REAL,
		title TEXT,
		description TEXT,
		evidence TEXT,
		curl_cmd TEXT,
		screenshot TEXT,
		tool TEXT,
		timestamp TEXT,
		tags_json TEXT,
		remediation TEXT,
		confirmed INTEGER,
		duplicate INTEGER,
		chained_with_json TEXT
	);`
	if _, err := db.Exec(stmt); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize findings schema: %w", err)
	}
	if err := ensureFindingsSchemaCompatibility(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func SaveFinding(db *sql.DB, f Finding) error {
	return saveFindingExec(db, f)
}

func SaveFindingsBatch(db *sql.DB, findings []Finding) error {
	if db == nil {
		return errors.New("findings db is nil")
	}
	if len(findings) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start findings transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()
	for _, finding := range findings {
		if err := saveFindingExec(tx, finding); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit findings transaction: %w", err)
	}
	return nil
}

type findingExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func saveFindingExec(db findingExecer, f Finding) error {
	if db == nil {
		return errors.New("findings db is nil")
	}
	if strings.TrimSpace(f.ID) == "" {
		f.ID = uuid.NewString()
	}
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now().UTC()
	}
	tagsJSON, err := json.Marshal(f.Tags)
	if err != nil {
		return fmt.Errorf("failed to encode finding tags: %w", err)
	}
	chainJSON, err := json.Marshal(f.ChainedWith)
	if err != nil {
		return fmt.Errorf("failed to encode finding chain links: %w", err)
	}
	fingerprint := findingFingerprint(f)
	q := `INSERT INTO findings (
		id, fingerprint, phase, vuln_class, target, host, url, method, parameter, payload,
		severity, cvss, title, description, evidence, curl_cmd, screenshot,
		tool, timestamp, tags_json, remediation, confirmed, duplicate, chained_with_json
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(fingerprint) DO UPDATE SET
		phase=excluded.phase,
		vuln_class=excluded.vuln_class,
		target=excluded.target,
		host=excluded.host,
		url=excluded.url,
		method=excluded.method,
		parameter=excluded.parameter,
		payload=excluded.payload,
		severity=excluded.severity,
		cvss=excluded.cvss,
		title=excluded.title,
		description=excluded.description,
		evidence=excluded.evidence,
		curl_cmd=excluded.curl_cmd,
		screenshot=excluded.screenshot,
		tool=excluded.tool,
		timestamp=excluded.timestamp,
		tags_json=excluded.tags_json,
		remediation=excluded.remediation,
		confirmed=excluded.confirmed,
		duplicate=excluded.duplicate,
		chained_with_json=excluded.chained_with_json;`

	_, err = db.Exec(
		q,
		f.ID, fingerprint, f.Phase, f.VulnClass, f.Target, f.Host, f.URL, f.Method, f.Parameter, f.Payload,
		string(f.Severity), f.CVSS, f.Title, f.Description, f.Evidence, f.CurlCmd, f.Screenshot,
		f.Tool, f.Timestamp.Format(time.RFC3339), string(tagsJSON), f.Remediation, boolToInt(f.Confirmed),
		boolToInt(f.Duplicate), string(chainJSON),
	)
	if err != nil {
		return fmt.Errorf("failed to persist finding %s: %w", f.ID, err)
	}
	if hook := getFindingSavedHook(); hook != nil {
		findingCopy := f
		go hook(findingCopy)
	}
	return nil
}

func GetFindings(db *sql.DB, filter FindingFilter) ([]Finding, error) {
	if db == nil {
		return nil, errors.New("findings db is nil")
	}
	query := `SELECT
		id, phase, vuln_class, target, host, url, method, parameter, payload,
		severity, cvss, title, description, evidence, curl_cmd, screenshot,
		tool, timestamp, tags_json, remediation, confirmed, duplicate, chained_with_json
	FROM findings`
	var where []string
	var args []any

	if filter.Phase != nil {
		where = append(where, "phase = ?")
		args = append(args, *filter.Phase)
	}
	if filter.Severity != nil {
		where = append(where, "severity = ?")
		args = append(args, strings.ToLower(string(*filter.Severity)))
	}
	if filter.VulnClass != nil {
		where = append(where, "vuln_class = ?")
		args = append(args, *filter.VulnClass)
	}
	if filter.Confirmed != nil {
		where = append(where, "confirmed = ?")
		args = append(args, boolToInt(*filter.Confirmed))
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY timestamp DESC"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	out := make([]Finding, 0)
	for rows.Next() {
		var (
			f         Finding
			timestamp string
			tagsJSON  string
			chainJSON string
			confirmed int
			duplicate int
			severity  string
		)
		if err := rows.Scan(
			&f.ID, &f.Phase, &f.VulnClass, &f.Target, &f.Host, &f.URL, &f.Method, &f.Parameter, &f.Payload,
			&severity, &f.CVSS, &f.Title, &f.Description, &f.Evidence, &f.CurlCmd, &f.Screenshot,
			&f.Tool, &timestamp, &tagsJSON, &f.Remediation, &confirmed, &duplicate, &chainJSON,
		); err != nil {
			return nil, fmt.Errorf("failed to scan finding row: %w", err)
		}
		f.Severity = Severity(severity)
		f.Confirmed = confirmed == 1
		f.Duplicate = duplicate == 1
		if timestamp != "" {
			if parsed, err := time.Parse(time.RFC3339, timestamp); err == nil {
				f.Timestamp = parsed
			}
		}
		if tagsJSON != "" {
			_ = json.Unmarshal([]byte(tagsJSON), &f.Tags)
		}
		if chainJSON != "" {
			_ = json.Unmarshal([]byte(chainJSON), &f.ChainedWith)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error while iterating findings: %w", err)
	}
	return out, nil
}

func UpdatePhaseStatus(db *sql.DB, phase int, status PhaseStatus) error {
	if db == nil {
		return errors.New("checkpoint db is nil")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	finishedAt := ""
	if status == PhaseDone || status == PhaseFailed || status == PhaseSkipped {
		finishedAt = now
	}
	q := `INSERT INTO phase_status (phase, status, started_at, finished_at, updated_at)
	VALUES (?, ?, CASE WHEN ? = 'running' THEN ? ELSE NULL END, ?, ?)
	ON CONFLICT(phase) DO UPDATE SET
		status = excluded.status,
		started_at = CASE
			WHEN phase_status.started_at IS NULL AND excluded.status = 'running' THEN excluded.started_at
			ELSE phase_status.started_at
		END,
		finished_at = CASE
			WHEN excluded.finished_at IS NOT NULL AND excluded.finished_at != '' THEN excluded.finished_at
			ELSE phase_status.finished_at
		END,
		updated_at = excluded.updated_at;`

	_, err := db.Exec(q, phase, string(status), string(status), now, finishedAt, now)
	if err != nil {
		return fmt.Errorf("failed to update phase %d status: %w", phase, err)
	}
	return nil
}

func UpdateToolStatus(db *sql.DB, phase int, tool string, status ToolResult) error {
	if db == nil {
		return errors.New("checkpoint db is nil")
	}
	q := `INSERT INTO tool_status (
		phase, tool_name, status, output_file, started_at, finished_at, items_found, error
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(phase, tool_name) DO UPDATE SET
		status = excluded.status,
		output_file = excluded.output_file,
		started_at = CASE
			WHEN tool_status.started_at IS NULL AND excluded.started_at IS NOT NULL AND excluded.started_at != '' THEN excluded.started_at
			ELSE tool_status.started_at
		END,
		finished_at = CASE
			WHEN excluded.finished_at IS NOT NULL AND excluded.finished_at != '' THEN excluded.finished_at
			ELSE tool_status.finished_at
		END,
		items_found = excluded.items_found,
		error = excluded.error;`

	started := ""
	finished := ""
	if !status.StartedAt.IsZero() {
		started = status.StartedAt.UTC().Format(time.RFC3339)
	}
	if !status.FinishedAt.IsZero() {
		finished = status.FinishedAt.UTC().Format(time.RFC3339)
	}
	_, err := db.Exec(q, phase, tool, string(status.Status), status.OutputFile, started, finished, status.ItemsFound, status.Error)
	if err != nil {
		return fmt.Errorf("failed to update tool status %s (phase %d): %w", tool, phase, err)
	}
	return nil
}

func GetPhaseStatus(db *sql.DB, phase int) (PhaseStatus, error) {
	if db == nil {
		return PhasePending, errors.New("checkpoint db is nil")
	}
	var status string
	err := db.QueryRow(`SELECT status FROM phase_status WHERE phase = ?`, phase).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return PhasePending, nil
	}
	if err != nil {
		return PhasePending, fmt.Errorf("failed to get phase status for %d: %w", phase, err)
	}
	return PhaseStatus(status), nil
}

func GetAllPhaseStatuses(db *sql.DB) (map[int]PhaseStatus, error) {
	if db == nil {
		return nil, errors.New("checkpoint db is nil")
	}
	rows, err := db.Query(`SELECT phase, status FROM phase_status ORDER BY phase ASC`)
	if err != nil {
		return nil, fmt.Errorf("failed to list phase statuses: %w", err)
	}
	defer rows.Close()

	statusMap := make(map[int]PhaseStatus)
	for rows.Next() {
		var phase int
		var status string
		if err := rows.Scan(&phase, &status); err != nil {
			return nil, fmt.Errorf("failed to read phase status row: %w", err)
		}
		statusMap[phase] = PhaseStatus(status)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed while iterating phase statuses: %w", err)
	}
	return statusMap, nil
}

func openSQLite(path string) (*sql.DB, error) {
	db, err := sql.Open(sqliteDriverName, path)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db %s: %w", path, err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}
	if _, err := db.Exec(`PRAGMA synchronous = NORMAL;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to set synchronous mode: %w", err)
	}
	if _, err := db.Exec(`PRAGMA cache_size = 10000;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to set cache size: %w", err)
	}
	return db, nil
}

func ensureFindingsSchemaCompatibility(db *sql.DB) error {
	if db == nil {
		return errors.New("findings db is nil")
	}
	if _, err := db.Exec(`ALTER TABLE findings ADD COLUMN fingerprint TEXT`); err != nil {
		lowerErr := strings.ToLower(err.Error())
		if !strings.Contains(lowerErr, "duplicate column") && !strings.Contains(lowerErr, "already exists") {
			return fmt.Errorf("failed to ensure findings fingerprint column: %w", err)
		}
	}
	statements := []string{
		`UPDATE findings SET fingerprint = id WHERE fingerprint IS NULL OR fingerprint = ''`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_severity_phase_confirmed ON findings(severity, phase, confirmed)`,
	}
	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("failed to ensure findings index: %w", err)
		}
	}
	return nil
}

func findingFingerprint(f Finding) string {
	parts := []string{
		fmt.Sprintf("%d", f.Phase),
		strings.ToLower(strings.TrimSpace(string(f.Severity))),
		strings.ToLower(strings.TrimSpace(f.VulnClass)),
		strings.ToLower(strings.TrimSpace(f.Target)),
		strings.ToLower(strings.TrimSpace(f.Host)),
		strings.TrimSpace(f.URL),
		strings.ToUpper(strings.TrimSpace(f.Method)),
		strings.TrimSpace(f.Parameter),
		strings.TrimSpace(f.Payload),
		strings.TrimSpace(f.Tool),
		strings.TrimSpace(f.Title),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
