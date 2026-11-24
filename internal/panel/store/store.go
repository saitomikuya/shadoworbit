package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const (
	// SQLiteTimeLayout is a fixed-width UTC timestamp layout guaranteeing
	// lexicographical order matches chronological order in SQLite TEXT columns.
	SQLiteTimeLayout = "2006-01-02T15:04:05.000000000Z"
)

var (
	ErrNotFound        = errors.New("store: record not found")
	ErrConflict        = errors.New("store: conflict / unique constraint violated")
	ErrForeignKey      = errors.New("store: foreign key constraint violated")
	ErrInvalidArgument = errors.New("store: invalid argument")
)

// Store wraps a single-writer SQLite database handle with WAL and FK enforcement.
type Store struct {
	db        *sql.DB
	isMemory  bool
	closeOnce sync.Once
	closeErr  error
}

// Open opens (or creates) a SQLite database at dbPath, verifies pragmas,
// enforces single-connection pooling, and runs idempotent schema migrations.
func Open(ctx context.Context, dbPath string) (*Store, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, fmt.Errorf("%w: empty db path", ErrInvalidArgument)
	}

	dsn, isMem, err := buildDSN(dbPath)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}

	// Single connection eliminates snapshot-upgrade SQLITE_BUSY under WAL and
	// guarantees per-connection PRAGMAs apply to every query.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping sqlite: %w", err)
	}

	s := &Store{db: db, isMemory: isMem}
	if err := s.ensureAndVerifyPragmas(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := s.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}

	return s, nil
}

func buildDSN(dbPath string) (string, bool, error) {
	if dbPath == ":memory:" || strings.HasPrefix(dbPath, "file::memory:") {
		if dbPath == ":memory:" {
			return "file::memory:?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", true, nil
		}
		sep := "?"
		if strings.Contains(dbPath, "?") {
			sep = "&"
		}
		return dbPath + sep + "_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", true, nil
	}

	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		return "", false, fmt.Errorf("store: resolve db path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return "", false, fmt.Errorf("store: create db dir: %w", err)
	}

	u := url.URL{
		Scheme: "file",
		Path:   filepath.ToSlash(absPath),
	}
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "synchronous(NORMAL)")
	u.RawQuery = q.Encode()
	return u.String(), false, nil
}

func (s *Store) ensureAndVerifyPragmas(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys = ON;`); err != nil {
		return fmt.Errorf("store: enable foreign_keys: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA busy_timeout = 5000;`); err != nil {
		return fmt.Errorf("store: set busy_timeout: %w", err)
	}

	var fk int
	if err := s.db.QueryRowContext(ctx, `PRAGMA foreign_keys;`).Scan(&fk); err != nil {
		return fmt.Errorf("store: query foreign_keys: %w", err)
	}
	if fk != 1 {
		return fmt.Errorf("store: expected foreign_keys=1, got %d", fk)
	}

	var bt int
	if err := s.db.QueryRowContext(ctx, `PRAGMA busy_timeout;`).Scan(&bt); err != nil {
		return fmt.Errorf("store: query busy_timeout: %w", err)
	}
	if bt < 5000 {
		return fmt.Errorf("store: expected busy_timeout>=5000, got %d", bt)
	}

	if !s.isMemory {
		if _, err := s.db.ExecContext(ctx, `PRAGMA journal_mode = WAL;`); err != nil {
			return fmt.Errorf("store: enable WAL mode: %w", err)
		}
	}

	var jm string
	if err := s.db.QueryRowContext(ctx, `PRAGMA journal_mode;`).Scan(&jm); err != nil {
		return fmt.Errorf("store: query journal_mode: %w", err)
	}
	jmLower := strings.ToLower(strings.TrimSpace(jm))
	if s.isMemory {
		if jmLower != "memory" && jmLower != "wal" {
			return fmt.Errorf("store: unexpected memory journal_mode %q", jm)
		}
	} else if jmLower != "wal" {
		return fmt.Errorf("store: expected journal_mode=wal, got %q", jm)
	}

	return nil
}

// Close closes the underlying database connection. It is idempotent.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if !s.isMemory {
			chkCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			_, _ = s.db.ExecContext(chkCtx, `PRAGMA wal_checkpoint(TRUNCATE);`)
			cancel()
		}
		s.closeErr = s.db.Close()
	})
	return s.closeErr
}

// DB exposes the underlying *sql.DB for advanced diagnostics or testing.
func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) withTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit tx: %w", err)
	}
	return nil
}

// FormatSQLiteTime formats t in fixed-width UTC RFC3339-nanoseconds.
func FormatSQLiteTime(t time.Time) string {
	return t.UTC().Format(SQLiteTimeLayout)
}

// ParseSQLiteTime parses timestamps stored in SQLiteTimeLayout or legacy formats.
func ParseSQLiteTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, fmt.Errorf("%w: empty timestamp", ErrInvalidArgument)
	}
	for _, layout := range []string{
		SQLiteTimeLayout,
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("store: parse timestamp %q: invalid format", s)
}

func mapSQLiteErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var sqlErr *sqlite.Error
	if errors.As(err, &sqlErr) {
		code := sqlErr.Code()
		switch code {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return fmt.Errorf("%w: %v", ErrConflict, err)
		case sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
			return fmt.Errorf("%w: %v", ErrForeignKey, err)
		case sqlite3.SQLITE_CONSTRAINT_CHECK, sqlite3.SQLITE_CONSTRAINT_NOTNULL, sqlite3.SQLITE_CONSTRAINT_DATATYPE:
			return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
		}
		if code&0xff == sqlite3.SQLITE_CONSTRAINT {
			msg := err.Error()
			switch {
			case strings.Contains(msg, "UNIQUE"), strings.Contains(msg, "PRIMARY KEY"):
				return fmt.Errorf("%w: %v", ErrConflict, err)
			case strings.Contains(msg, "FOREIGN KEY"):
				return fmt.Errorf("%w: %v", ErrForeignKey, err)
			case strings.Contains(msg, "CHECK"), strings.Contains(msg, "NOT NULL"):
				return fmt.Errorf("%w: %v", ErrInvalidArgument, err)
			}
		}
	}
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func formatNullableTime(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: FormatSQLiteTime(*t), Valid: true}
}

func parseNullableTime(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid || strings.TrimSpace(ns.String) == "" {
		return nil, nil
	}
	t, err := ParseSQLiteTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
