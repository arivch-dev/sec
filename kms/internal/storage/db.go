package storage

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type KeyRecord struct {
	ID            string
	CiphertextDEK []byte
	KEKVersion    int
	Description   string
	CreatedAt     time.Time
	Status        string
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA synchronous = NORMAL;",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return nil, fmt.Errorf("failed to apply pragma %s: %w", pragma, err)
		}
	}

	query := `
	CREATE TABLE IF NOT EXISTS data_keys (
		id TEXT PRIMARY KEY,
		ciphertext_dek BLOB NOT NULL,
		kek_version INTEGER NOT NULL DEFAULT 1,
		description TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		status TEXT DEFAULT 'active'
	);`

	if _, err := db.Exec(query); err != nil {
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	return &Store{db: db}, nil
}

func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *Store) SaveKey(ciphertextDEK []byte, kekVersion int, description string) (string, error) {
	id := generateID()
	query := `INSERT INTO data_keys (id, ciphertext_dek, kek_version, description) VALUES (?, ?, ?, ?)`
	_, err := s.db.Exec(query, id, ciphertextDEK, kekVersion, description)
	if err != nil {
		return "", fmt.Errorf("failed to save key: %w", err)
	}
	return id, nil
}

func (s *Store) GetKey(id string) ([]byte, int, error) {
	var ciphertextDEK []byte
	var kekVersion int
	query := `SELECT ciphertext_dek, kek_version FROM data_keys WHERE id = ? AND status = 'active'`
	err := s.db.QueryRow(query, id).Scan(&ciphertextDEK, &kekVersion)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, 0, fmt.Errorf("key not found or inactive")
		}
		return nil, 0, fmt.Errorf("failed to get key: %w", err)
	}
	return ciphertextDEK, kekVersion, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}
