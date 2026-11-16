package audit

import (
	"fmt"
	"log"
	"os"
	"time"
)

type Logger struct {
	file *os.File
}

func NewLogger(filePath string) (*Logger, error) {

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	return &Logger{file: f}, nil
}

func (l *Logger) Log(clientCN, action, keyID, status string) {
	timestamp := time.Now().Format(time.RFC3339)

	entry := fmt.Sprintf("[%s] %s | %s | %s | %s\n", timestamp, clientCN, action, keyID, status)

	if _, err := l.file.WriteString(entry); err != nil {
		log.Printf("Failed to write audit log: %v", err)
	}
}

func (l *Logger) Close() {
	l.file.Close()
}
