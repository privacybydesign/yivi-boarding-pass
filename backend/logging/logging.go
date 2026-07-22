package logging

import (
	"io"
	"log"
	"os"
)

var (
	Info  *log.Logger
	Error *log.Logger
	// Debug carries verbose, potentially sensitive detail (raw error values,
	// internal identifiers). It discards everything unless debug logging is
	// enabled via SetDebug, so production logs never leak this detail.
	Debug *log.Logger
)

// out is the destination the Info/Error loggers write to. It is kept so that
// toggling debug logging after InitFileLogger keeps writing to the same sink.
var out io.Writer = os.Stderr

// debugEnabled controls whether the Debug logger emits anything. It is off by
// default so that ordinary logs never contain raw error values, which may
// embed external addresses, tokens or internal identifiers.
var debugEnabled = false

func init() {
	initLoggers()
}

func initLoggers() {
	// Standard flags only (date + time) for the always-on loggers: Lshortfile
	// is reserved for the (opt-in) Debug logger so ordinary logs do not leak
	// source file and line numbers.
	Info = log.New(out, "INFO: ", log.Ldate|log.Ltime)
	Error = log.New(out, "ERROR: ", log.Ldate|log.Ltime)

	debugOut := io.Discard
	if debugEnabled {
		debugOut = out
	}
	Debug = log.New(debugOut, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// InitFileLogger redirects all log output to the given file.
func InitFileLogger(fileName string) {
	logFile, err := os.Create(fileName)

	if err != nil {
		log.Fatalf("failed to open error log file: %v", err)
	}

	out = logFile
	initLoggers()
}

// SetDebug toggles debug-level logging. When disabled (the default) the Debug
// logger discards everything written to it.
func SetDebug(enabled bool) {
	debugEnabled = enabled
	initLoggers()
}
