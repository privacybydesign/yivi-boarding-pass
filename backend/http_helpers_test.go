package main

import (
	log "boarding-pass/logging"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// secret is a stand-in for the kind of sensitive detail a raw error may carry:
// external addresses, internal identifiers or token strings.
const secret = "https://internal-irma.example.com/session?token=SECRET-TOKEN-123"

// TestRespondWithErrDoesNotLeakRawError is the rejection path: with debug
// logging off (the default), the raw error value must never reach the ERROR
// log, and the client must receive only the generic response body.
func TestRespondWithErrDoesNotLeakRawError(t *testing.T) {
	var errBuf bytes.Buffer
	log.Error.SetOutput(&errBuf)
	defer log.Error.SetOutput(os.Stderr)

	rec := httptest.NewRecorder()
	respondWithErr(rec, http.StatusInternalServerError, ErrorInternal, "failed to start IRMA session", errors.New(secret))

	logged := errBuf.String()
	if strings.Contains(logged, "SECRET-TOKEN-123") || strings.Contains(logged, "internal-irma.example.com") {
		t.Errorf("ERROR log leaked raw error value: %q", logged)
	}
	if !strings.Contains(logged, "failed to start IRMA session") {
		t.Errorf("ERROR log missing sanitized message, got: %q", logged)
	}
	if rec.Body.String() != ErrorInternal {
		t.Errorf("response body = %q, want generic %q", rec.Body.String(), ErrorInternal)
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

// TestRespondWithErrLogsRawErrorAtDebug is the happy path: when debug logging
// is explicitly enabled, the raw error value is available for troubleshooting
// on the DEBUG logger.
func TestRespondWithErrLogsRawErrorAtDebug(t *testing.T) {
	log.SetDebug(true)
	defer log.SetDebug(false)

	var dbgBuf bytes.Buffer
	log.Debug.SetOutput(&dbgBuf)

	rec := httptest.NewRecorder()
	respondWithErr(rec, http.StatusInternalServerError, ErrorInternal, "failed to start IRMA session", errors.New(secret))

	if !strings.Contains(dbgBuf.String(), "SECRET-TOKEN-123") {
		t.Errorf("DEBUG log missing raw error value, got: %q", dbgBuf.String())
	}
}

// TestDebugDisabledByDefault guards the default: the Debug logger must discard
// output unless SetDebug(true) is called.
func TestDebugDisabledByDefault(t *testing.T) {
	// Ensure a clean default state regardless of test ordering.
	log.SetDebug(false)

	if w := log.Debug.Writer(); w != io.Discard {
		t.Errorf("Debug logger writes to %T while disabled, want io.Discard", w)
	}
}
