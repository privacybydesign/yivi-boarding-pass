package main

import (
	log "boarding-pass/logging"
	"net/http"
)

const ErrorInternal = "error:internal"

// respondWithErr writes a generic response body to the client and logs the
// error. Only the controlled, human-readable logMsg is logged at ERROR level;
// the raw err value (which may embed external addresses, tokens or internal
// identifiers) is emitted only at DEBUG level, which is disabled by default.
func respondWithErr(w http.ResponseWriter, code int, responseBody string, logMsg string, err error) {
	log.Error.Printf("%s -> returning status code %d", logMsg, code)
	if err != nil {
		log.Debug.Printf("%s: %v", logMsg, err)
	}
	w.WriteHeader(code)
	if _, writeErr := w.Write([]byte(responseBody)); writeErr != nil {
		log.Error.Printf("failed to write body to http response")
		log.Debug.Printf("failed to write body to http response: %v", writeErr)
	}
}
