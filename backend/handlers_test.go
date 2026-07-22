package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

func TestValidateSessionID(t *testing.T) {
	valid := []string{"abcDEF123", "abc.def-ghi_jkl", strings.Repeat("a", 128)}
	for _, s := range valid {
		if err := validateSessionID(s); err != nil {
			t.Errorf("validateSessionID(%q) = %v, want nil", s, err)
		}
	}
	invalid := []string{"", "../../etc/passwd", "has space", "slash/here", strings.Repeat("a", 129)}
	for _, s := range invalid {
		if err := validateSessionID(s); err == nil {
			t.Errorf("validateSessionID(%q) = nil, want error", s)
		}
	}
}

func TestGenerateResultToken(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		tok, err := generateResultToken()
		if err != nil {
			t.Fatalf("generateResultToken() error: %v", err)
		}
		if !resultTokenPattern.MatchString(tok) {
			t.Fatalf("generated token %q does not match resultTokenPattern", tok)
		}
		if seen[tok] {
			t.Fatalf("generateResultToken() produced a duplicate token %q", tok)
		}
		seen[tok] = true
	}
}

// buildCallbackJWT builds a callback JWT with the given disclosed raw values.
// If key is nil it is signed with HS256 (for the unverified/bearer path);
// otherwise it is signed with RS256.
func buildCallbackJWT(t *testing.T, key *rsa.PrivateKey, rawValues ...string) string {
	t.Helper()
	group := make([]any, 0, len(rawValues))
	for _, v := range rawValues {
		group = append(group, map[string]any{"rawvalue": v})
	}
	claims := jwt.MapClaims{"disclosed": []any{group}}

	var (
		token  *jwt.Token
		signed string
		err    error
	)
	if key == nil {
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err = token.SignedString([]byte("test-hs-key"))
	} else {
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed, err = token.SignedString(key)
	}
	if err != nil {
		t.Fatalf("failed to sign callback JWT: %v", err)
	}
	return signed
}

func writePubKeyPEM(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	p := filepath.Join(t.TempDir(), "pub.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	return p
}

func postNextSession(state *ServerState, body, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/nextsession", strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	handleNextSession(rr, req, state)
	return rr
}

func TestHandleNextSession_FailsClosedWithoutAuthConfig(t *testing.T) {
	state := &ServerState{credentialConfig: CredentialConfig{}}
	body := buildCallbackJWT(t, nil, "Alice", "Smith")
	rr := postNextSession(state, body, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when no auth configured, got %d", rr.Code)
	}
}

func TestHandleNextSession_BearerToken(t *testing.T) {
	state := &ServerState{credentialConfig: CredentialConfig{NextSessionAuthToken: "s3cr3t"}}
	body := buildCallbackJWT(t, nil, "Alice", "Smith")

	if rr := postNextSession(state, body, "wrong"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong bearer token, got %d", rr.Code)
	}
	if rr := postNextSession(state, body, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with missing bearer token, got %d", rr.Code)
	}
	rr := postNextSession(state, body, "s3cr3t")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid bearer token, got %d (%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "Alice") {
		t.Errorf("expected issuance response to contain disclosed firstname, got %s", rr.Body.String())
	}
}

func TestHandleNextSession_JWTSignatureVerification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubPath := writePubKeyPEM(t, &key.PublicKey)
	state := &ServerState{credentialConfig: CredentialConfig{NextSessionPublicKeyPath: pubPath}}

	// Correctly signed callback -> accepted.
	valid := buildCallbackJWT(t, key, "Alice", "Smith")
	if rr := postNextSession(state, valid, ""); rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for validly signed JWT, got %d (%s)", rr.Code, rr.Body.String())
	}

	// Signed by a different key -> rejected.
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	forged := buildCallbackJWT(t, attacker, "Mallory", "Evil")
	if rr := postNextSession(state, forged, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for forged JWT, got %d", rr.Code)
	}

	// Unsigned / tampered token -> rejected.
	if rr := postNextSession(state, "not-a-jwt", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for malformed JWT, got %d", rr.Code)
	}
}

func TestHandleNextSession_BoundsCheckRawValues(t *testing.T) {
	state := &ServerState{credentialConfig: CredentialConfig{NextSessionAuthToken: "tok"}}

	// Only one disclosed value: must be rejected instead of panicking on values[1].
	oneValue := buildCallbackJWT(t, nil, "Alice")
	if rr := postNextSession(state, oneValue, "tok"); rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when fewer than 2 raw values, got %d", rr.Code)
	}

	// Two values: accepted.
	twoValues := buildCallbackJWT(t, nil, "Alice", "Smith")
	if rr := postNextSession(state, twoValues, "tok"); rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with two raw values, got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestHandleResult_RequiresValidToken(t *testing.T) {
	state := &ServerState{tokenStorage: NewInMemoryTokenStorage()}

	// Missing token.
	req := httptest.NewRequest(http.MethodGet, "/api/result", nil)
	rr := httptest.NewRecorder()
	handleResult(rr, req, state)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing token, got %d", rr.Code)
	}

	// Malformed token.
	req = httptest.NewRequest(http.MethodGet, "/api/result?token=short!", nil)
	rr = httptest.NewRecorder()
	handleResult(rr, req, state)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed token, got %d", rr.Code)
	}

	// Well-formed but unknown token.
	req = httptest.NewRequest(http.MethodGet, "/api/result?token="+strings.Repeat("a", 43), nil)
	rr = httptest.NewRecorder()
	handleResult(rr, req, state)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown token, got %d", rr.Code)
	}
}

func TestExtractSessionIDFromPtr(t *testing.T) {
	id, err := extractSessionIDFromPtr([]byte(`{"u":"https://irma.example/irma/session/abc123"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "abc123" {
		t.Errorf("got sessionID %q, want abc123", id)
	}
	if _, err := extractSessionIDFromPtr([]byte(`{"u":""}`)); err == nil {
		t.Error("expected error for empty session URL")
	}
}
