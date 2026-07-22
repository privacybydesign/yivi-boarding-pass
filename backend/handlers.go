package main

import (
	log "boarding-pass/logging"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	irma "github.com/privacybydesign/irmago/irma"
)

// sessionIDPattern restricts session identifiers to a safe character set so that
// values derived from external input cannot be used for path traversal or
// injection into downstream URLs.
var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// resultTokenPattern matches the base64url tokens produced by generateResultToken.
var resultTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// validateSessionID returns an error when the sessionID is empty or contains
// unexpected characters.
func validateSessionID(sessionID string) error {
	if !sessionIDPattern.MatchString(sessionID) {
		return fmt.Errorf("session ID has an invalid format")
	}
	return nil
}

// generateResultToken returns an unpredictable, URL-safe lookup token that binds
// a caller to the IRMA session they started. It is used as the storage key so
// that knowing (or guessing) the IRMA session ID is not enough to read a result.
func generateResultToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func handleStart(w http.ResponseWriter, r *http.Request, state *ServerState) {

	// should be get request
	if r.Method != http.MethodGet {
		respondWithErr(w, http.StatusBadRequest, "invalid request", "invalid request method", fmt.Errorf("invalid request method"))
		return
	}

	disclosureWithNext := makeChainedRequest(*state)

	privateKey, err := readPrivateKey(state)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to read private key", err)
		return
	}

	// sign and start session
	signedDiscReq, err := irma.SignRequestorRequest(&disclosureWithNext, jwt.SigningMethodRS256, privateKey, state.credentialConfig.RequestorId)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to sign disclosure request", err)
		return
	}
	irmaSessionURL := fmt.Sprintf("%s/session", state.irmaServerURL)

	chainedSessionResponse, err := sendDisclosureRequest(irmaSessionURL, signedDiscReq)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to start IRMA session", err)
		return
	}

	// get sessionID and sessionPtr from disclosure response
	var sp SessionPackage
	if err := json.NewDecoder(chainedSessionResponse.Body).Decode(&sp); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to decode disclosure response", err)
		return
	}
	sessionID, err := extractSessionIDFromPtr(sp.SessionPtr)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to extract sessionID from sessionPtr", err)
		return
	}
	if err := validateSessionID(sessionID); err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "extracted sessionID is invalid", err)
		return
	}

	// Issue an unpredictable lookup token and store the IRMA requestor token
	// keyed by it. The result endpoint requires this token, so a caller must
	// have started the session to read its result.
	resultToken, err := generateResultToken()
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to generate result token", err)
		return
	}

	err = state.tokenStorage.StoreToken(resultToken, sp.Token)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to store token", err)
		return
	}
	type StartResponse struct {
		SessionPtr json.RawMessage `json:"sessionPtr"`
		SessionID  string          `json:"sessionId"`
		Token      string          `json:"token"`
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(StartResponse{SessionPtr: sp.SessionPtr, SessionID: sessionID, Token: resultToken}); err != nil {
		log.Error.Printf("failed to write response: %v", err)
	}
}

func handleResult(w http.ResponseWriter, r *http.Request, state *ServerState) {
	// The result is bound to the unpredictable lookup token issued at /api/start,
	// not to the (guessable) IRMA session ID.
	resultToken := r.URL.Query().Get("token")

	if resultToken == "" {
		respondWithErr(w, http.StatusBadRequest, "missing token", "token query parameter is required", fmt.Errorf("missing token"))
		return
	}
	if !resultTokenPattern.MatchString(resultToken) {
		respondWithErr(w, http.StatusBadRequest, "invalid token", "token has an invalid format", fmt.Errorf("invalid token format"))
		return
	}

	token, err := state.tokenStorage.RetrieveToken(resultToken)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid token", "failed to retrieve token", err)
		return
	}

	discResp, err := getDisclosureResp(state, token)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to get result from IRMA server", err)
		return
	}

	discBody, err := io.ReadAll(discResp.Body)
	if err != nil {
		respondWithErr(w, http.StatusBadGateway, ErrorInternal, "failed to read response body from IRMA server", err)
		return
	}

	type ResultResponse struct {
		SessionResult json.RawMessage `json:"sessionResult"`
	}
	response := ResultResponse{SessionResult: json.RawMessage(discBody)}

	// remove token from storage after sending over the results
	err = state.tokenStorage.RemoveToken(resultToken)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to remove token", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error.Printf("failed to write result response: %v", err)
	}

}

func handleNextSession(w http.ResponseWriter, r *http.Request, state *ServerState) {
	if r.Method != http.MethodPost {
		respondWithErr(w, http.StatusBadRequest, "invalid request", "invalid request method", fmt.Errorf("invalid request method"))
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read body", http.StatusBadRequest)
		return
	}

	// Authenticate the callback before trusting any disclosed claims. The
	// endpoint is reachable by anyone on the network, so an unauthenticated
	// caller could otherwise forge disclosed attributes and have arbitrary
	// values issued into a boarding pass.
	claims, err := authenticateCallback(state, r, string(body))
	if err != nil {
		respondWithErr(w, http.StatusUnauthorized, "unauthorized", "failed to authenticate next-session callback", err)
		return
	}

	disclosedClaims, ok := claims["disclosed"].([]any)
	if !ok || len(disclosedClaims) == 0 {
		respondWithErr(w, http.StatusBadRequest, "invalid disclosed claims", "disclosed is missing or not an array", fmt.Errorf("invalid disclosed claims"))
		return
	}

	group, ok := disclosedClaims[0].([]any)
	if !ok || len(group) == 0 {
		respondWithErr(w, http.StatusBadRequest, "invalid disclosed claims", "disclosed group is missing or not an array", fmt.Errorf("invalid disclosed group"))
		return
	}

	// Collect all raw values from the disclosed attributes
	values := make([]string, 0, len(group))
	for _, item := range group {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if v, ok := m["rawvalue"].(string); ok && v != "" {
			values = append(values, v)
		}
	}

	// The boarding pass needs both a first name and a last name, so require at
	// least two disclosed raw values before indexing values[0] and values[1].
	if len(values) < 2 {
		respondWithErr(w, http.StatusBadRequest, "missing raw values", "expected at least two rawvalue entries in disclosed attributes", fmt.Errorf("insufficient raw values: got %d, want >= 2", len(values)))
		return
	}

	// Set up the irma cred, fill the cred with values from the disclosed attributes and the rest are fake
	credID := irma.NewCredentialTypeIdentifier("irma-demo.demo-airline.boardingpass")
	cred := &irma.CredentialRequest{
		CredentialTypeID: credID,
		Attributes: map[string]string{
			"firstname": values[0],
			"lastname":  values[1],
			"flight":    "Y256",
			"from":      "AMS",
			"to":        "MXP",
			"seat":      "15B",
			"date":      "2025-12-5",
			"time":      "13:30",
			"gate":      "12",
		},
	}
	issuanceReq := irma.NewIssuanceRequest([]*irma.CredentialRequest{cred})
	payload := issuanceJSON{
		Context:         irma.LDContextIssuanceRequest,
		IssuanceRequest: issuanceReq,
	}

	bs, err := json.Marshal(payload)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to marshal issuance payload", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(bs); err != nil {
		log.Error.Printf("failed to write chained issuance response: %v", err)
	}
}

type issuanceJSON struct {
	Context     string `json:"@context"`
	CallbackURL string `json:"callbackURL,omitempty"`
	CallbackUrl string `json:"callbackUrl,omitempty"`
	*irma.IssuanceRequest
}

// authenticateCallback verifies that a /api/nextsession request genuinely
// originates from the trusted IRMA server and returns the JWT claims once
// authenticated. Two mechanisms are supported and can be combined:
//
//   - next_session_public_key_path: the callback JWT's RS256 signature is
//     verified against the IRMA server's public key (preferred).
//   - next_session_auth_token: a pre-shared bearer token is required in the
//     Authorization header.
//
// The handler fails closed: if neither is configured the callback is rejected.
func authenticateCallback(state *ServerState, r *http.Request, rawJWT string) (jwt.MapClaims, error) {
	cfg := state.credentialConfig

	// Pre-shared bearer token (checked first when configured).
	if cfg.NextSessionAuthToken != "" {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) ||
			subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(cfg.NextSessionAuthToken)) != 1 {
			return nil, fmt.Errorf("invalid or missing bearer token")
		}
	}

	// JWT signature verification against the IRMA server's public key.
	if cfg.NextSessionPublicKeyPath != "" {
		pub, err := readNextSessionPublicKey(cfg.NextSessionPublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load next-session public key: %w", err)
		}
		token, err := jwt.Parse(rawJWT, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return pub, nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to verify callback JWT signature: %w", err)
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			return nil, fmt.Errorf("invalid callback JWT claims")
		}
		return claims, nil
	}

	// No signature key configured: only proceed if a bearer token was configured
	// (and therefore validated above). Otherwise fail closed.
	if cfg.NextSessionAuthToken == "" {
		return nil, fmt.Errorf("no next-session authentication configured: set next_session_public_key_path or next_session_auth_token")
	}
	parser := jwt.Parser{SkipClaimsValidation: true}
	parsedJWT, _, err := parser.ParseUnverified(rawJWT, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse callback JWT: %w", err)
	}
	claims, ok := parsedJWT.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid callback JWT claims")
	}
	return claims, nil
}

func readNextSessionPublicKey(path string) (*rsa.PublicKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(keyBytes)
}

func readPrivateKey(state *ServerState) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(state.credentialConfig.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	priv, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, err
	}
	return priv, nil
}
