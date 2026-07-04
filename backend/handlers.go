package main

import (
	log "boarding-pass/logging"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v4"
	irma "github.com/privacybydesign/irmago/irma"
)

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
	log.Debug.Printf("sp.SessionPtr: %s", sp.SessionPtr)
	sessionID, err := extractSessionIDFromPtr(sp.SessionPtr)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to extract sessionID from sessionPtr", err)
		return
	}

	err = state.tokenStorage.StoreToken(sessionID, sp.Token)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to store token", err)
		return
	}
	type StartResponse struct {
		SessionPtr json.RawMessage `json:"sessionPtr"`
		SessionID  string          `json:"sessionId"`
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(StartResponse{SessionPtr: sp.SessionPtr, SessionID: sessionID}); err != nil {
		log.Error.Printf("failed to write response")
		log.Debug.Printf("failed to write response: %v", err)
	}
}

func handleResult(w http.ResponseWriter, r *http.Request, state *ServerState) {
	sessionID := r.URL.Query().Get("sessionID")

	if sessionID == "" {
		respondWithErr(w, http.StatusBadRequest, "missing sessionID", "sessionID query parameter is required", fmt.Errorf("missing sessionID"))
		return
	}

	token, err := state.tokenStorage.RetrieveToken(sessionID)
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid sessionID", "failed to retrieve token", err)
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
	err = state.tokenStorage.RemoveToken(sessionID)
	if err != nil {
		respondWithErr(w, http.StatusInternalServerError, ErrorInternal, "failed to remove token", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error.Printf("failed to write result response")
		log.Debug.Printf("failed to write result response: %v", err)
	}

}

func handleNextSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithErr(w, http.StatusBadRequest, "invalid request", "invalid request method", fmt.Errorf("invalid request method"))
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "could not read body", http.StatusBadRequest)
		return
	}

	// decode jwt body response
	Parser := jwt.Parser{SkipClaimsValidation: true}
	parsedJWT, _, err := Parser.ParseUnverified(string(body), jwt.MapClaims{})
	if err != nil {
		respondWithErr(w, http.StatusBadRequest, "invalid JWT", "failed to parse callback JWT", err)
		return
	}

	claims, ok := parsedJWT.Claims.(jwt.MapClaims)
	if !ok {
		respondWithErr(w, http.StatusBadRequest, "invalid JWT claims", "failed to extract JWT claims", fmt.Errorf("invalid JWT claims"))
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

	if len(values) == 0 {
		respondWithErr(w, http.StatusBadRequest, "missing raw values", "no rawvalue found in disclosed attributes", fmt.Errorf("missing raw values"))
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
		log.Error.Printf("failed to write chained issuance response")
		log.Debug.Printf("failed to write chained issuance response: %v", err)
	}
}

type issuanceJSON struct {
	Context     string `json:"@context"`
	CallbackURL string `json:"callbackURL,omitempty"`
	CallbackUrl string `json:"callbackUrl,omitempty"`
	*irma.IssuanceRequest
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
