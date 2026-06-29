package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	irma "github.com/privacybydesign/irmago/irma"
)

type SessionPackage struct {
	Token      string          `json:"token"`
	SessionPtr json.RawMessage `json:"sessionPtr"`
}

func makeChainedRequest(state ServerState) irma.ServiceProviderRequest {
	irma.NewRequestorIdentifier("boarding-pass")

	disclosureRequest := irma.NewDisclosureRequest()
	disclosureRequest.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest(state.credentialConfig.Scheme + ".pbdf.passport.firstName"),
				irma.NewAttributeRequest(state.credentialConfig.Scheme + ".pbdf.passport.lastName"),
			},
		},
	}

	chainedRequest := irma.ServiceProviderRequest{
		RequestorBaseRequest: irma.RequestorBaseRequest{
			ResultJwtValidity: 120,
			ClientTimeout:     120,
			NextSession:       &irma.NextSessionData{URL: state.credentialConfig.NextSessionURL},
		},
		Request: disclosureRequest,
	}
	return chainedRequest
}

func extractSessionIDFromPtr(sessionPtr json.RawMessage) (string, error) {
	var ptrData struct {
		U string `json:"u"`
	}

	if err := json.Unmarshal(sessionPtr, &ptrData); err != nil {
		return "", fmt.Errorf("failed to unmarshal session pointer: %w", err)
	}

	parts := strings.Split(ptrData.U, "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("invalid session URL format")
	}

	sessionID := parts[len(parts)-1]
	if sessionID == "" {
		return "", fmt.Errorf("empty session ID")
	}

	return sessionID, nil
}
func getDisclosureResp(state *ServerState, token string) (response *http.Response, err error) {
	requestorResultURL := fmt.Sprintf("%s/session/%s/result", state.irmaServerURL, token)
	discReq, err := http.NewRequest(http.MethodGet, requestorResultURL, nil)
	if err != nil {
		return nil, err
	}
	discReq.Header.Set("Accept", "application/json")
	discResp, err := http.DefaultClient.Do(discReq)
	if err != nil {
		return nil, err
	}
	return discResp, nil

}
func sendDisclosureRequest(irmaSessionURL string, signedDiscReq string) (*http.Response, error) {
	httpReq, err := http.NewRequest(http.MethodPost, irmaSessionURL, strings.NewReader(signedDiscReq))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "text/plain")
	httpReq.Header.Set("Accept", "application/json")

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	return httpResp, err
}
