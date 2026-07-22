package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpaHandler_DoesNotEscapeStaticPath(t *testing.T) {
	root := t.TempDir()
	staticDir := filepath.Join(root, "dist")
	if err := os.MkdirAll(staticDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("INDEX"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "app.js"), []byte("APPJS"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A secret sibling file that lives outside the static directory.
	secret := filepath.Join(root, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}

	h := SpaHandler{staticPath: staticDir, indexPath: "index.html"}

	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+path, nil)
		req.URL.Path = path // preserve traversal segments without net/http cleaning
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// A real file inside the static dir is served.
	if rr := get("/app.js"); rr.Body.String() != "APPJS" {
		t.Errorf("expected app.js content, got %q (code %d)", rr.Body.String(), rr.Code)
	}

	// Traversal attempts must never leak the sibling secret file.
	for _, p := range []string{"/../secret.txt", "/../../secret.txt", "/..%2fsecret.txt", "/dist/../../secret.txt"} {
		rr := get(p)
		if strings.Contains(rr.Body.String(), "TOPSECRET") {
			t.Errorf("path %q leaked secret file content: %q", p, rr.Body.String())
		}
	}
}
