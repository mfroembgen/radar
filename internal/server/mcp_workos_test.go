package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skyhook-io/radar/internal/auth"
)

// A browser or proxy identity must never reach MCP when WorkOS protects it,
// including through the mounts' subpaths.
func TestMCPWorkOSRejectsBrowserIdentity(t *testing.T) {
	mcp := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	for _, basePath := range []string{"", "/radar"} {
		srv := New(Config{
			DevMode: true, BasePath: basePath, MCPHandler: mcp, MCPReadOnlyHandler: mcp,
			AuthConfig: auth.Config{
				Mode: "proxy", Secret: "0123456789abcdef0123456789abcdef",
				MCPWorkOSAuthKitDomain: "https://auth.example.com", MCPWorkOSPublicURL: "https://radar.example.com" + basePath,
				MCPWorkOSEmailDomain: "example.com",
			},
		})
		for path, want := range map[string]int{
			"/mcp": http.StatusUnauthorized, "/mcp/": http.StatusNotFound,
			"/mcp-readonly": http.StatusUnauthorized, "/mcp-readonly/x": http.StatusNotFound,
		} {
			req := httptest.NewRequest(http.MethodPost, basePath+path, nil)
			req.Header.Set("X-Forwarded-User", "outsider@other.com")
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != want {
				t.Errorf("basePath=%q POST %s with a proxy identity: status %d, want %d", basePath, path, rec.Code, want)
			}
		}
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource"+basePath+"/mcp", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("basePath=%q: protected resource metadata status %d, want public 200", basePath, rec.Code)
		}
	}
}
