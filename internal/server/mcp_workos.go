package server

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/skyhook-io/radar/internal/auth"
)

// setupMCPWorkOS enables WorkOS AuthKit for the mounted MCP endpoints when
// configured. The browser UI keeps its own authentication mode.
func (s *Server) setupMCPWorkOS(cfg Config) {
	a := s.authConfig
	if a.MCPWorkOSAuthKitDomain == "" && a.MCPWorkOSPublicURL == "" && a.MCPWorkOSEmailDomain == "" {
		return
	}
	if a.MCPWorkOSAuthKitDomain == "" || a.MCPWorkOSPublicURL == "" || a.MCPWorkOSEmailDomain == "" {
		log.Fatal("[auth] --mcp-workos-authkit-domain, --mcp-workos-public-url and --mcp-workos-allowed-email-domain are required together")
	}
	if !a.Enabled() || cloudMode() || cfg.CloudConnect.CloudTunnelConfigured {
		log.Fatal("[auth] MCP WorkOS authentication requires --auth-mode=oidc or proxy in a standalone deployment")
	}
	if u, err := url.Parse(a.MCPWorkOSPublicURL); err != nil || strings.TrimSuffix(u.Path, "/") != s.basePath {
		log.Fatalf("[auth] --mcp-workos-public-url path must equal the base path %q", s.basePath)
	}
	var paths []string
	if s.mcpHandler != nil {
		paths = append(paths, "/mcp")
	}
	if s.mcpReadOnlyHandler != nil {
		paths = append(paths, "/mcp-readonly")
	}
	workOS, err := auth.NewWorkOSAuth(auth.WorkOSConfig{
		AuthKitDomain: a.MCPWorkOSAuthKitDomain, PublicURL: a.MCPWorkOSPublicURL, AllowedEmailDomain: a.MCPWorkOSEmailDomain,
		UsernamePrefix: a.OIDCUsernamePrefix, GroupsPrefix: a.OIDCGroupsPrefix, Paths: paths,
	})
	if err != nil {
		log.Fatalf("[auth] MCP WorkOS authentication: %v", err)
	}
	s.mcpWorkOS = workOS
	log.Printf("[auth] MCP endpoints %v authenticate with WorkOS AuthKit %s", paths, a.MCPWorkOSAuthKitDomain)
}

// authenticate sends WorkOS-protected MCP requests to AuthKit token checks,
// serves discovery metadata publicly and leaves every other route to the
// configured authentication mode.
func (s *Server) authenticate(next http.Handler) http.Handler {
	standard := auth.Authenticate(s.authConfig)(next)
	if s.mcpWorkOS == nil {
		return standard
	}
	metadata := s.mcpWorkOS.MetadataPaths()
	mcp := make(map[string]http.Handler)
	for _, path := range []string{"/mcp", "/mcp-readonly"} {
		if s.mcpWorkOS.Handles(path) {
			mcp[path] = s.mcpWorkOS.Middleware(path, next)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := mcp[r.URL.Path]; h != nil {
			h.ServeHTTP(w, r)
			return
		}
		for path := range mcp {
			// MCP is served only at the exact endpoint; the mount's subpaths
			// must not fall back to browser authentication.
			if strings.HasPrefix(r.URL.Path, path+"/") {
				http.NotFound(w, r)
				return
			}
		}
		if _, public := metadata[r.URL.Path]; public {
			next.ServeHTTP(w, r)
			return
		}
		standard.ServeHTTP(w, r)
	})
}

// mountMCPWorkOSMetadata serves discovery documents at the origin root.
func (s *Server) mountMCPWorkOSMetadata(r chi.Router) {
	if s.mcpWorkOS == nil {
		return
	}
	for path, handler := range s.mcpWorkOS.MetadataPaths() {
		r.Method(http.MethodGet, path, handler)
		r.Method(http.MethodOptions, path, handler)
	}
}
