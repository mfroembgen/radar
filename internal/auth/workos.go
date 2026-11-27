package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	mcpauth "github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/time/rate"
)

// workOSScopes are the scopes every MCP access token must carry. Clients also
// request offline_access so AuthKit issues refresh tokens.
var workOSScopes = []string{"openid", "email"}

const (
	workOSProfileCacheLimit  = 4096
	workOSKeyRefreshInterval = time.Minute
)

// WorkOSAuth authenticates remote MCP callers with WorkOS AuthKit access
// tokens. AuthKit owns client registration, sign-in, consent and refresh, so
// Radar keeps no OAuth state and restarts or extra replicas sign nobody out.
type WorkOSAuth struct {
	issuer, emailDomain          string
	usernamePrefix, groupsPrefix string
	resources                    map[string]*workOSResource // keyed by MCP path, e.g. "/mcp"
	client                       *http.Client
	mu                           sync.Mutex
	profiles                     map[[32]byte]workOSProfile
}

type workOSResource struct {
	url, metadataURL string
	verifier         *oidc.IDTokenVerifier
}

type workOSProfile struct {
	user    User
	expires time.Time
}

// WorkOSConfig configures MCP authentication through WorkOS AuthKit.
type WorkOSConfig struct {
	AuthKitDomain      string   // HTTPS AuthKit origin, e.g. https://example.authkit.app
	PublicURL          string   // public HTTPS origin plus base path Radar is served at
	AllowedEmailDomain string   // verified users of this domain may use MCP
	UsernamePrefix     string   // Kubernetes username is UsernamePrefix + email
	GroupsPrefix       string   // Kubernetes group is GroupsPrefix + email domain
	Paths              []string // mounted MCP paths, e.g. "/mcp", "/mcp-readonly"
}

// NewWorkOSAuth validates the configuration and prepares one token audience per
// MCP path. Each audience must be registered as a WorkOS resource indicator.
func NewWorkOSAuth(cfg WorkOSConfig) (*WorkOSAuth, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return newWorkOSAuth(cfg, &http.Client{
		Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	})
}

func newWorkOSAuth(cfg WorkOSConfig, client *http.Client) (*WorkOSAuth, error) {
	issuer, err := workOSHTTPSURL(strings.TrimSuffix(cfg.AuthKitDomain, "/"))
	if err != nil || issuer.Path != "" {
		return nil, fmt.Errorf("WorkOS AuthKit domain must be an HTTPS origin without a path")
	}
	public, err := workOSHTTPSURL(strings.TrimSuffix(cfg.PublicURL, "/"))
	if err != nil || public.RawPath != "" {
		return nil, fmt.Errorf("WorkOS public URL must be the HTTPS origin and base path Radar is served at")
	}
	domain := cfg.AllowedEmailDomain
	if domain == "" || strings.ContainsAny(domain, "@*/[]:\\ \t\r\n") || strings.ToLower(domain) != domain {
		return nil, fmt.Errorf("WorkOS allowed email domain must be one lowercase domain")
	}
	if len(cfg.Paths) == 0 {
		return nil, fmt.Errorf("WorkOS authentication requires an MCP endpoint")
	}
	a := &WorkOSAuth{
		issuer: issuer.String(), emailDomain: domain,
		usernamePrefix: cfg.UsernamePrefix, groupsPrefix: cfg.GroupsPrefix,
		resources: make(map[string]*workOSResource), client: client,
		profiles: make(map[[32]byte]workOSProfile),
	}
	keyClient := *client
	keyClient.Transport = &workOSKeyRefreshLimit{base: client.Transport, limit: rate.NewLimiter(rate.Every(workOSKeyRefreshInterval), 1)}
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), &keyClient), a.issuer+"/oauth2/jwks")
	for _, path := range cfg.Paths {
		resource := public.String() + path
		a.resources[path] = &workOSResource{
			url:         resource,
			metadataURL: public.Scheme + "://" + public.Host + "/.well-known/oauth-protected-resource" + public.Path + path,
			verifier:    oidc.NewVerifier(a.issuer, keys, &oidc.Config{ClientID: resource, SupportedSigningAlgs: []string{oidc.RS256}}),
		}
	}
	return a, nil
}

type workOSKeyRefreshLimit struct {
	base  http.RoundTripper
	limit *rate.Limiter
}

func (l *workOSKeyRefreshLimit) RoundTrip(r *http.Request) (*http.Response, error) {
	if !l.limit.Allow() {
		return nil, errors.New("WorkOS key refresh rate limited")
	}
	return l.base.RoundTrip(r)
}

func workOSHTTPSURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("invalid HTTPS URL")
	}
	return u, nil
}

// MetadataPaths maps origin-relative protected resource metadata paths to
// their handlers. They belong at the origin root, outside any base path.
func (a *WorkOSAuth) MetadataPaths() map[string]http.Handler {
	routes := make(map[string]http.Handler)
	for _, resource := range a.resources {
		u, _ := url.Parse(resource.metadataURL)
		routes[u.Path] = mcpauth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
			Resource: resource.url, AuthorizationServers: []string{a.issuer},
			ScopesSupported:        append(slices.Clone(workOSScopes), "profile", "offline_access"),
			BearerMethodsSupported: []string{"header"},
		})
	}
	return routes
}

// Handles reports whether path is an MCP endpoint WorkOS authenticates.
func (a *WorkOSAuth) Handles(path string) bool { return a.resources[path] != nil }

// Middleware requires a WorkOS access token for the MCP endpoint at path and
// runs next as the token's user. Caller credentials never reach next.
func (a *WorkOSAuth) Middleware(path string, next http.Handler) http.Handler {
	resource := a.resources[path]
	verify := func(ctx context.Context, raw string, _ *http.Request) (*mcpauth.TokenInfo, error) {
		return a.verify(ctx, resource, raw)
	}
	return mcpauth.RequireBearerToken(verify, &mcpauth.RequireBearerTokenOptions{
		ResourceMetadataURL: resource.metadataURL, Scopes: workOSScopes,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := mcpauth.TokenInfoFromContext(r.Context()).Extra["user"].(*User)
		r = r.Clone(ContextWithUser(r.Context(), user))
		r.Header.Del("Authorization")
		r.Header.Del("Cookie")
		next.ServeHTTP(w, r)
	}))
}

func (a *WorkOSAuth) verify(ctx context.Context, resource *workOSResource, raw string) (*mcpauth.TokenInfo, error) {
	token, err := resource.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, mcpauth.ErrInvalidToken
	}
	var claims struct {
		ClientID string `json:"client_id"`
		SID      string `json:"sid"`
		Scope    string `json:"scope"`
	}
	if token.Claims(&claims) != nil || !strings.HasPrefix(token.Subject, "user_") || claims.ClientID == "" || claims.SID == "" {
		return nil, mcpauth.ErrInvalidToken
	}
	scopes := strings.Fields(claims.Scope)
	for _, scope := range workOSScopes {
		if !slices.Contains(scopes, scope) {
			return nil, mcpauth.ErrInvalidToken
		}
	}
	user, err := a.profile(ctx, raw, token.Subject, token.Expiry)
	if err != nil {
		return nil, mcpauth.ErrInvalidToken
	}
	return &mcpauth.TokenInfo{
		UserID: token.Subject, Scopes: scopes, Expiration: token.Expiry,
		Extra: map[string]any{"user": user},
	}, nil
}

// profile resolves the token's verified email through AuthKit's userinfo
// endpoint, caching the result until the token expires.
func (a *WorkOSAuth) profile(ctx context.Context, raw, subject string, expires time.Time) (*User, error) {
	key := sha256.Sum256([]byte(raw))
	now := time.Now()
	a.mu.Lock()
	cached, ok := a.profiles[key]
	a.mu.Unlock()
	if ok && now.Before(cached.expires) {
		user := cached.user
		user.Groups = slices.Clone(user.Groups)
		return &user, nil
	}
	body, err := a.request(ctx, http.MethodPost, a.issuer+"/oauth2/userinfo", raw)
	var info struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err != nil || json.Unmarshal(body, &info) != nil {
		return nil, fmt.Errorf("WorkOS userinfo unavailable")
	}
	email := strings.ToLower(info.Email)
	local, domain, _ := strings.Cut(email, "@")
	if info.Subject != subject || !info.EmailVerified || local == "" || domain != a.emailDomain {
		return nil, fmt.Errorf("WorkOS user is not allowed")
	}
	user := User{Username: a.usernamePrefix + email, Groups: []string{a.groupsPrefix + domain}}
	if !ForwardedIdentityAllowed(user.Username, user.Groups, false) {
		return nil, fmt.Errorf("WorkOS user maps to a reserved Kubernetes identity")
	}
	a.mu.Lock()
	for k, p := range a.profiles {
		if !now.Before(p.expires) {
			delete(a.profiles, k)
		}
	}
	if len(a.profiles) < workOSProfileCacheLimit {
		a.profiles[key] = workOSProfile{user: user, expires: expires}
	}
	a.mu.Unlock()
	user.Groups = slices.Clone(user.Groups)
	return &user, nil
}

func (a *WorkOSAuth) request(ctx context.Context, method, target, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("WorkOS request failed: %s", resp.Status)
	}
	const maxBody = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return nil, fmt.Errorf("invalid WorkOS response")
	}
	return body, nil
}
