package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	testWorkOSIssuer = "https://auth.example.com"
	testWorkOSPublic = "https://radar.example.com"
)

type workOSFake struct {
	t        *testing.T
	key      *rsa.PrivateKey
	profile  string
	userinfo int
}

func (f *workOSFake) RoundTrip(r *http.Request) (*http.Response, error) {
	body := ""
	switch r.URL.String() {
	case testWorkOSIssuer + "/oauth2/jwks":
		jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
		body = string(jwks)
	case testWorkOSIssuer + "/oauth2/userinfo":
		f.userinfo++
		body = f.profile
	default:
		f.t.Fatalf("unexpected WorkOS request %s", r.URL)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func newTestWorkOS(t *testing.T) (*WorkOSAuth, *workOSFake) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fake := &workOSFake{t: t, key: key, profile: `{"sub":"user_1","email":"Dev@Example.com","email_verified":true}`}
	a, err := newWorkOSAuth(WorkOSConfig{
		AuthKitDomain: testWorkOSIssuer, PublicURL: testWorkOSPublic, AllowedEmailDomain: "example.com",
		UsernamePrefix: "radar:google:", GroupsPrefix: "radar:google:", Paths: []string{"/mcp", "/mcp-readonly"},
	}, &http.Client{Transport: fake})
	if err != nil {
		t.Fatal(err)
	}
	return a, fake
}

func (f *workOSFake) token(t *testing.T, changes map[string]any) string {
	t.Helper()
	claims := map[string]any{
		"iss": testWorkOSIssuer, "aud": testWorkOSPublic + "/mcp", "sub": "user_1",
		"client_id": "client_1", "sid": "session_1", "scope": "openid email offline_access",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	for k, v := range changes {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: f.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := jws.CompactSerialize()
	return raw
}

func serveMCP(a *WorkOSAuth, path, token string) (*httptest.ResponseRecorder, *http.Request) {
	var seen *http.Request
	h := a.Middleware(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r }))
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Cookie", "radar_session=x")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, seen
}

func TestWorkOSAdmitsVerifiedUserAsKubernetesIdentity(t *testing.T) {
	a, fake := newTestWorkOS(t)
	token := fake.token(t, nil)
	for range 2 {
		rec, seen := serveMCP(a, "/mcp", token)
		if rec.Code != http.StatusOK || seen == nil {
			t.Fatalf("status %d, want the request admitted", rec.Code)
		}
		user := UserFromContext(seen.Context())
		if user == nil || user.Username != "radar:google:dev@example.com" || len(user.Groups) != 1 || user.Groups[0] != "radar:google:example.com" {
			t.Fatalf("user %+v, want the Google browser identity", user)
		}
		if seen.Header.Get("Authorization") != "" || seen.Header.Get("Cookie") != "" {
			t.Fatal("caller credentials reached the MCP handler")
		}
	}
	if fake.userinfo != 1 {
		t.Fatalf("userinfo called %d times, want the profile cached for the token", fake.userinfo)
	}
}

func TestWorkOSRejectsTokensBeforeUserinfo(t *testing.T) {
	a, fake := newTestWorkOS(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string]string{
		"missing token":   "",
		"other audience":  fake.token(t, map[string]any{"aud": testWorkOSPublic + "/mcp-readonly"}),
		"other issuer":    fake.token(t, map[string]any{"iss": "https://other.example.com"}),
		"expired":         fake.token(t, map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}),
		"machine subject": fake.token(t, map[string]any{"sub": "client_1"}),
		"no session":      fake.token(t, map[string]any{"sid": nil}),
		"no email scope":  fake.token(t, map[string]any{"scope": "openid"}),
		"untrusted key":   (&workOSFake{t: t, key: other}).token(t, nil),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			rec, seen := serveMCP(a, "/mcp", token)
			if rec.Code == http.StatusOK || seen != nil {
				t.Fatalf("status %d, want rejection", rec.Code)
			}
			if !strings.Contains(rec.Header().Get("WWW-Authenticate"), `resource_metadata="https://radar.example.com/.well-known/oauth-protected-resource/mcp"`) {
				t.Fatalf("challenge %q lacks resource metadata", rec.Header().Get("WWW-Authenticate"))
			}
		})
	}
	if fake.userinfo != 0 {
		t.Fatalf("userinfo called %d times for invalid tokens", fake.userinfo)
	}
}

func TestWorkOSRejectsDisallowedProfiles(t *testing.T) {
	for name, profile := range map[string]string{
		"unverified email": `{"sub":"user_1","email":"dev@example.com","email_verified":false}`,
		"other domain":     `{"sub":"user_1","email":"dev@other.com","email_verified":true}`,
		"other subject":    `{"sub":"user_2","email":"dev@example.com","email_verified":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			a, fake := newTestWorkOS(t)
			fake.profile = profile
			if rec, seen := serveMCP(a, "/mcp", fake.token(t, nil)); rec.Code != http.StatusUnauthorized || seen != nil {
				t.Fatalf("status %d, want 401", rec.Code)
			}
		})
	}
}

func TestWorkOSPublishesResourceMetadata(t *testing.T) {
	a, _ := newTestWorkOS(t)
	h := a.MetadataPaths()["/.well-known/oauth-protected-resource/mcp-readonly"]
	if h == nil {
		t.Fatal("read-only resource metadata missing")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp-readonly", nil))
	var got struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Resource != testWorkOSPublic+"/mcp-readonly" || len(got.AuthorizationServers) != 1 || got.AuthorizationServers[0] != testWorkOSIssuer {
		t.Fatalf("metadata %s, want the read-only resource on AuthKit", rec.Body)
	}
}
