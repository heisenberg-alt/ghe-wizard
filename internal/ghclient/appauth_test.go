package ghclient

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testKeyPEM(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return key, pemBytes
}

// newExchangeServer returns a fake token-exchange endpoint that verifies the
// app JWT against pub and counts calls.
func newExchangeServer(t *testing.T, pub *rsa.PublicKey, calls *atomic.Int32, expiresAt time.Time) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/app/installations/456/access_tokens") {
			t.Errorf("unexpected exchange request: %s %s", r.Method, r.URL.Path)
		}
		jwt := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(jwt, ".")
		if len(parts) != 3 {
			t.Errorf("JWT should have 3 segments, got %d", len(parts))
			http.Error(w, "bad jwt", http.StatusUnauthorized)
			return
		}
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Errorf("decode signature: %v", err)
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Errorf("JWT signature does not verify: %v", err)
		}
		claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Errorf("decode claims: %v", err)
		}
		var claims struct {
			Iat int64  `json:"iat"`
			Exp int64  `json:"exp"`
			Iss string `json:"iss"`
		}
		if err := json.Unmarshal(claimsRaw, &claims); err != nil {
			t.Errorf("parse claims: %v", err)
		}
		if claims.Iss != "123" {
			t.Errorf("iss = %q, want 123", claims.Iss)
		}
		now := time.Now().Unix()
		if claims.Iat > now {
			t.Errorf("iat should be backdated, got %d > now %d", claims.Iat, now)
		}
		if claims.Exp > now+int64((10*time.Minute).Seconds()) {
			t.Errorf("exp exceeds GitHub's 10-minute ceiling: %d", claims.Exp)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"token":"ghs_test_%d","expires_at":%q}`, calls.Load(), expiresAt.UTC().Format(time.RFC3339))
	}))
}

func TestAppAuth_MintsVerifiableJWTAndCachesToken(t *testing.T) {
	key, pemBytes := testKeyPEM(t)
	var calls atomic.Int32
	ts := newExchangeServer(t, &key.PublicKey, &calls, time.Now().Add(time.Hour))
	defer ts.Close()

	a, err := NewAppAuth(123, 456, pemBytes, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	tok1, err := a.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok1 != "ghs_test_1" {
		t.Fatalf("token = %q", tok1)
	}
	tok2, err := a.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok2 != tok1 {
		t.Fatalf("second call should hit the cache, got %q vs %q", tok2, tok1)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("exchange called %d times, want 1", n)
	}
}

func TestAppAuth_RefreshesNearExpiry(t *testing.T) {
	key, pemBytes := testKeyPEM(t)
	var calls atomic.Int32
	// The issued token expires within the 5-minute refresh margin, so the
	// second Token() call must mint a fresh one.
	ts := newExchangeServer(t, &key.PublicKey, &calls, time.Now().Add(4*time.Minute))
	defer ts.Close()

	a, err := NewAppAuth(123, 456, pemBytes, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	tok, err := a.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "ghs_test_2" {
		t.Fatalf("expected refreshed token, got %q", tok)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("exchange called %d times, want 2", n)
	}
}

func TestAppAuth_ParsesPKCS8Keys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := NewAppAuth(1, 2, pemBytes, ""); err != nil {
		t.Fatalf("PKCS#8 key should parse: %v", err)
	}
}

func TestAppAuth_RejectsBadInput(t *testing.T) {
	_, pemBytes := testKeyPEM(t)
	if _, err := NewAppAuth(0, 2, pemBytes, ""); err == nil {
		t.Fatal("missing app ID should error")
	}
	if _, err := NewAppAuth(1, 0, pemBytes, ""); err == nil {
		t.Fatal("missing installation ID should error")
	}
	if _, err := NewAppAuth(1, 2, []byte("not a key"), ""); err == nil {
		t.Fatal("malformed PEM should error")
	}
}

func TestClientSendsProviderToken(t *testing.T) {
	var got atomic.Value
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	c := NewWithAuth(StaticToken("tok-123"), ts.URL, ts.URL+"/graphql")
	if _, err := c.rest(context.Background(), http.MethodGet, "/anything", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got.Load() != "Bearer tok-123" {
		t.Fatalf("Authorization = %v, want Bearer tok-123", got.Load())
	}
	if err := c.graphql(context.Background(), "query{}", nil, nil); err != nil {
		t.Fatal(err)
	}
	if got.Load() != "Bearer tok-123" {
		t.Fatalf("GraphQL Authorization = %v", got.Load())
	}
}
