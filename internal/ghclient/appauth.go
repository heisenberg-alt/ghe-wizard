package ghclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AppAuth mints GitHub App installation tokens and refreshes them before
// expiry. It implements TokenProvider and is safe for concurrent use. The JWT
// is hand-rolled with the standard library (RS256) to keep the project
// dependency-free.
type AppAuth struct {
	appID          int64
	installationID int64
	key            *rsa.PrivateKey
	apiBase        string
	http           *http.Client
	now            func() time.Time // test hook

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// appTokenRefreshMargin is how long before expiry a cached token is renewed.
const appTokenRefreshMargin = 5 * time.Minute

// NewAppAuth parses the PEM private key and returns an installation-token
// provider. apiBase defaults to the public GitHub API when empty.
func NewAppAuth(appID, installationID int64, pemKey []byte, apiBase string) (*AppAuth, error) {
	if appID == 0 || installationID == 0 {
		return nil, errors.New("github app auth requires both an app ID and an installation ID")
	}
	key, err := parseRSAPrivateKey(pemKey)
	if err != nil {
		return nil, err
	}
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	return &AppAuth{
		appID:          appID,
		installationID: installationID,
		key:            key,
		apiBase:        strings.TrimRight(apiBase, "/"),
		http:           &http.Client{Timeout: 30 * time.Second},
		now:            time.Now,
	}, nil
}

// parseRSAPrivateKey accepts both PKCS#1 ("RSA PRIVATE KEY", as GitHub ships)
// and PKCS#8 ("PRIVATE KEY", e.g. after openssl conversion) PEM blocks.
func parseRSAPrivateKey(pemKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, errors.New("app private key: no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("app private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("app private key: not an RSA key")
	}
	return key, nil
}

// Token returns a valid installation token, minting or refreshing as needed.
func (a *AppAuth) Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token != "" && a.now().Before(a.expiry.Add(-appTokenRefreshMargin)) {
		return a.token, nil
	}
	tok, exp, err := a.exchange(ctx)
	if err != nil {
		return "", err
	}
	a.token, a.expiry = tok, exp
	return tok, nil
}

// mintJWT builds the short-lived RS256 app JWT used to mint installation
// tokens: iat is backdated 60s for clock drift, exp stays under GitHub's
// 10-minute ceiling.
func (a *AppAuth) mintJWT() (string, error) {
	now := a.now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(a.appID, 10),
	})
	if err != nil {
		return "", err
	}
	signing := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign app JWT: %w", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (a *AppAuth) exchange(ctx context.Context) (string, time.Time, error) {
	jwt, err := a.mintJWT()
	if err != nil {
		return "", time.Time{}, err
	}
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", a.apiBase, a.installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := a.http.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return "", time.Time{}, errors.New("app token exchange rejected (401): check the app ID and private key")
	case resp.StatusCode == http.StatusNotFound:
		return "", time.Time{}, errors.New("app installation not found (404): check the installation ID and that the app is installed for your enterprise/organizations")
	case resp.StatusCode >= 400:
		return "", time.Time{}, fmt.Errorf("app token exchange failed (%d): %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("decode app token response: %w", err)
	}
	if out.Token == "" {
		return "", time.Time{}, errors.New("app token exchange returned an empty token")
	}
	if out.ExpiresAt.IsZero() {
		// GitHub installation tokens live one hour; be conservative if absent.
		out.ExpiresAt = a.now().Add(time.Hour)
	}
	return out.Token, out.ExpiresAt, nil
}
