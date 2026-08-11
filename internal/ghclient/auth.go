package ghclient

import "context"

// TokenProvider supplies a bearer token for API requests. Implementations
// must be safe for concurrent use.
type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a fixed personal access token.
type StaticToken string

// Token returns the static token.
func (s StaticToken) Token(context.Context) (string, error) { return string(s), nil }
