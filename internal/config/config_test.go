package config

import (
	"strings"
	"testing"
)

func TestLoad_AppAuthEnv(t *testing.T) {
	t.Setenv("GHE_ENTERPRISE", "env-ent")
	t.Setenv("GHE_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GHE_APP_ID", "123")
	t.Setenv("GHE_APP_INSTALLATION_ID", "456")
	t.Setenv("GHE_APP_PRIVATE_KEY_PATH", "/keys/app.pem")
	t.Setenv("GHE_APP_PRIVATE_KEY", "")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enterprise != "env-ent" || cfg.AppID != 123 || cfg.AppInstallationID != 456 ||
		cfg.AppPrivateKeyPath != "/keys/app.pem" {
		t.Fatalf("env not applied: %+v", cfg)
	}
	if !cfg.HasAppAuth() {
		t.Fatal("HasAppAuth should be true with the complete triple")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("app-auth config should validate: %v", err)
	}
}

func TestLoad_BadAppIDErrors(t *testing.T) {
	t.Setenv("GHE_APP_ID", "not-a-number")
	if _, err := Load(""); err == nil {
		t.Fatal("non-numeric GHE_APP_ID should error")
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string // empty = valid
	}{
		{"token only", Config{Enterprise: "e", Token: "t"}, ""},
		{"app triple inline key", Config{Enterprise: "e", AppID: 1, AppInstallationID: 2, AppPrivateKey: "pem"}, ""},
		{"app triple key path", Config{Enterprise: "e", AppID: 1, AppInstallationID: 2, AppPrivateKeyPath: "/k.pem"}, ""},
		{"no credentials", Config{Enterprise: "e"}, "credentials"},
		{"partial app auth", Config{Enterprise: "e", AppID: 1}, "GHE_APP_INSTALLATION_ID"},
		{"partial app auth missing key", Config{Enterprise: "e", AppID: 1, AppInstallationID: 2}, "GHE_APP_PRIVATE_KEY"},
		{"no enterprise", Config{Token: "t"}, "enterprise"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %v should mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestDeriveEndpoints(t *testing.T) {
	cases := []struct {
		name              string
		cfg               Config
		wantBase, wantGQL string
		wantErr           bool
	}{
		{"empty server keeps defaults",
			Config{BaseURL: DefaultBaseURL, GraphQLURL: DefaultGraphQLURL},
			DefaultBaseURL, DefaultGraphQLURL, false},
		{"github.com keeps defaults",
			Config{Server: "github.com", BaseURL: DefaultBaseURL, GraphQLURL: DefaultGraphQLURL},
			DefaultBaseURL, DefaultGraphQLURL, false},
		{"data residency",
			Config{Server: "acme.ghe.com", BaseURL: DefaultBaseURL, GraphQLURL: DefaultGraphQLURL},
			"https://api.acme.ghe.com", "https://api.acme.ghe.com/graphql", false},
		{"GHES hostname",
			Config{Server: "github.example.internal", BaseURL: DefaultBaseURL, GraphQLURL: DefaultGraphQLURL},
			"https://github.example.internal/api/v3", "https://github.example.internal/api/graphql", false},
		{"scheme prefix stripped",
			Config{Server: "https://acme.ghe.com/", BaseURL: DefaultBaseURL, GraphQLURL: DefaultGraphQLURL},
			"https://api.acme.ghe.com", "https://api.acme.ghe.com/graphql", false},
		{"explicit base URL wins",
			Config{Server: "github.example.internal", BaseURL: "https://proxy.example/api", GraphQLURL: DefaultGraphQLURL},
			"https://proxy.example/api", "https://github.example.internal/api/graphql", false},
		{"path in server rejected",
			Config{Server: "example.com/api/v3"},
			"", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.DeriveEndpoints()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.cfg.BaseURL != tc.wantBase || tc.cfg.GraphQLURL != tc.wantGQL {
				t.Fatalf("derived (%q, %q), want (%q, %q)",
					tc.cfg.BaseURL, tc.cfg.GraphQLURL, tc.wantBase, tc.wantGQL)
			}
		})
	}
}

func TestAppPrivateKeyPEM_InlineWins(t *testing.T) {
	cfg := Config{AppPrivateKey: "inline-pem", AppPrivateKeyPath: "/does/not/exist.pem"}
	b, err := cfg.AppPrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "inline-pem" {
		t.Fatalf("inline key should win, got %q", b)
	}
	cfg = Config{AppPrivateKeyPath: "/does/not/exist.pem"}
	if _, err := cfg.AppPrivateKeyPEM(); err == nil {
		t.Fatal("missing key file should error")
	}
}
