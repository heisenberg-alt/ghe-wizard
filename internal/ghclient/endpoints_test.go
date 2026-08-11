package ghclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteEndpoints_SendCorrectRequests(t *testing.T) {
	type rec struct{ method, path, body string }
	var last rec
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		last = rec{r.Method, r.URL.Path, string(b)}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer ts.Close()
	c := New("tok", ts.URL, ts.URL+"/graphql")
	ctx := context.Background()

	cases := []struct {
		name         string
		call         func() error
		method, path string
		bodyContains []string
	}{
		{"org base permission",
			func() error { return c.SetOrgDefaultRepositoryPermission(ctx, "org1", "read") },
			"PATCH", "/orgs/org1",
			[]string{`"default_repository_permission":"read"`}},
		{"secret scanning defaults",
			func() error { return c.SetOrgSecretScanningDefaults(ctx, "org1", true) },
			"PATCH", "/orgs/org1",
			[]string{`"secret_scanning_enabled_for_new_repositories":true`,
				`"secret_scanning_push_protection_enabled_for_new_repositories":true`}},
		{"dependabot defaults",
			func() error { return c.SetOrgDependabotDefaults(ctx, "org1") },
			"PATCH", "/orgs/org1",
			[]string{`"dependency_graph_enabled_for_new_repositories":true`,
				`"dependabot_alerts_enabled_for_new_repositories":true`,
				`"dependabot_security_updates_enabled_for_new_repositories":true`}},
		{"public repo creation",
			func() error { return c.SetOrgMembersCanCreatePublicRepos(ctx, "org1", false) },
			"PATCH", "/orgs/org1",
			[]string{`"members_can_create_public_repositories":false`}},
		{"web commit signoff",
			func() error { return c.SetOrgWebCommitSignoff(ctx, "org1", true) },
			"PATCH", "/orgs/org1",
			[]string{`"web_commit_signoff_required":true`}},
		{"enterprise workflow permissions",
			func() error { return c.SetEnterpriseDefaultWorkflowPermissions(ctx, "acme", "read") },
			"PUT", "/enterprises/acme/actions/permissions/workflow",
			[]string{`"default_workflow_permissions":"read"`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err != nil {
				t.Fatal(err)
			}
			if last.method != tc.method || last.path != tc.path {
				t.Fatalf("request %s %s, want %s %s", last.method, last.path, tc.method, tc.path)
			}
			for _, want := range tc.bodyContains {
				if !strings.Contains(last.body, want) {
					t.Fatalf("body %q missing %q", last.body, want)
				}
			}
		})
	}
}

func TestEnterprise_ReadsActionsPolicies(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/graphql":
			_, _ = w.Write([]byte(`{"data":{"enterprise":{"name":"Acme","slug":"acme",
				"ownerInfo":{"defaultRepositoryPermissionSetting":"READ","ipAllowListEnabledSetting":"DISABLED","samlIdentityProvider":null}}}}`))
		case "/enterprises/acme/actions/permissions/workflow":
			_, _ = w.Write([]byte(`{"default_workflow_permissions":"write","can_approve_pull_request_reviews":false}`))
		case "/enterprises/acme/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled_organizations":"all","allowed_actions":"all"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	c := New("tok", ts.URL, ts.URL+"/graphql")
	ent, err := c.Enterprise(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	if ent.DefaultWorkflowPermissions != "write" {
		t.Fatalf("DefaultWorkflowPermissions = %q, want write", ent.DefaultWorkflowPermissions)
	}
	if ent.AllowedActions != "all" {
		t.Fatalf("AllowedActions = %q, want all", ent.AllowedActions)
	}
}

func TestServerMeta(t *testing.T) {
	t.Run("GHES", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/meta" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"installed_version":"3.14.2"}`))
		}))
		defer ts.Close()
		v, isGHES, err := New("tok", ts.URL, ts.URL+"/graphql").ServerMeta(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !isGHES || v != "3.14.2" {
			t.Fatalf("expected GHES 3.14.2, got isGHES=%v v=%q", isGHES, v)
		}
	})
	t.Run("cloud", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"verifiable_password_authentication":false}`))
		}))
		defer ts.Close()
		_, isGHES, err := New("tok", ts.URL, ts.URL+"/graphql").ServerMeta(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if isGHES {
			t.Fatal("cloud /meta must not detect GHES")
		}
	})
}

func TestAuditLogStreamEnabled(t *testing.T) {
	t.Run("streams configured", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/enterprises/acme/audit-log/streams" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":1,"stream_type":"Splunk"}]`))
		}))
		defer ts.Close()
		enabled, capb, err := New("tok", ts.URL, ts.URL+"/graphql").AuditLogStreamEnabled(context.Background(), "acme")
		if err != nil {
			t.Fatal(err)
		}
		if !capb.Determined || !enabled {
			t.Fatalf("expected determined+enabled, got %+v enabled=%v", capb, enabled)
		}
	})
	t.Run("none configured", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		}))
		defer ts.Close()
		enabled, capb, err := New("tok", ts.URL, ts.URL+"/graphql").AuditLogStreamEnabled(context.Background(), "acme")
		if err != nil {
			t.Fatal(err)
		}
		if !capb.Determined || enabled {
			t.Fatalf("expected determined+disabled, got %+v enabled=%v", capb, enabled)
		}
	})
	t.Run("endpoint unavailable", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		}))
		defer ts.Close()
		_, capb, err := New("tok", ts.URL, ts.URL+"/graphql").AuditLogStreamEnabled(context.Background(), "acme")
		if err != nil {
			t.Fatal(err)
		}
		if capb.Determined {
			t.Fatalf("unavailable endpoint should be undetermined, got %+v", capb)
		}
	})
}
