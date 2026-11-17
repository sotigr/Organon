package e2e

import (
	"strings"
	"testing"

	"organon/internal/app"
	manifestdomain "organon/internal/manifest/domain"
	manifestfs "organon/internal/manifest/infrastructure/fs"
	"organon/platform/config"
)

// ADR 0030: app.json auth.people lets non-admins manage users through the
// built-in people actions of the user type, within the roles they may
// assign, never on themselves or on admins, and never through generic
// writes.
func TestPeopleManagers(t *testing.T) {
	s := startFull(t, "sqlite", nil, func(m *manifestdomain.Manifest) {
		m.App.Roles["lead"] = []string{"editor"}
		m.App.Auth.People = map[string][]string{"lead": {"viewer", "editor", "lead"}}
	}, func(c *config.Config) {
		c.Secrets.DataKeyFile, c.Secrets.CreateDataKey = t.TempDir()+"/data.key", true
	})
	admin := s.admin()
	anon := s.anon()
	lead := s.user(admin, "lea", "lead")
	ed := s.user(admin, "ed", "editor")
	act := func(c *client, id, name string, input map[string]any) resp {
		if input == nil {
			input = map[string]any{}
		}
		return c.do("POST", "/v1/actions/user/"+id+"/"+name, input)
	}
	login := func(email, pw string) resp {
		return anon.do("POST", "/v1/auth/password", map[string]any{"login": email, "password": pw, "cli": true})
	}

	// Adding a user runs on the caller's own record, with an assignable role.
	add := func(c *client, on, name, role string) resp {
		return act(c, on, "addUser", map[string]any{"displayName": name, "email": name + "@example.com",
			"password": "password-" + name + "-123", "role": role})
	}
	if r := add(lead, lead.id, "adam", "admin"); r.Status != 403 {
		t.Fatalf("lead adds an admin: %d %s", r.Status, r.Raw)
	}
	if r := add(lead, ed.id, "vic", "viewer"); r.Status != 403 {
		t.Fatalf("addUser on another record: %d %s", r.Status, r.Raw)
	}
	if r := add(ed, ed.id, "vic", "viewer"); r.Status != 403 {
		t.Fatalf("editor adds a user: %d %s", r.Status, r.Raw)
	}
	if r := act(lead, lead.id, "addUser", map[string]any{"displayName": "Vic", "email": "vic@example.com", "password": "short", "role": "viewer"}); r.Status != 400 {
		t.Fatalf("short password: %d %s", r.Status, r.Raw)
	}
	if r := act(lead, lead.id, "addUser", map[string]any{"email": "vic@example.com", "password": "password-vic-123", "role": "viewer", "roles": []string{"admin"}}); r.Status != 400 {
		t.Fatalf("unknown input field: %d %s", r.Status, r.Raw)
	}
	vic := mustOK(t, add(lead, lead.id, "vic", "viewer"), 200).str("output", "id")
	if vic == "" {
		t.Fatal("addUser returned no id")
	}
	vicC := s.login("vic@example.com", "password-vic-123")

	// Managers read the email, roles, and status of users they manage; not of
	// admins, and members never see them.
	if u := mustOK(t, lead.do("GET", "/v1/features/user/"+vic, nil), 200); u.str("data", "email") != "vic@example.com" || !strings.Contains(u.Raw, `"roles":["viewer"]`) {
		t.Fatalf("lead reads vic: %s", u.Raw)
	}
	if u := mustOK(t, lead.do("GET", "/v1/features/user/"+admin.id, nil), 200); u.str("data", "email") != "" {
		t.Fatalf("lead reads the admin's email: %s", u.Raw)
	}
	if u := mustOK(t, ed.do("GET", "/v1/features/user/"+vic, nil), 200); u.str("data", "email") != "" {
		t.Fatalf("editor reads vic's email: %s", u.Raw)
	}

	// Lists apply the same audiences row by row.
	list := mustOK(t, lead.do("POST", "/v1/query", map[string]any{"type": "user", "limit": 50}), 200)
	if !strings.Contains(list.Raw, "vic@example.com") || !strings.Contains(list.Raw, "ed@example.com") || strings.Contains(list.Raw, adminEmail) {
		t.Fatalf("lead lists users: %s", list.Raw)
	}
	if list := mustOK(t, ed.do("POST", "/v1/query", map[string]any{"type": "user", "limit": 50}), 200); strings.Contains(list.Raw, "vic@example.com") {
		t.Fatalf("editor lists emails: %s", list.Raw)
	}

	// can() answers from the same rule.
	perms := mustOK(t, lead.do("POST", "/v1/permissions", map[string]any{"checks": []map[string]any{
		{"id": lead.id, "op": "action:addUser"}, {"id": vic, "op": "action:suspend"}, {"id": vic, "op": "action:reactivate"},
		{"id": admin.id, "op": "action:setRole"}, {"id": lead.id, "op": "action:suspend"}, {"id": vic, "op": "action:setPassword"}}}), 200)
	if !strings.Contains(perms.Raw, `[true,true,false,false,false,true]`) {
		t.Fatalf("lead permissions: %s", perms.Raw)
	}
	if r := mustOK(t, ed.do("POST", "/v1/permissions", map[string]any{"checks": []map[string]any{
		{"id": ed.id, "op": "action:addUser"}, {"id": vic, "op": "action:suspend"}}}), 200); !strings.Contains(r.Raw, `[false,false]`) {
		t.Fatalf("editor permissions: %s", r.Raw)
	}

	// Roles change only through setRole, within the assignable roles.
	if r := lead.do("PATCH", "/v1/features/user/"+vic, map[string]any{"roles": []string{"admin"}}, "If-Match", `"1"`); r.Status < 400 {
		t.Fatalf("generic role write: %d %s", r.Status, r.Raw)
	}
	if r := lead.do("PATCH", "/v1/features/user/"+vic, map[string]any{"status": "suspended"}, "If-Match", `"1"`); r.Status < 400 {
		t.Fatalf("generic status write: %d %s", r.Status, r.Raw)
	}
	if r := act(lead, vic, "setRole", map[string]any{"role": "admin"}); r.Status != 403 {
		t.Fatalf("setRole admin: %d %s", r.Status, r.Raw)
	}
	if r := act(lead, admin.id, "setRole", map[string]any{"role": "viewer"}); r.Status != 403 {
		t.Fatalf("setRole on the admin: %d %s", r.Status, r.Raw)
	}
	if r := act(lead, lead.id, "setRole", map[string]any{"role": "viewer"}); r.Status != 403 {
		t.Fatalf("setRole on oneself: %d %s", r.Status, r.Raw)
	}
	mustOK(t, act(lead, vic, "setRole", map[string]any{"role": "editor"}), 200)
	if u := mustOK(t, admin.do("GET", "/v1/features/user/"+vic, nil), 200); !strings.Contains(u.Raw, `"roles":["editor"]`) {
		t.Fatalf("after setRole: %s", u.Raw)
	}

	// Suspension signs the user out and blocks sign-in until reactivated.
	if r := act(lead, lead.id, "suspend", nil); r.Status != 403 {
		t.Fatalf("suspend oneself: %d %s", r.Status, r.Raw)
	}
	mustOK(t, act(lead, vic, "suspend", nil), 200)
	if r := vicC.do("GET", "/v1/auth/session", nil); r.Status != 401 {
		t.Fatalf("suspended session: %d", r.Status)
	}
	if r := login("vic@example.com", "password-vic-123"); r.Status == 200 {
		t.Fatalf("suspended sign-in: %s", r.Raw)
	}
	if r := act(lead, vic, "suspend", nil); r.Status != 403 {
		t.Fatalf("suspend twice: %d", r.Status)
	}
	mustOK(t, act(lead, vic, "reactivate", nil), 200)
	vicC = s.login("vic@example.com", "password-vic-123")

	// Password, MFA, and sessions.
	if r := act(ed, vic, "setPassword", map[string]any{"password": "password-vic-456"}); r.Status != 403 {
		t.Fatalf("editor sets a password: %d", r.Status)
	}
	mustOK(t, act(lead, vic, "setPassword", map[string]any{"password": "password-vic-456"}), 200)
	if r := vicC.do("GET", "/v1/auth/session", nil); r.Status != 401 {
		t.Fatalf("session after a new password: %d", r.Status)
	}
	vicC = s.login("vic@example.com", "password-vic-456")
	en := mustOK(t, vicC.do("POST", "/v1/auth/mfa/totp/enroll", map[string]any{}), 200)
	mustOK(t, vicC.do("POST", "/v1/auth/mfa/totp/confirm", map[string]any{"code": totpNow(t, s, en.str("secret"))}), 204)
	mustOK(t, act(lead, vic, "resetMfa", nil), 200)
	if r := login("vic@example.com", "password-vic-456"); r.str("token") == "" {
		t.Fatalf("login after MFA reset: %s", r.Raw)
	}
	vicC = s.login("vic@example.com", "password-vic-456")
	mustOK(t, act(lead, vic, "signOutEverywhere", nil), 200)
	if r := vicC.do("GET", "/v1/auth/session", nil); r.Status != 401 {
		t.Fatalf("session after sign-out everywhere: %d", r.Status)
	}

	// The admin HTTP routes follow the same rule.
	if r := lead.do("POST", "/v1/auth/users/"+admin.id+"/password", map[string]any{"password": "password-hijack-123"}); r.Status != 403 {
		t.Fatalf("lead resets the admin's password: %d", r.Status)
	}
	if r := lead.do("POST", "/v1/auth/users", map[string]any{"email": "x@example.com", "password": "password-x-1234", "roles": []string{"admin"}}); r.Status != 403 {
		t.Fatalf("lead creates an admin over HTTP: %d", r.Status)
	}

	// Admins use the same actions on anyone.
	mustOK(t, act(admin, lead.id, "setRole", map[string]any{"role": "editor"}), 200)

	// Audited with the user as the target.
	audit := mustOK(t, admin.do("GET", "/v1/audit?limit=200", nil), 200)
	for _, a := range []string{"user_created", "roles_set", "user_suspended", "user_reactivated", "password_set", "mfa_reset", "sessions_revoked"} {
		if !strings.Contains(audit.Raw, a) {
			t.Errorf("audit lacks %s", a)
		}
	}
}

// ADR 0030: auth.people is validated, and apps cannot redefine the
// people actions.
func TestPeopleValidation(t *testing.T) {
	for name, c := range map[string]struct {
		people map[string][]string
		want   string
	}{
		"admin key":     {map[string][]string{"admin": {"viewer"}}, "/auth/people/admin"},
		"admin value":   {map[string][]string{"editor": {"admin"}}, "/auth/people/editor/0"},
		"unknown key":   {map[string][]string{"boss": {"viewer"}}, "unknown role boss"},
		"unknown value": {map[string][]string{"editor": {"ghost"}}, "unknown role ghost"},
		"empty":         {map[string][]string{"editor": {}}, "list the roles"},
	} {
		t.Run(name, func(t *testing.T) {
			m := trackerManifest(t)
			m.App.Auth.People = c.people
			_, err := compileManifest(m)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
	m := trackerManifest(t)
	m.Policies = append(m.Policies, manifestdomain.File{Path: "policies/user.json",
		Data: []byte(`{"type": "urn:sys:feature:user", "read": "true", "actions": {"suspend": "true"}}`)})
	if _, err := compileManifest(m); err == nil || !strings.Contains(err.Error(), "built-in user action") {
		t.Fatalf("policy defining suspend: %v", err)
	}
}

func trackerManifest(t *testing.T) *manifestdomain.Manifest {
	t.Helper()
	m, err := manifestfs.Load("../../examples/tracker", "dev")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func compileManifest(m *manifestdomain.Manifest) (*app.Compiled, error) { return app.Compile(m) }
