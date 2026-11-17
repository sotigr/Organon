package e2e

import (
	"strings"
	"testing"
	"time"

	manifestdomain "organon/internal/manifest/domain"
)

// app.json auth.session sets the idle timeout and lifetime of sessions.
func TestSessionLifetime(t *testing.T) {
	s := startFull(t, "sqlite", nil, func(m *manifestdomain.Manifest) {
		m.App.Auth.Session = manifestdomain.SessionConfig{IdleHours: 24 * 60, MaxDays: 365}
	}, nil)
	admin := s.admin()
	ed := s.user(admin, "ed", "editor")

	// Fifty idle days: still signed in (the default would end it after 24 h).
	s.clock.Advance(50 * 24 * time.Hour)
	mustOK(t, ed.do("GET", "/v1/auth/session", nil), 200)
	// Active every 50 days, the session still ends after a year.
	for i := 0; i < 6; i++ {
		s.clock.Advance(50 * 24 * time.Hour)
		mustOK(t, ed.do("GET", "/v1/auth/session", nil), 200)
	}
	s.clock.Advance(20 * 24 * time.Hour)
	if r := ed.do("GET", "/v1/auth/session", nil); r.Status != 401 {
		t.Fatalf("after a year: %d", r.Status)
	}
	// Idle longer than idleHours ends a fresh session.
	ed = s.login("ed@example.com", "password-ed-123")
	s.clock.Advance(61 * 24 * time.Hour)
	if r := ed.do("GET", "/v1/auth/session", nil); r.Status != 401 {
		t.Fatalf("after 61 idle days: %d", r.Status)
	}
}

func TestSessionValidation(t *testing.T) {
	for name, c := range map[string]struct {
		s    manifestdomain.SessionConfig
		want string
	}{
		"negative idle":   {manifestdomain.SessionConfig{IdleHours: -1}, "/auth/session/idleHours"},
		"too long":        {manifestdomain.SessionConfig{MaxDays: 4000}, "/auth/session/maxDays"},
		"idle over limit": {manifestdomain.SessionConfig{IdleHours: 24 * 40, MaxDays: 30}, "longer than the session lifetime"},
	} {
		t.Run(name, func(t *testing.T) {
			m := trackerManifest(t)
			m.App.Auth.Session = c.s
			if _, err := compileManifest(m); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}
