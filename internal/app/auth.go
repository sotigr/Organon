package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	accessapp "organon/internal/access/application"
	accesscrypto "organon/internal/access/infrastructure/crypto"
	"organon/internal/access/infrastructure/oidc"
	"organon/internal/kernel"
	manifestdomain "organon/internal/manifest/domain"
	"organon/platform/config"
)

// wellKnownIssuers lets app.json name common providers without an issuer.
var wellKnownIssuers = map[string]string{
	"google": "https://accounts.google.com",
	"gitlab": "https://gitlab.com",
}

var providerName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// checkAuth validates app.json auth.oidc and auth.mfa (organon validate).
func checkAuth(a manifestdomain.AuthConfig, roles map[string][]string) []Problem {
	var probs []Problem
	seen := map[string]bool{}
	for i, p := range a.OIDC {
		ptr := fmt.Sprintf("/auth/oidc/%d", i)
		add := func(field, msg string) {
			probs = append(probs, Problem{File: "app.json", Pointer: ptr + field, Message: msg})
		}
		switch {
		case !providerName.MatchString(p.Provider):
			add("/provider", "provider names are lower-case letters, digits, and dashes")
		case seen[p.Provider]:
			add("/provider", "duplicate provider")
		}
		seen[p.Provider] = true
		if p.ClientID == "" {
			add("/clientId", "clientId is required")
		}
		if !strings.HasPrefix(p.ClientSecret, "${secret:") {
			add("/clientSecret", "clientSecret must be a ${secret:<name>} reference")
		}
		issuer := p.Issuer
		if issuer == "" {
			issuer = wellKnownIssuers[p.Provider]
		}
		if issuer == "" {
			add("/issuer", "issuer is required for provider "+p.Provider)
		} else if !strings.HasPrefix(issuer, "https://") && !strings.HasPrefix(issuer, "http://localhost") && !strings.HasPrefix(issuer, "http://127.0.0.1") {
			add("/issuer", "issuer must use https")
		}
	}
	for i, r := range a.MFA.RequiredForRoles {
		if _, ok := roles[r]; !ok {
			probs = append(probs, Problem{File: "app.json", Pointer: fmt.Sprintf("/auth/mfa/requiredForRoles/%d", i), Message: "unknown role " + r})
		}
	}
	probs = append(probs, checkPeople(a, roles)...)
	return append(probs, checkSession(a.Session)...)
}

// Bounds of auth.session.
const (
	maxSessionDays      = 3650
	defaultSessionDays  = 30
	defaultSessionHours = 24
)

// checkSession validates auth.session: positive values, at most ten years,
// and an idle timeout no longer than the lifetime.
func checkSession(s manifestdomain.SessionConfig) []Problem {
	var probs []Problem
	add := func(p, msg string) {
		probs = append(probs, Problem{File: "app.json", Pointer: "/auth/session/" + p, Message: msg})
	}
	if s.IdleHours < 0 {
		add("idleHours", "must be positive")
	}
	if s.MaxDays < 0 || s.MaxDays > maxSessionDays {
		add("maxDays", fmt.Sprintf("must be between 1 and %d", maxSessionDays))
	}
	idle, max := sessionDurations(s)
	if s.IdleHours > 0 && idle > max {
		add("idleHours", fmt.Sprintf("is longer than the session lifetime (%d days)", int(max.Hours()/24)))
	}
	return probs
}

// sessionDurations returns the idle timeout and lifetime of auth.session,
// with the defaults for unset values.
func sessionDurations(s manifestdomain.SessionConfig) (idle, max time.Duration) {
	idle, max = defaultSessionHours*time.Hour, defaultSessionDays*24*time.Hour
	if s.IdleHours > 0 {
		idle = time.Duration(s.IdleHours) * time.Hour
	}
	if s.MaxDays > 0 {
		max = time.Duration(s.MaxDays) * 24 * time.Hour
	}
	return idle, max
}

// checkPeople validates auth.people (ADR 0030): app roles only, never
// admin, and non-empty lists without duplicates. Managers without MFA
// get a warning.
func checkPeople(a manifestdomain.AuthConfig, roles map[string][]string) []Problem {
	var probs []Problem
	keys := make([]string, 0, len(a.People))
	for k := range a.People {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		ptr := "/auth/people/" + k
		add := func(p, msg string, warn bool) {
			probs = append(probs, Problem{File: "app.json", Pointer: p, Message: msg, Warning: warn})
		}
		switch _, ok := roles[k]; {
		case k == "admin":
			add(ptr, "admins already manage people; list other roles", false)
		case !ok:
			add(ptr, "unknown role "+k, false)
		case !a.MFA.RequiredForAll && !slices.Contains(a.MFA.RequiredForRoles, k):
			add(ptr, "people managers can reset passwords and MFA; consider listing "+k+" in auth.mfa.requiredForRoles", true)
		}
		list := a.People[k]
		if len(list) == 0 {
			add(ptr, "list the roles "+k+" may assign", false)
		}
		seen := map[string]bool{}
		for i, r := range list {
			p := fmt.Sprintf("%s/%d", ptr, i)
			_, ok := roles[r]
			switch {
			case r == "admin":
				add(p, "only admins assign the admin role", false)
			case !ok:
				add(p, "unknown role "+r, false)
			case seen[r]:
				add(p, "duplicate role "+r, false)
			}
			seen[r] = true
		}
	}
	return probs
}

// authConfig builds the authentication settings: MFA roles, the data key
// sealer for TOTP secrets, the OIDC state sealer, and OIDC providers whose
// calls go through the egress client.
func authConfig(cfg config.Config, c *Compiled, instanceKey []byte, secrets func(string) (string, bool), out oidc.HTTPDoer, clock kernel.Clock) (accessapp.AuthConfig, error) {
	a := c.Manifest.App.Auth
	ac := accessapp.AuthConfig{PasswordEnabled: a.Password.Enabled, MinPasswordLength: a.Password.MinLength,
		MFAAll: a.MFA.RequiredForAll, MFARoles: slices.Clone(a.MFA.RequiredForRoles), Issuer: c.Manifest.App.App,
		OIDC: map[string]accessapp.OIDCConfig{}}
	ac.SessionIdle, ac.SessionAbsolute = sessionDurations(a.Session)
	key, err := dataKey(cfg)
	if err != nil {
		return ac, err
	}
	if key != nil {
		if ac.Sealer, err = accesscrypto.NewSealer(key); err != nil {
			return ac, fmt.Errorf("secrets.dataKeyFile: %w", err)
		}
	}
	m := hmac.New(sha256.New, instanceKey)
	m.Write([]byte("oidc-state"))
	if ac.StateSealer, err = accesscrypto.NewSealer(m.Sum(nil)); err != nil {
		return ac, err
	}
	for _, p := range a.OIDC {
		secret, ok := secrets(p.ClientSecret)
		if !ok {
			return ac, fmt.Errorf("auth.oidc %s: secret %s is not set", p.Provider, p.ClientSecret)
		}
		issuer := p.Issuer
		if issuer == "" {
			issuer = wellKnownIssuers[p.Provider]
		}
		client := oidc.New(oidc.Config{Issuer: issuer, ClientID: p.ClientID, ClientSecret: secret, Scopes: p.Scopes}, out)
		client.Now = clock.Now
		ac.OIDC[p.Provider] = accessapp.OIDCConfig{Signup: p.Signup, AllowedDomains: p.AllowedDomains, Provider: client}
	}
	return ac, nil
}

// dataKey loads the instance data key (spec 8.2, 14.7): hex in a key file
// outside the database. Memory credential stores get a per-process key;
// without a key file, TOTP enrollment is unavailable.
func dataKey(cfg config.Config) ([]byte, error) {
	path := cfg.Secrets.DataKeyFile
	if path == "" {
		if cfg.Credentials.Driver == "memory" {
			k := make([]byte, 32)
			_, err := rand.Read(k)
			return k, err
		}
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) && cfg.Secrets.CreateDataKey {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(k)+"\n"), 0o600); err != nil {
			return nil, err
		}
		return k, nil
	}
	if err != nil {
		return nil, fmt.Errorf("secrets.dataKeyFile: %w", err)
	}
	k, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("secrets.dataKeyFile: want 64 hex characters (32 bytes)")
	}
	return k, nil
}
