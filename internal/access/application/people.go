package application

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	accessapi "organon/internal/access/api"
	"organon/internal/access/domain"
	"organon/internal/kernel"
	schemaapi "organon/internal/schema/api"
)

// Delegated user management (ADR 0030): the built-in people actions of
// the user type. The Authorizer decides them first (auth.people); every
// operation checks again here, so the admin HTTP routes and the actions
// follow the same rule.

// mayManage allows admins, and people managers for users they manage.
func (s *AuthService) mayManage(actor accessapi.Principal, id kernel.ID, data map[string]any, action string, input map[string]any) error {
	if isAdmin(actor) {
		return nil
	}
	if s.cfg.People.Allows(actor.ID.String(), actor.Roles, action, domain.TargetOf(id.String(), data), input) {
		return nil
	}
	return kernel.ErrForbidden
}

// auditUser records an account operation on a user.
func (s *AuthService) auditUser(ctx context.Context, actor accessapi.Principal, action string, target kernel.ID, detail string) {
	if s.cfg.Audit == nil {
		return
	}
	if detail == "" {
		detail = "for " + target.String()
	}
	kind := string(actor.Kind)
	if kind == "" {
		kind = string(accessapi.KindUser)
	}
	t := target
	_ = s.cfg.Audit(ctx, []kernel.AuditRecord{{At: s.clock.Now(), Actor: actor.ID, ActorKind: kind, Action: action,
		Target: &t, Type: "user", Detail: detail}})
}

// PeopleInputs returns the input schemas of the people actions, for the
// end-user UI and validation.
func (s *AuthService) PeopleInputs() map[string]json.RawMessage {
	roles := s.cfg.People.AllAssignable()
	if roles == nil {
		roles = s.knownRoles()
	}
	return domain.PeopleInputs(roles, s.cfg.MinPasswordLength)
}

// knownRoles are the app roles an admin may assign, sorted.
func (s *AuthService) knownRoles() []string {
	out := []string{}
	for r := range s.cfg.Roles {
		out = append(out, r)
	}
	if !s.cfg.NoAdmins && !slices.Contains(out, "admin") {
		out = append(out, "admin")
	}
	slices.Sort(out)
	return out
}

// target loads a user (not a service account) for a people action.
func (s *AuthService) target(ctx context.Context, id kernel.ID) (map[string]any, kernel.Version, error) {
	f, err := s.reader.Get(ctx, id)
	if err != nil {
		return nil, 0, err
	}
	if f.Type.Base() != schemaapi.TypeUser {
		return nil, 0, kernel.NewError(kernel.CodeBadRequest, "people actions apply to users")
	}
	return f.Data, f.Version, nil
}

// SetRoles replaces a user's roles. A user whose new roles need MFA and
// who has no authenticator is signed out, so they enroll at the next
// sign-in.
func (s *AuthService) SetRoles(ctx context.Context, actor accessapi.Principal, id kernel.ID, roles []string) error {
	data, version, err := s.target(ctx, id)
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		return kernel.NewValidationError(kernel.FieldError{Path: "/role", Code: "required", Message: "a role is required"})
	}
	input := map[string]any{"role": roles[0]}
	if err := s.mayManage(actor, id, data, domain.ActSetRole, input); err != nil {
		return err
	}
	if !isAdmin(actor) && !s.cfg.People.MayAssign(actor.Roles, roles) {
		return kernel.ErrForbidden
	}
	if isAdmin(actor) {
		known := s.knownRoles()
		for _, r := range roles {
			if !slices.Contains(known, r) {
				return kernel.NewValidationError(kernel.FieldError{Path: "/role", Code: "enum", Message: "unknown role " + r})
			}
		}
	}
	if s.cfg.NoAdmins && slices.Contains(roles, "admin") {
		return ErrAdminsDisabled
	}
	old := domain.TargetOf(id.String(), data).Roles
	vals := make([]any, len(roles))
	for i, r := range roles {
		vals[i] = r
	}
	if err := s.writer.Update(ctx, "user", id, version, map[string]any{"roles": vals}); err != nil {
		return err
	}
	if s.mfaRequired(accessapi.Principal{Kind: accessapi.KindUser, Roles: roles}) {
		if t, err := s.store.TOTP(ctx, id); err != nil || !t.Confirmed {
			_ = s.store.DeleteSessionsOf(ctx, id)
		}
	}
	s.auditUser(ctx, actor, "roles_set", id, "for "+id.String()+": "+strings.Join(old, ",")+" -> "+strings.Join(roles, ","))
	return nil
}

// SetStatus suspends (and signs out) or reactivates a user.
func (s *AuthService) SetStatus(ctx context.Context, actor accessapi.Principal, id kernel.ID, status string) error {
	action, event := domain.ActSuspend, "user_suspended"
	switch status {
	case "suspended":
	case "active":
		action, event = domain.ActReactivate, "user_reactivated"
	default:
		return kernel.NewValidationError(kernel.FieldError{Path: "/status", Code: "enum", Message: "status is active or suspended"})
	}
	data, version, err := s.target(ctx, id)
	if err != nil {
		return err
	}
	if err := s.mayManage(actor, id, data, action, nil); err != nil {
		return err
	}
	if actor.ID == id && status == "suspended" {
		return kernel.NewError(kernel.CodeForbidden, "you cannot suspend yourself")
	}
	if cur, _ := data["status"].(string); cur == status || (cur == "" && status == "active") {
		return kernel.NewError(kernel.CodeConflict, "the user is already %s", status)
	}
	if err := s.writer.Update(ctx, "user", id, version, map[string]any{"status": status}); err != nil {
		return err
	}
	if status == "suspended" {
		if err := s.store.DeleteSessionsOf(ctx, id); err != nil {
			return err
		}
	}
	s.auditUser(ctx, actor, event, id, "")
	return nil
}

// PeopleAction runs a built-in people action on user id. For addUser, id
// is the caller's own user and the output is the new user's id.
func (s *AuthService) PeopleAction(ctx context.Context, actor accessapi.Principal, id kernel.ID, action string, input map[string]any) (any, error) {
	str := func(k string) string { v, _ := input[k].(string); return strings.TrimSpace(v) }
	allowed := map[string][]string{domain.ActAddUser: {"displayName", "email", "password", "role"}, domain.ActSetRole: {"role"},
		domain.ActSetPassword: {"password"}}
	for k := range input {
		if !slices.Contains(allowed[action], k) {
			return nil, kernel.NewValidationError(kernel.FieldError{Path: "/" + k, Code: "additionalProperties", Message: "unknown field " + k})
		}
	}
	switch action {
	case domain.ActAddUser:
		if !isAdmin(actor) && actor.ID != id {
			return nil, kernel.ErrForbidden
		}
		var errs []kernel.FieldError
		if str("displayName") == "" {
			errs = append(errs, kernel.FieldError{Path: "/displayName", Code: "required", Message: "a name is required"})
		}
		if e := str("email"); e == "" || !strings.Contains(e, "@") || strings.ContainsAny(e, " \t\r\n") {
			errs = append(errs, kernel.FieldError{Path: "/email", Code: "format", Message: "a valid email is required"})
		}
		if str("role") == "" {
			errs = append(errs, kernel.FieldError{Path: "/role", Code: "required", Message: "a role is required"})
		}
		if len(errs) > 0 {
			return nil, kernel.NewValidationError(errs...)
		}
		if isAdmin(actor) && !slices.Contains(s.knownRoles(), str("role")) {
			return nil, kernel.NewValidationError(kernel.FieldError{Path: "/role", Code: "enum", Message: "unknown role"})
		}
		pw, _ := input["password"].(string)
		nid, err := s.CreateUser(ctx, actor, NewUser{Email: str("email"), DisplayName: str("displayName"), Password: pw,
			Roles: []string{str("role")}})
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": nid.String()}, nil
	case domain.ActSetRole:
		return nil, s.SetRoles(ctx, actor, id, []string{str("role")})
	case domain.ActSuspend:
		return nil, s.SetStatus(ctx, actor, id, "suspended")
	case domain.ActReactivate:
		return nil, s.SetStatus(ctx, actor, id, "active")
	case domain.ActSetPassword:
		pw, _ := input["password"].(string)
		if _, _, err := s.target(ctx, id); err != nil {
			return nil, err
		}
		return nil, s.SetPassword(ctx, actor, id, pw)
	case domain.ActResetMFA:
		if _, _, err := s.target(ctx, id); err != nil {
			return nil, err
		}
		return nil, s.ResetMFA(ctx, actor, id)
	case domain.ActSignOutEverywhere:
		if _, _, err := s.target(ctx, id); err != nil {
			return nil, err
		}
		return nil, s.SignOutEverywhere(ctx, actor, id)
	}
	return nil, kernel.NewError(kernel.CodeNotFound, "unknown action %q", action)
}
