package domain

import (
	"encoding/json"
	"slices"
	"sort"
)

// Delegated user management (ADR 0030). app.json auth.people names the
// roles whose holders manage people and the roles each may assign:
//
//	"auth": { "people": { "manager": ["mechanic", "frontdesk", "manager"] } }
//
// A people manager runs the built-in people actions on users whose roles
// are all assignable by them, never on themselves (except signing out
// everywhere) and never on admins. Admins and the system are not limited
// by these rules.

// People actions, built into the system user type.
const (
	ActAddUser           = "addUser"
	ActSetRole           = "setRole"
	ActSuspend           = "suspend"
	ActReactivate        = "reactivate"
	ActSetPassword       = "setPassword"
	ActResetMFA          = "resetMfa"
	ActSignOutEverywhere = "signOutEverywhere"
)

// PeopleActions are the reserved action names of the user type.
var PeopleActions = []string{ActAddUser, ActSetRole, ActSuspend, ActReactivate, ActSetPassword, ActResetMFA, ActSignOutEverywhere}

// IsPeopleAction reports whether name is a built-in people action.
func IsPeopleAction(name string) bool { return slices.Contains(PeopleActions, name) }

// People is the compiled auth.people setting. A nil *People manages
// nobody: only admins manage users.
type People struct {
	assignable map[string][]string
	roles      *Roles
}

// NewPeople returns the rules for cfg, or nil when cfg is empty.
func NewPeople(cfg map[string][]string, roles *Roles) *People {
	if len(cfg) == 0 || roles == nil {
		return nil
	}
	return &People{assignable: cfg, roles: roles}
}

// PersonTarget is what the rules need to know about a user.
type PersonTarget struct {
	ID     string
	Roles  []string
	Status string
}

// TargetOf reads a user's id, roles, and status from its data.
func TargetOf(id string, data map[string]any) PersonTarget {
	t := PersonTarget{ID: id}
	if t.ID == "" {
		t.ID, _ = data["id"].(string)
	}
	t.Status, _ = data["status"].(string)
	switch rs := data["roles"].(type) {
	case []string:
		t.Roles = slices.Clone(rs)
	case []any:
		for _, r := range rs {
			if s, ok := r.(string); ok {
				t.Roles = append(t.Roles, s)
			}
		}
	}
	return t
}

// AssignableBy returns the roles a holder of held may assign, sorted;
// never admin.
func (p *People) AssignableBy(held []string) []string {
	if p == nil {
		return nil
	}
	set := map[string]bool{}
	for key, list := range p.assignable {
		for _, h := range held {
			if p.roles.Satisfies(h, key) {
				for _, r := range list {
					if r != "admin" {
						set[r] = true
					}
				}
				break
			}
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// AllAssignable returns every role some people manager may assign, sorted.
func (p *People) AllAssignable() []string {
	if p == nil {
		return nil
	}
	set := map[string]bool{}
	for _, list := range p.assignable {
		for _, r := range list {
			if r != "admin" {
				set[r] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// IsManager reports whether a holder of held manages people.
func (p *People) IsManager(held []string) bool { return len(p.AssignableBy(held)) > 0 }

// Manages reports whether the actor may manage the target user: the
// target is someone else, not deleted, and every role it holds is one the
// actor may assign.
func (p *People) Manages(actorID string, held []string, t PersonTarget) bool {
	if p == nil || t.ID == "" || t.ID == actorID || t.Status == "deleted" {
		return false
	}
	can := p.AssignableBy(held)
	if len(can) == 0 {
		return false
	}
	for _, r := range t.Roles {
		if !slices.Contains(can, r) {
			return false
		}
	}
	return true
}

// MayAssign reports whether the actor may give a user exactly roles.
func (p *People) MayAssign(held, roles []string) bool {
	if p == nil || len(roles) == 0 {
		return false
	}
	can := p.AssignableBy(held)
	for _, r := range roles {
		if !slices.Contains(can, r) {
			return false
		}
	}
	return true
}

// Allows decides a people action by a non-admin actor on target. input
// may be empty (permission checks); a role in it must be assignable.
func (p *People) Allows(actorID string, held []string, action string, t PersonTarget, input map[string]any) bool {
	if p == nil {
		return false
	}
	switch action {
	case ActAddUser:
		// Runs on the actor's own record (the UI needs an id).
		if t.ID != actorID || !p.IsManager(held) {
			return false
		}
		if r, ok := input["role"].(string); ok && r != "" {
			return p.MayAssign(held, []string{r})
		}
		return true
	case ActSetRole:
		if !p.Manages(actorID, held, t) {
			return false
		}
		if r, ok := input["role"].(string); ok && r != "" {
			return p.MayAssign(held, []string{r})
		}
		return true
	case ActSuspend:
		return p.Manages(actorID, held, t) && (t.Status == "" || t.Status == "active")
	case ActReactivate:
		return p.Manages(actorID, held, t) && t.Status == "suspended"
	case ActSetPassword, ActResetMFA:
		return p.Manages(actorID, held, t)
	case ActSignOutEverywhere:
		return t.ID == actorID || p.Manages(actorID, held, t)
	}
	return false
}

// PeopleInputs returns the input schemas of the people actions; roles is
// the role enum of addUser and setRole.
func PeopleInputs(roles []string, minPassword int) map[string]json.RawMessage {
	if minPassword <= 0 {
		minPassword = 12
	}
	enum, _ := json.Marshal(roles)
	pw := map[string]any{"type": "string", "format": "password", "writeOnly": true, "minLength": minPassword, "maxLength": 256}
	role := map[string]any{"type": "string", "enum": json.RawMessage(enum)}
	obj := func(props map[string]any, required ...string) json.RawMessage {
		s := map[string]any{"type": "object", "additionalProperties": false, "properties": props}
		if len(required) > 0 {
			s["required"] = required
		}
		b, _ := json.Marshal(s)
		return b
	}
	empty := obj(map[string]any{})
	return map[string]json.RawMessage{
		ActAddUser: obj(map[string]any{
			"displayName": map[string]any{"type": "string", "minLength": 1, "maxLength": 120},
			"email":       map[string]any{"type": "string", "format": "email", "maxLength": 254},
			"password":    pw,
			"role":        role,
		}, "displayName", "email", "password", "role"),
		ActSetRole:           obj(map[string]any{"role": role}, "role"),
		ActSetPassword:       obj(map[string]any{"password": pw}, "password"),
		ActSuspend:           empty,
		ActReactivate:        empty,
		ActResetMFA:          empty,
		ActSignOutEverywhere: empty,
	}
}
