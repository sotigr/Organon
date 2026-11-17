package domain

import (
	"encoding/json"
	"reflect"
	"testing"
)

func testPeople(t *testing.T) *People {
	t.Helper()
	r, err := NewRoles(map[string][]string{"mechanic": {}, "frontdesk": {"mechanic"}, "manager": {"frontdesk"}, "admin": {"manager"}, "owner": {"manager"}})
	if err != nil {
		t.Fatal(err)
	}
	return NewPeople(map[string][]string{"manager": {"mechanic", "frontdesk", "manager"}}, r)
}

// ADR 0030: managers assign their listed roles; roles including the key
// (owner) inherit it; admin is never assignable.
func TestPeopleAssignable(t *testing.T) {
	p := testPeople(t)
	want := []string{"frontdesk", "manager", "mechanic"}
	if got := p.AssignableBy([]string{"manager"}); !reflect.DeepEqual(got, want) {
		t.Fatalf("manager: %v", got)
	}
	if got := p.AssignableBy([]string{"owner"}); !reflect.DeepEqual(got, want) {
		t.Fatalf("owner inherits manager: %v", got)
	}
	if got := p.AssignableBy([]string{"frontdesk"}); len(got) != 0 {
		t.Fatalf("frontdesk manages nobody: %v", got)
	}
	if !reflect.DeepEqual(p.AllAssignable(), want) {
		t.Fatalf("all: %v", p.AllAssignable())
	}
	if p.MayAssign([]string{"manager"}, []string{"admin"}) || p.MayAssign([]string{"manager"}, nil) ||
		p.MayAssign([]string{"manager"}, []string{"owner"}) || !p.MayAssign([]string{"manager"}, []string{"frontdesk"}) {
		t.Fatal("MayAssign")
	}
	var none *People
	if none.IsManager([]string{"manager"}) || NewPeople(nil, nil) != nil {
		t.Fatal("nil People manages nobody")
	}
}

func TestPeopleManages(t *testing.T) {
	p := testPeople(t)
	mgr := []string{"manager"}
	for _, c := range []struct {
		name string
		t    PersonTarget
		ok   bool
	}{
		{"mechanic", PersonTarget{ID: "u2", Roles: []string{"mechanic"}, Status: "active"}, true},
		{"no roles", PersonTarget{ID: "u2"}, true},
		{"peer manager", PersonTarget{ID: "u2", Roles: []string{"manager"}}, true},
		{"admin", PersonTarget{ID: "u2", Roles: []string{"admin"}}, false},
		{"mixed with admin", PersonTarget{ID: "u2", Roles: []string{"mechanic", "admin"}}, false},
		{"unknown role", PersonTarget{ID: "u2", Roles: []string{"owner"}}, false},
		{"self", PersonTarget{ID: "u1", Roles: []string{"mechanic"}}, false},
		{"deleted", PersonTarget{ID: "u2", Status: "deleted"}, false},
	} {
		if got := p.Manages("u1", mgr, c.t); got != c.ok {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
	if p.Manages("u1", []string{"frontdesk"}, PersonTarget{ID: "u2", Roles: []string{"mechanic"}}) {
		t.Error("frontdesk manages")
	}
}

func TestPeopleAllows(t *testing.T) {
	p := testPeople(t)
	mgr := []string{"manager"}
	mech := PersonTarget{ID: "u2", Roles: []string{"mechanic"}, Status: "active"}
	susp := PersonTarget{ID: "u2", Roles: []string{"mechanic"}, Status: "suspended"}
	self := PersonTarget{ID: "u1", Roles: []string{"manager"}, Status: "active"}
	in := func(role string) map[string]any { return map[string]any{"role": role} }
	for _, c := range []struct {
		name   string
		action string
		t      PersonTarget
		input  map[string]any
		ok     bool
	}{
		{"add on self", ActAddUser, self, nil, true},
		{"add mechanic", ActAddUser, self, in("mechanic"), true},
		{"add admin", ActAddUser, self, in("admin"), false},
		{"add on other", ActAddUser, mech, nil, false},
		{"set role", ActSetRole, mech, in("frontdesk"), true},
		{"set role admin", ActSetRole, mech, in("admin"), false},
		{"set own role", ActSetRole, self, in("mechanic"), false},
		{"suspend", ActSuspend, mech, nil, true},
		{"suspend suspended", ActSuspend, susp, nil, false},
		{"suspend self", ActSuspend, self, nil, false},
		{"reactivate", ActReactivate, susp, nil, true},
		{"reactivate active", ActReactivate, mech, nil, false},
		{"password", ActSetPassword, mech, nil, true},
		{"own password", ActSetPassword, self, nil, false},
		{"mfa", ActResetMFA, mech, nil, true},
		{"sign out self", ActSignOutEverywhere, self, nil, true},
		{"sign out other", ActSignOutEverywhere, mech, nil, true},
		{"unknown", "promote", mech, nil, false},
	} {
		if got := p.Allows("u1", mgr, c.action, c.t, c.input); got != c.ok {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
	if p.Allows("u3", []string{"mechanic"}, ActSignOutEverywhere, mech, nil) {
		t.Error("a mechanic signs out a colleague")
	}
}

func TestPeopleInputs(t *testing.T) {
	in := PeopleInputs([]string{"frontdesk", "mechanic"}, 12)
	for _, a := range PeopleActions {
		var s map[string]any
		if err := json.Unmarshal(in[a], &s); err != nil || s["type"] != "object" {
			t.Fatalf("%s: %s %v", a, in[a], err)
		}
	}
	var add struct {
		Properties map[string]map[string]any `json:"properties"`
		Required   []string                  `json:"required"`
	}
	_ = json.Unmarshal(in[ActAddUser], &add)
	if add.Properties["password"]["format"] != "password" || len(add.Required) != 4 ||
		!reflect.DeepEqual(add.Properties["role"]["enum"], []any{"frontdesk", "mechanic"}) {
		t.Fatalf("addUser: %+v", add)
	}
	if got := TargetOf("", map[string]any{"id": "x", "roles": []any{"a"}, "status": "active"}); got.ID != "x" || got.Roles[0] != "a" {
		t.Fatalf("TargetOf: %+v", got)
	}
}
