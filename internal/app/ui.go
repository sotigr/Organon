package app

import (
	"encoding/json"
	"slices"

	accessdomain "organon/internal/access/domain"
	manifestdomain "organon/internal/manifest/domain"

	flowdomain "organon/internal/flow/domain"
	"organon/internal/runtime/domain/expression"
	schemaapi "organon/internal/schema/api"
	uidomain "organon/internal/ui/domain"
)

// uiDeps are the UI compiler's view of the app: its types and the actions
// its flows implement. flows is nil when the flows failed to compile.
func uiDeps(types schemaapi.TypeRegistry, flows *flowdomain.FlowSet, people map[string]json.RawMessage) uidomain.Deps {
	return uidomain.Deps{Types: types, Exprs: expression.NewCompiler(),
		FlowAction: func(ct *schemaapi.CompiledType, name string) (json.RawMessage, bool) {
			if in, ok := people[name]; ok && ct.Base() == schemaapi.TypeUser {
				return in, true
			}
			if flows == nil {
				return nil, true // flow errors are reported already
			}
			f, ok := flows.Action(ct, name)
			if !ok {
				return nil, false
			}
			return f.Def.Input, true
		}}
}

// peopleInputs returns the input schemas of the built-in people actions
// of the user type (ADR 0030): roles are the assignable ones, or every
// role when only admins manage people.
func peopleInputs(m *manifestdomain.Manifest, people *accessdomain.People) map[string]json.RawMessage {
	roles := people.AllAssignable()
	if roles == nil {
		roles = []string{}
		for r := range m.App.Roles {
			roles = append(roles, r)
		}
		if !slices.Contains(roles, "admin") {
			roles = append(roles, "admin")
		}
		slices.Sort(roles)
	}
	return accessdomain.PeopleInputs(roles, m.App.Auth.Password.MinLength)
}

// UICatalog returns the UI component and step catalog (ADR 0016).
func UICatalog() uidomain.Catalog { return uidomain.GetCatalog() }

// UISchemas returns the JSON Schemas of ui/ files by file name.
func UISchemas() map[string]map[string]any {
	return map[string]map[string]any{"ui-app.json": uidomain.AppSchema(), "ui-page.json": uidomain.PageSchema(), "ui-layout.json": uidomain.LayoutSchema(),
		"ui-i18n.json": uidomain.I18nSchema()}
}

// UITranslations is one ui/i18n/<lang>.json (ADR 0018).
type UITranslations = uidomain.Translations

// UIProp is one prop of a UI component or step.
type UIProp = uidomain.Prop
