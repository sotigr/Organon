package domain

import (
	"sort"

	accessapi "organon/internal/access/api"
	rt "organon/internal/runtime/api"
)

// Layouts (ADR 0029): ui/layouts/<name>.json is the frame around the pages
// that use it. Its header, sidebar, and footer regions are component
// trees like a page body, with their own state and data sources; their
// expressions see the principal and the shown page (page.name,
// page.params), never the page's data.

// layoutHead reads a layout's name so ui/app.json and pages can refer to it.
func (c *compiler) layoutHead(s Source) {
	c.file = s.File
	if len(s.Data) > MaxPageBytes {
		c.errf("", "layout is larger than %d bytes", MaxPageBytes)
		return
	}
	m, err := decode(s.Data)
	if err != nil {
		c.errf("", "invalid JSON: %v", err)
		return
	}
	name, _ := m["layout"].(string)
	switch {
	case !nameRe.MatchString(name):
		c.errf("/layout", "layout name must match %s", nameRe)
	case name == LayoutDefault || name == LayoutNone:
		c.errf("/layout", "%q is reserved: default is the built-in header, none is no frame", name)
	case c.layouts[name] != nil:
		c.errf("/layout", "layout %q is also defined in %s", name, c.layouts[name].file)
	default:
		c.layouts[name] = &layoutHead{name: name, file: s.File, doc: m}
	}
}

// layoutRef checks a layout member of ui/app.json or a page.
func (c *compiler) layoutRef(ptr string, v any) string {
	name, _ := v.(string)
	if name == LayoutDefault || name == LayoutNone || c.layouts[name] != nil {
		return name
	}
	c.errf(ptr, "unknown layout %q: name a file of ui/layouts, default (the built-in header), or none", name)
	return LayoutDefault
}

// layoutScope is the expression environment of a layout.
func layoutScope() *scope {
	return &scope{funcs: uiFuncEnv, vars: map[string]*rt.Type{
		"principal": accessapi.PrincipalExprType(),
		"page":      rt.MapOf(map[string]*rt.Type{"name": rt.String, "params": rt.OpenMap()}),
	}}
}

func (c *compiler) compileLayout(h *layoutHead) *Layout {
	c.file = h.file
	m := h.doc
	c.known("", m, "$schema", "layout", "state", "data", "header", "sidebar", "footer", "x-layout")
	c.page = &pageCtx{sources: map[string]*srcInfo{}, state: map[string]*rt.Type{}, dialogs: map[string]bool{},
		dialogRefs: map[string]string{}, types: map[string]bool{}}
	defer func() { c.page = nil }()
	l := &Layout{Name: h.name, File: h.file, Doc: browserDoc(m)}
	sc := layoutScope()
	if v, ok := m["state"]; ok {
		c.state(v)
	}
	sc.vars["state"] = rt.MapOf(c.page.state)
	c.sources(m["data"], sc)
	regions := 0
	for _, r := range LayoutRegions {
		if v, ok := m[r]; ok {
			regions++
			c.node("/"+r, v, sc)
		}
	}
	if regions == 0 {
		c.errf("", "a layout has at least one of header, sidebar, footer")
	}
	for ptr, name := range c.page.dialogRefs {
		if !c.page.dialogs[name] {
			c.errf(ptr, "no dialog named %q in this layout", name)
		}
	}
	if !h.used {
		c.warnf("", "no page uses layout %s: set \"layout\" in ui/app.json or a page", h.name)
	}
	for t := range c.page.types {
		l.Types = append(l.Types, t)
	}
	sort.Strings(l.Types)
	return l
}
