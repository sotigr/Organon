// Shell components (ADR 0029): the parts of an app frame that ui/layouts
// arrange — brand, nav, userMenu, languageSwitch, spacer. Pages may use
// them too.
import { useContext, useEffect, useRef, useState } from "react";
import { register, type ComponentProps } from "../render";
import { RouteContext, useEval, useRuntime, withClass, type Eval, type Route, type Runtime } from "../runtime";
import { languageName, type Translate } from "../i18n";
import { safeURL } from "./layout";
import type { Bundle, NavItem } from "../types";

function cls(...parts: (string | false | undefined)[]) {
  return parts.filter(Boolean).join(" ");
}

/** LanguageSwitch offers the app's languages when it has more than one. */
export function LanguageSwitch({ bundle, t, onChange, className }: { bundle: Bundle; t: Translate; onChange(lang: string): void; className?: string }) {
  const i18n = bundle.i18n;
  if (!i18n || i18n.languages.length < 2) return null;
  return (
    <select className={cls("o-input o-lang", className)} aria-label={t("Language")} value={i18n.language} onChange={(e) => onChange(e.target.value)}>
      {i18n.languages.map((l) => <option key={l} value={l} lang={l}>{languageName(l)}</option>)}
    </select>
  );
}

/** goHome opens the home page, or the shared feature for share-link holders. */
export function goHome(rt: Runtime) {
  const app = rt.bundle.app;
  if (rt.principal?.kind === "link" && app.linkHome) rt.navigate(app.linkHome, { id: rt.principal.object });
  else rt.navigate(app.home);
}

register("brand", ({ node }: ComponentProps) => {
  const rt = useRuntime();
  const ev = useEval();
  const app = rt.bundle.app;
  const text = node.text !== undefined ? ev.text(node.text) : app.title ? rt.t(app.title) : "";
  return (
    <a className={withClass("o-brand", node)} href="/" onClick={(e) => { e.preventDefault(); goHome(rt); }}>
      {app.logo && <img src={`/assets/app/${app.logo.replace(/^assets\//, "")}`} alt="" />}
      {text && <span>{text}</span>}
    </a>
  );
});

register("spacer", ({ node }: ComponentProps) => <div className={withClass("o-spacer", node)} aria-hidden="true" />);

register("languageSwitch", ({ node }: ComponentProps) => {
  const rt = useRuntime();
  if (!rt.setLanguage) return null;
  return <LanguageSwitch bundle={rt.bundle} t={rt.t} className={node.class} onChange={(l) => void rt.setLanguage!(l)} />;
});

/** sameParams reports whether the shown page has the link's parameters. */
function sameParams(route: Route, params: Record<string, unknown>): boolean {
  return Object.entries(params).every(([k, v]) => String(route.params[k] ?? "") === String(v ?? ""));
}

interface Resolved {
  label: string;
  href: string;
  external: boolean;
  icon?: string;
  badge?: string;
  active: boolean;
  go(): void;
}

/** resolveLink evaluates one link; null when hidden or its page is not
 * offered to this user (the bundle leaves such pages out). */
function resolveLink(item: NavItem, ev: Eval, rt: Runtime, route: Route | null): Resolved | null {
  if (item.visible !== undefined && ev.ex(item.visible) !== true) return null;
  const icon = item.icon ? safeURL(ev.plain(item.icon)) : undefined;
  const b = item.badge !== undefined ? ev.text(item.badge) : "";
  const badge = b && b !== "0" ? b : undefined;
  const label = ev.text(item.label);
  if (item.url !== undefined) {
    const url = safeURL(ev.plain(item.url));
    if (!url) return null;
    const active = item.active !== undefined && ev.ex(item.active) === true;
    return { label, href: url, external: true, icon, badge, active, go: () => window.open(url, "_blank", "noopener,noreferrer") };
  }
  const page = item.page;
  if (!page || (!rt.editor && !rt.bundle.pages.some((p) => p.name === page))) return null;
  const params: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(item.params || {})) params[k] = ev.ex(v);
  const active = item.active !== undefined ? ev.ex(item.active) === true : !!route && route.name === page && sameParams(route, params);
  return { label, href: rt.href(page, params), external: false, icon, badge, active, go: () => rt.navigate(page, params) };
}

function LinkBody({ r }: { r: Resolved }) {
  return (
    <>
      {r.icon && <img className="o-nav-icon" src={r.icon} alt="" />}
      <span className="o-nav-label">{r.label}</span>
      {r.badge && <span className="o-nav-badge">{r.badge}</span>}
    </>
  );
}

function NavLink({ r, className, onDone }: { r: Resolved; className: string; onDone?: () => void }) {
  if (r.external) {
    return <a className={className} href={r.href} target="_blank" rel="noopener noreferrer" onClick={onDone}><LinkBody r={r} /></a>;
  }
  return (
    <a className={cls(className, r.active && "o-nav-active")} href={r.href} aria-current={r.active ? "page" : undefined}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey) return;
        e.preventDefault();
        onDone?.();
        r.go();
      }}>
      <LinkBody r={r} />
    </a>
  );
}

/** useDismiss closes a drop-down on an outside click or Escape. */
function useDismiss(open: boolean, close: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const click = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) close(); };
    const key = (e: KeyboardEvent) => { if (e.key === "Escape") close(); };
    document.addEventListener("mousedown", click);
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("mousedown", click);
      document.removeEventListener("keydown", key);
    };
  }, [open]);
  return ref;
}

/** DropDown is a button that opens a list of links. */
function DropDown({ label, active, className, links, footer }: {
  label: React.ReactNode; active?: boolean; className: string; links: Resolved[]; footer?: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const ref = useDismiss(open, () => setOpen(false));
  return (
    <div className={cls(className, open && "o-open")} ref={ref}>
      <button type="button" className={cls("o-nav-link o-nav-group-button", active && "o-nav-active")} aria-haspopup="true" aria-expanded={open}
        onClick={() => setOpen(!open)}>
        {label}<span className="o-nav-caret" aria-hidden="true">▾</span>
      </button>
      {open && (
        <div className="o-menu-items o-nav-menu" role="menu">
          {links.map((r, i) => <NavLink key={i} r={r} className="o-menu-item" onDone={() => setOpen(false)} />)}
          {footer}
        </div>
      )}
    </div>
  );
}

register("nav", ({ node }: ComponentProps) => {
  const rt = useRuntime();
  const ev = useEval();
  const route = useContext(RouteContext);
  const [open, setOpen] = useState(false);
  // Without items: the nav of ui/app.json, already filtered by the server.
  const items = (node.items as NavItem[] | undefined) ?? rt.bundle.app.nav ?? [];
  const vertical = node.orientation === "vertical";
  // A navigation closes the collapsed menu on narrow screens.
  useEffect(() => setOpen(false), [route?.name, JSON.stringify(route?.params)]);
  const entries = items.map((it, i) => {
    if (!it.items) {
      const r = resolveLink(it, ev, rt, route);
      return r && <li key={i}><NavLink r={r} className="o-nav-link" /></li>;
    }
    if (it.visible !== undefined && ev.ex(it.visible) !== true) return null;
    const links = it.items.map((x) => resolveLink(x, ev, rt, route)).filter((r): r is Resolved => r !== null);
    if (!links.length) return null;
    const label = ev.text(it.label);
    const active = links.some((r) => r.active);
    if (vertical) {
      return (
        <li key={i} className="o-nav-group">
          <span className={cls("o-nav-group-label", active && "o-nav-active")}>{label}</span>
          <ul>{links.map((r, j) => <li key={j}><NavLink r={r} className="o-nav-link" /></li>)}</ul>
        </li>
      );
    }
    return <li key={i}><DropDown label={label} active={active} className="o-nav-group" links={links} /></li>;
  });
  return (
    <nav className={withClass(cls("o-navbar", vertical ? "o-nav-vertical" : "o-nav-horizontal", open && "o-open"), node)}>
      {!vertical && (
        <button type="button" className="o-nav-toggle" aria-label={rt.t("Menu")} aria-expanded={open} onClick={() => setOpen(!open)}>☰</button>
      )}
      <ul className="o-nav-items">{entries}</ul>
    </nav>
  );
});

register("userMenu", ({ node }: ComponentProps) => {
  const rt = useRuntime();
  const ev = useEval();
  const route = useContext(RouteContext);
  const p = rt.principal;
  if (!p || p.kind === "anonymous" || p.kind === "link") return null;
  const label = node.label !== undefined ? ev.text(node.label) : (p.kind === "user" && rt.label(p.id)) || rt.t("Account");
  const links = ((node.items as NavItem[] | undefined) || []).map((x) => resolveLink(x, ev, rt, route)).filter((r): r is Resolved => r !== null);
  const signOut = node.signOut !== false;
  return (
    <DropDown label={<span className="o-nav-label">{label}</span>} className={withClass("o-user-menu", node)} links={links}
      footer={signOut && <button type="button" className="o-menu-item" onClick={() => rt.logout()}>{rt.t("Sign out")}</button>} />
  );
});
