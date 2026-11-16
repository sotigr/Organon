# 0029: UI layouts and custom navigation

Status: accepted (2026-11-16, requested by the project owner)

## Context
ADR 0016 gave every page the same built-in frame: a header with the logo
and title, the flat `nav` list of `ui/app.json`, a language switch, and
Sign out. Apps need more than that: drop-down groups, badges ("3 open"),
icons, actions and menus in the header, a sidebar, a footer, and pages
with no frame at all (kiosk and print views). The owner chose (2026-11-16):
named layouts that pages pick from, layouts with their own data sources,
header, sidebar, and footer in the first version, and a declarative frame
only, with no custom HTML or scripts.

## Decision
- **Files.** `ui/layouts/<name>.json` holds one layout: `layout` (its name),
  optional `state` and `data` like a page, and the regions `header`,
  `sidebar`, and `footer`, each one component tree (at least one region).
  Layouts belong to the app; modules contribute pages only.
- **Choosing a layout.** `ui/app.json` `layout` sets the default of pages;
  a page's `layout` overrides it. Two names are reserved: `default`, the
  built-in header of ADR 0016 (still the default, so existing apps render
  as before), and `none`, no frame. Unknown names are validation errors,
  and a layout no page uses is a warning.
- **Scope.** Layout expressions see `principal`, `page` (`name` and
  `params` of the page shown), and the layout's own `data` and `state`,
  never the page's data, so a layout is checked once, not per page. Steps
  and dialogs in a layout use the layout's state and dialogs.
- **Shell components** (catalog family `shell`, usable in pages too):
  `brand`, `nav` (links to a page or URL with `icon`, `badge`, `visible`,
  `active`; groups one level deep as drop-downs or, vertically, indented
  lists; without `items` it renders the `nav` of `ui/app.json`),
  `userMenu` (links and Sign out; hidden for anonymous and link
  principals), `languageSwitch`, and `spacer`. Icons are `ui/assets` files;
  there is no icon font.
- **Pages the user cannot see.** Navigation links to pages missing from the
  principal's bundle are left out by the renderer; `visible` is only for
  extra conditions. The bundle carries only the layouts of the pages it
  offers, so a frame reveals nothing to principals who never see it.
- **Rendering.** The layout stays mounted while pages of the same layout
  change, so its sources load once and update live like page sources. A
  horizontal `nav` collapses into a menu button below 720 px; a sidebar
  moves above the page. Styling uses stable classes (`o-layout-header`,
  `o-layout-sidebar`, `o-layout-footer`, `o-navbar`, `o-nav-link`,
  `o-nav-active`, `o-nav-badge`, `o-user-menu`, ...) and
  `--o-sidebar-width`.
- **Builder.** `/admin` → UI lists layouts and edits them as JSON with live
  validation (`PUT`/`DELETE /v1/dev/manifest/ui/layouts/{name}`, dev only);
  page settings and the app shell pick a layout. A visual layout editor is
  left for later.

## Consequences
- The built-in header remains, so `ui/app.json` `nav` keeps working, both
  in the default frame and in a `nav` without items.
- Layout data sources cost requests on every page view of their pages;
  keep them small (counts for badges).
- No custom code enters the frame: anything a layout cannot express is a
  component request, as for pages.
