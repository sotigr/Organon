# 0030: Delegated user management

Status: accepted (2026-11-17, requested by the project owner)

## Context
Only admins could create and manage users (`CreateUser`, set password,
reset MFA), and only in the admin console. The `email`, `roles`, and
`status` of a user are `x-visibility: owner` and `x-write: admin`. Apps
whose day-to-day staff management belongs to a non-admin role (a shop
manager) had to hand out the admin role or call an admin for each new
employee. The owner chose (2026-11-17):
- managers create staff (with an initial password they type), change
  roles, suspend and reactivate, and reset passwords and MFA;
- the roles they may assign are configured, never `admin`;
- the rule is built into the framework and configured in app.json, and the
  end-user UI drives it with its existing components.

## Decision
- **Config.** `app.json` `auth.people` maps a role to the roles its holders
  may assign: `{"manager": ["mechanic", "frontdesk", "manager"]}`. Roles
  that include a key (through `roles`) get its list too, and several keys
  add up. `validate` rejects `admin` as a key or value, unknown roles, and
  empty or duplicate lists, and warns when a key is not in
  `auth.mfa.requiredForRoles`.
- **Rule** (`access/domain/people.go`, pure). An actor *manages* a user
  when the user is someone else, not deleted, and every role the user
  holds is one the actor may assign. So managers never touch admins (or
  users with roles outside their list) and never themselves; with
  `manager` in its own list, managers manage other managers (accepted:
  admins can undo anything and every operation is audited). Admins and the
  system are not limited.
- **Built-in actions on the `user` type**, dispatched like `share`:
  `addUser {displayName, email, password, role}` (run on the caller's own
  record, output `{id}`), `setRole {role}`, `suspend`, `reactivate`,
  `setPassword {password}`, `resetMfa`, `signOutEverywhere`. One role per
  user through `setRole`, which fits hierarchical roles. Apps cannot
  define policies or flows with these names on `user`.
- **Checked twice.** The Authorizer answers these actions from the rule
  and ignores policies (so `POST /v1/permissions` and the UI's `can()`
  agree), and the account service checks again. The admin routes
  (`POST /v1/auth/users`, `/password`, `/mfa`, `/sessions`) call the same
  service methods, so they follow the same rule.
- **Reads.** A manager gets the owner audience on users they manage, so
  lists and reads show their `email`, `roles`, and `status`. Writes do not
  change: the owner write view excludes `x-write: admin`, so `roles` and
  `status` still cannot be written through `PATCH /v1/features`.
- **Side effects.** Suspending signs the user out; a new password signs
  them out; a role that needs MFA signs out a user with no authenticator,
  so they enroll at the next sign-in.
- **Audit.** `user_created`, `roles_set` (old -> new), `user_suspended`,
  `user_reactivated`, `password_set`, `mfa_reset`, and `sessions_revoked`,
  with the user as the target and the caller as the actor.
- **End-user UI.** `form` fields get the `password` widget (also chosen
  for `format: password` / `writeOnly` inputs, never dictated) and
  `options: [{value, label}]` for select choices with translatable labels.

## Why actions, and why addUser runs on the caller's record
Letting managers write `roles` through generic updates would need
per-field, per-value write rules in the content pipeline and would make
every client responsible for the role check. Actions keep one entry point
with a server-side rule and work with the existing `form mode: action`,
`button`, and `can()`. A `form` in action mode needs a feature id;
`principal.id` is always at hand, so `addUser` runs on the caller's own
user. A type-level action endpoint could replace that later.

## Consequences
- Service accounts, teams, and organizations are out of scope.
- Managers cannot edit a user's name or email (the email is also the
  sign-in login); a later `setProfile` action could.
- Managers cannot filter the user list by roles or status: list filters
  use the member query view.
