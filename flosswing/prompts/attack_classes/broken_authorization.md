# Attack class: broken_authorization

An *authenticated* caller can act on objects or invoke functions that
should be denied to them. The bug lives after identity is established:
the request proves *who* you are, but the code never checks *whether
this principal may touch this object or reach this handler*. Two
shapes: object-level (IDOR / BOLA) — a record identifier from the
request is used to fetch or mutate a row without scoping to the current
principal — and function-level — a privileged/admin route with no role
or permission gate. This is **authorization**, not authentication. If
the request is served with missing or forgeable *credentials* (unguarded
endpoint, unverified signature, backdoor), that is `auth_bypass` — record
it there, not here.

## What to look for

A handler that trusts a client-supplied identifier, or a sensitive
route with no policy check.

- **IDOR / BOLA (any language).** A handler reads `id`, `user_id`,
  `account_id`, `order_id`, `doc_id`, etc. straight from the path,
  query string, or body and passes it to a fetch/update/delete keyed
  only on that id — `Model.objects.get(pk=request_id)`,
  `SELECT ... WHERE id = :id`, `repo.findById(id)` — with no `AND
  owner_id = current_user` / tenant filter and no post-fetch ownership
  check. The tell is that swapping the id to another principal's value
  would succeed.
- **Missing function-level authz.** A route that performs a privileged
  action (delete user, change role, read another tenant's data, admin
  dashboard) registered *without* the role/permission decorator or
  middleware that guards its siblings — Flask/Django/FastAPI routes
  lacking `@permission_required` / a `Depends(require_role)`; Express/
  Nest routes missing the `authorize`/`roles` guard; Spring methods
  lacking `@PreAuthorize`/`@Secured`; a mass-assignment path that lets a
  user set their own `is_admin`/`role`.
- **Broken policy logic.** A check that reads the *target* object's
  owner from the request instead of from the loaded record, compares
  against a client-supplied role claim, or returns the resource before
  the check runs (fetch-then-authorize with an early leak).

## Evidence

Hunt's v0.3 toolset is `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, and `record_finding` — there is no `compile_and_run`, so a
finding cannot carry a real execution result. Use `find_definition` and
`find_callers` to trace how untrusted data reaches the sink. A finding should
carry `file`, `function`, `line_start`, `line_end` at the sink plus a
`description` of that flow, and a short **textual** `poc_code` sketch of the
triggering input. Do **not** fabricate a `poc_result` — leave it unset.
Confidence: `likely` when you can trace the flow end-to-end, `speculative`
when a link in the chain is unclear. Do **not** use `confirmed`; it requires
execution Hunt cannot perform in v0.3.

## Common false positives

- The query is already scoped to the current principal — `WHERE id = ?
  AND user_id = current_user.id`, `request.user.orders.get(pk=id)`, a
  tenant filter injected by the ORM's row-level security.
- Ownership is verified *before* the action against the loaded record
  (`if obj.owner_id != current_user.id: raise Forbidden`).
- A centralized policy layer / decorator / middleware enforces the check
  for the whole route group and the handler in scope inherits it.
- The identifier is not a cross-principal reference (a global public
  resource, or an id namespaced to the caller).

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
