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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, and `compile_and_run`, and you report through
`record_finding`. Authorization flaws are usually a *reasoning* about
missing enforcement, not something you can execute in isolation — there
is no server, session, or second principal in the sandbox — so an
end-to-end trace is normally the ceiling and `likely` is the honest
confidence. Use `find_callers`/`grep` to confirm the id reaches the
query unscoped and that no upstream middleware or decorator supplies the
missing check; use `find_definition` to inspect the ORM/query call and
any policy helper. A finding should carry `file`, `function`,
`line_start`, `line_end` at the unscoped query or the unguarded route,
and a `description` naming the identifier, the sink, and the absent
ownership/tenant/role check. `compile_and_run` rarely proves this class
directly; if you can build a self-contained harness that shows the query
returns another principal's row given only their id, attach `poc_result`
and claim `confirmed`. Traced-but-unrun (the standard case) →
`confirmed` requires a genuine reachability trace showing the sink is
hit with attacker-controlled id and no enforcement in between; a clean
end-to-end trace without that rigor is `likely`; an unclear middleware
chain or unproven reachability is `speculative`.

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
