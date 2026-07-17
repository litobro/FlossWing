# Attack class: sqli

Untrusted data is concatenated, interpolated, or formatted into a SQL
string that reaches a database driver, instead of being passed as a
bound parameter. The bug lives at the boundary where attacker data
becomes part of the query *text* rather than a value the driver binds
separately. The safe shape is a parameterized query: a static SQL
template with placeholders and the untrusted values handed to the
driver as a separate argument.

## What to look for

A query string built from data that traces back to attacker-controlled
input (HTTP route params, query strings, form/JSON bodies, headers,
uploaded content, IPC messages) and passed to a driver's
execute/query/exec sink without placeholders.

- **Python.** A DB-API `cursor.execute(sql)` / `executemany` where `sql`
  is built with `%`, `.format`, f-strings, or `+` concatenation of user
  data — as opposed to `execute(sql, params)` with `%s`/`?`
  placeholders. ORM raw-SQL escape hatches (`session.execute(text(...))`
  with interpolation, `.raw()`, `.extra()`) count too.
- **JavaScript / Node.** `db.query`/`connection.query`/`knex.raw` with a
  template literal or concatenated string carrying request data, rather
  than the `(sql, values)` parameterized form. Sequelize
  `sequelize.query` with interpolation and any `.raw()` builder path.
- **Go.** `db.Query`/`db.Exec`/`QueryRow` whose SQL argument is built
  with `fmt.Sprintf`, `+`, or `strings.Join` over user data — as opposed
  to the placeholder form (`?` / `$1`) with args passed variadically.
- **Java.** `Statement.execute*`/`createStatement` fed a concatenated
  string, versus `PreparedStatement` with `?` placeholders and
  `setString`/`setInt`. JPA/Hibernate string-built HQL/JPQL or native
  queries with inlined values.
- **ORM escape hatches (any language).** Raw-SQL methods that bypass the
  builder's binding — report the interpolation into them, not the
  builder's own bound calls.

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

- The query is parameterized: static SQL with `?`/`%s`/`$1` placeholders
  and values passed as a separate argument. This is the safe shape — do
  not report it.
- An ORM query builder with bound arguments (`.filter(Model.x == user)`,
  `where('x', user)`), which parameterizes under the hood.
- Column/table/order-by identifiers — which cannot be bound as
  parameters — chosen through a fixed allowlist and never taken raw from
  user input.
- The interpolated value is a program-controlled constant or already an
  integer the code parsed and range-checked, not attacker data.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
