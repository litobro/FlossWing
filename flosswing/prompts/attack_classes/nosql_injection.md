# Attack class: nosql_injection

Untrusted input injects query *operators* or a non-scalar *type* into a
NoSQL query, changing what the query means. The canonical shape:
attacker-controlled request data is dropped into a query document where
the code expected a scalar, so an attacker who supplies
`{"$ne": null}`, `{"$gt": ""}`, `{"$regex": ".*"}`, or `{"$where":
"..."}` rewrites the match — bypassing a login (`{password: {$ne:1}}`),
widening a filter, or smuggling server-side JavaScript. The bug lives
where a value the code treats as a string/number is actually an
attacker-shaped object or a concatenated JS fragment.

## What to look for

A query built from request data where operator objects or JS can slip in.

- **MongoDB — operator injection.** A driver call
  (`collection.find(query)`, `findOne`, `updateOne`, `deleteMany`) whose
  `query` embeds a raw request field — `find({username: req.body.user,
  password: req.body.pass})` — where the framework parses
  `user[$ne]=1`/JSON bodies into nested objects, so `req.body.pass`
  arrives as `{$ne: null}` instead of a string. Watch for Express/`qs`
  bodies, PyMongo/Motor filters built from `request.json`, Mongoose
  queries fed unvalidated input.
- **MongoDB — `$where` / JS evaluation.** `$where: "this.x == '" + input
  + "'"`, `mapReduce`, or `$function`/`$accumulate` with a JS body built
  by concatenation — this is server-side JS execution, treat as high
  severity.
- **Other document/KV stores.** CouchDB Mango selectors, Firebase rules,
  Redis/ElasticSearch query DSLs, or any store where a JSON query
  document is assembled from request data and operator keys are not
  filtered.

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

- The input is cast/validated to the expected scalar *before* the query
  (`str(pass)`, `int(id)`, a Pydantic/JOI/Zod schema, `mongo-sanitize`)
  so operator objects cannot survive.
- Schema validation or an ODM with typed fields rejects non-scalar
  values at the boundary.
- `$where`/`mapReduce`/server-side JS is disabled at the database
  (`--noscripting`) and no such operator is used in code.
- The query document is fully program-controlled with only bound scalar
  values, not attacker-supplied sub-objects.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
