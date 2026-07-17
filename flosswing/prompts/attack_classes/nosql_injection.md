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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, and `compile_and_run`, reporting through
`record_finding`. The decisive question is *type discipline at the
boundary*: does the request value reach the query still able to be an
object? Use `find_callers`/`grep` to trace the field from the request
parser to the query and check for a cast/validation step. A finding
should carry `file`, `function`, `line_start`, `line_end` at the query
sink, a `description` tracing the untrusted field into the query
document and stating why an object/operator is not rejected, and a
`poc_code` payload (e.g. `password[$ne]=x` or a `{"$gt": ""}` JSON body,
or a `$where` string). `compile_and_run` is genuinely useful here when
you can run the driver against an in-memory/scratch store (e.g.
`mongomock`, an embedded engine) and show the operator payload returning
rows a scalar would not — attach `poc_result` and claim `confirmed`; a
`$where` PoC that evaluates injected JS is likewise `confirmed`. A clean
end-to-end trace without execution is `likely`; an unclear parser shape
or unproven reachability is `speculative`.

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
