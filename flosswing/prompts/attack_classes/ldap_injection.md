# Attack class: ldap_injection

Untrusted data is placed into an LDAP search filter or a distinguished
name without RFC-4515 (filter) / RFC-4514 (DN) escaping, letting an
attacker alter the filter's logic or the DN's structure. The classic
payload closes the current assertion and injects another — `*)(uid=*` or
`*)(|(uid=*` — turning a scoped lookup into a wildcard match or
defeating an authentication filter. The bug lives where request data
becomes part of the filter/DN *syntax* rather than an escaped assertion
value.

## What to look for

A filter or DN string built by concatenation, interpolation, or
formatting from data that traces back to attacker input (login form
username/password, search boxes, request params), then passed to a
directory search or bind.

- **Python.** `python-ldap` `conn.search_s(base, scope, filterstr)` or
  `ldap3` `conn.search(base, search_filter=...)` where the filter is
  built with `%`, `.format`, f-strings, or `+` over user data — instead
  of escaping each value with `ldap.filter.escape_filter_chars` /
  `ldap3.utils.conv.escape_filter_chars` (and `escape_rdn`/`escape_dn_chars`
  for DNs).
- **Java.** `DirContext.search(name, filter, ...)` / `InitialDirContext`
  with a concatenated `filter` string, or JNDI lookups whose DN is built
  from user input, without `encodeFilter`/manual RFC-4515 escaping.
  Spring LDAP `LdapQueryBuilder` used with a raw interpolated filter
  rather than bound `.where(attr).is(value)`.
- **JavaScript / Node.** `ldapjs` `client.search(base, { filter: '...'
  })` where the filter string is assembled from request fields instead
  of using a parsed/escaped filter object.
- **C# / .NET.** `System.DirectoryServices` `DirectorySearcher.Filter`
  or `DirectoryEntry` paths concatenated from user input without
  escaping.

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

- Each interpolated value is passed through an RFC-4515/4514 escaping
  helper (`escape_filter_chars`, `escape_dn_chars`, `encodeFilter`)
  before reaching the filter/DN.
- The filter is built with a parameterized/bound API (Spring LDAP
  `LdapQueryBuilder.where(...).is(value)`, an `ldap3` assertion object)
  that escapes values internally.
- The value is constrained to an allow-listed set (a fixed attribute
  name, an enum) and never taken raw from the request.
- The interpolated value is a program-controlled constant, not attacker
  data.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
