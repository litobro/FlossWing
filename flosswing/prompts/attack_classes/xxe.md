# Attack class: xxe

XML External Entity injection: an XML parser processing untrusted
input is configured to resolve external entities or fetch external
DTDs, letting a crafted document read local files, trigger
server-side requests (SSRF), or exhaust resources (billion-laughs /
entity-expansion DoS). The bug lives where attacker-controlled XML
reaches a parser whose entity/DTD resolution is left enabled.

## What to look for

Untrusted XML (request bodies, SOAP calls, uploaded documents, SVG,
config imports, SAML assertions) parsed by an API that has not been
hardened against DOCTYPE/entity resolution.

- **Python.** `lxml.etree` parsers built with `resolve_entities=True`
  or a `no_network=False` / DTD-loading configuration;
  `xml.etree.ElementTree` / `xml.sax` / `xml.dom.minidom` on untrusted
  input (the stdlib historically resolved entities). `xml.dom.pulldom`
  and `xmlrpc` count too.
- **Java.** `DocumentBuilderFactory`, `SAXParserFactory`,
  `XMLInputFactory`, or `TransformerFactory` used **without**
  `disallow-doctype-decl` set true, without `FEATURE_SECURE_PROCESSING`,
  and with external general/parameter entities left enabled.
- **JavaScript / Node.** `libxmljs` parsed with `{ noent: true }` (which
  substitutes entities); other native XML bindings with entity
  expansion turned on.
- **.NET.** `XmlReader`/`XmlDocument` with a non-null `XmlResolver`
  (e.g. `XmlUrlResolver`) or `DtdProcessing` set to `Parse` on
  untrusted input.
- **C / C++.** `libxml2` used without `XML_PARSE_NONET` /
  `XML_PARSE_NOENT` handling, or with the external-entity loader left
  at its permissive default.

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

- The parser explicitly disables DOCTYPE and external entities
  (`disallow-doctype-decl=true`, `resolve_entities=False`, null
  `XmlResolver`, `defusedxml` in Python). This is the hardened, safe
  shape — do not report it.
- The XML input is entirely program-generated / trusted and never
  attacker-controlled.
- Only local, program-defined internal entities are used, with network
  and DTD loading disabled.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
