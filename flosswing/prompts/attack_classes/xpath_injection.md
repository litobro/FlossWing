# Attack class: xpath_injection

Untrusted data is concatenated into an XPath expression, letting an
attacker rewrite the query to select nodes they should not reach or to
defeat an XPath-based authentication check. The classic payload closes
a predicate and injects an always-true clause — `' or '1'='1` — turning
a scoped node lookup (`//user[name='x' and pass='y']`) into a match on
every node. The bug lives where request data becomes part of the XPath
*syntax* rather than a bound variable.

## What to look for

An XPath string built by concatenation, interpolation, or formatting
from data tracing back to attacker input (login fields, search params,
request bodies), then evaluated against an XML document.

- **Python.** `lxml` `tree.xpath(expr)` / `etree.XPath(expr)` where
  `expr` is built with `%`, `.format`, f-strings, or `+` over user data
  — instead of a compiled expression with bound variables
  (`tree.xpath("//user[name=$n]", n=value)`). `ElementTree.findall`
  with an interpolated path counts too.
- **Java.** `javax.xml.xpath` `XPath.compile(expr)` / `xpath.evaluate(
  expr, doc)` with a concatenated `expr`, instead of a static expression
  plus an `XPathVariableResolver` binding the values.
- **C# / .NET.** `System.Xml` `XmlNode.SelectNodes(xpath)` /
  `SelectSingleNode(xpath)` or `XPathNavigator.Select` with a
  concatenated string, rather than `XPathExpression` with bound
  variables via an `XsltArgumentList`/`IXmlNamespaceResolver`.
- **JavaScript / other.** `document.evaluate` / DOM XPath or any binding
  where the expression string is assembled from request fields.

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

- The expression is parameterized: a static XPath with `$var`
  placeholders and values bound via an `XPathVariableResolver` /
  `XsltArgumentList` / `lxml` keyword arguments. This is the safe shape
  — do not report it.
- Interpolated values pass through XPath-string escaping / are quoted and
  the quoting is proven safe against the injected quote char.
- The value is constrained to an allow-listed set (a fixed node name, an
  enum) and never taken raw from the request.
- The interpolated value is a program-controlled constant, not attacker
  data.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
