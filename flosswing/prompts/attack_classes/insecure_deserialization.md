# Attack class: insecure_deserialization

Untrusted bytes are handed to a deserializer that can instantiate
arbitrary types or invoke gadget chains during decoding, turning a
data payload into code execution or object-injection. The bug lives
where attacker-controlled bytes reach a format/library that embeds
type information and reconstructs objects, rather than parsing into a
fixed, known shape. This is the **polyglot umbrella** class: when a
language-specific class fits (`unsafe_yaml`, `unsafe_pickle`,
`java_deserialization`), that one wins and you should record there.
This fragment covers the remaining serializers.

## What to look for

Deserialization of attacker-influenced bytes (request bodies, cookies,
cache/session blobs, message-queue payloads, uploaded files) by a
type-embedding or gadget-capable decoder.

- **PHP.** `unserialize($userData)` on request/cookie data; magic
  methods (`__wakeup`, `__destruct`) in reachable classes form the
  gadget chain. Phar deserialization via filesystem functions on a
  `phar://` path counts too.
- **Ruby.** `Marshal.load` / `Marshal.restore` on untrusted bytes;
  `Oj.load` in a mode that instantiates arbitrary objects; YAML/CSV
  loaders that build objects.
- **.NET.** `BinaryFormatter.Deserialize`, `SoapFormatter`,
  `NetDataContractSerializer`, `LosFormatter`, and `Json.NET`
  configured with `TypeNameHandling` set to anything other than `None`
  (especially `All`/`Auto`) on untrusted JSON.
- **General type-embedding decoders.** Any serializer that writes a
  concrete type/class name into the payload and re-creates it on read
  — polymorphic JSON/XML binders, `readObject`-style APIs in other
  ecosystems, language-native object dumpers.

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

- The payload is parsed into a plain struct/DTO with **no type
  metadata** (e.g. `JSON.parse` to a fixed schema, `Json.NET` with
  `TypeNameHandling=None`, a strict struct binder). This is the safe
  shape — do not report it.
- The serialized bytes are signed or encrypted with a server-held key
  and integrity is verified before decoding.
- The decoder is restricted to an allowlist of expected types, or the
  input provably originates only from trusted server-side code.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
