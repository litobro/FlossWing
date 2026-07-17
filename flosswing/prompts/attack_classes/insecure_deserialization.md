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

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. Trace the
bytes from the entry point (which header/field/cookie) to the decode
sink; use `find_callers` to confirm the payload is attacker-reachable
and not internally produced. A finding should carry `file`,
`function`, `line_start`, `line_end` at the deserialize call and a
`description` naming the decoder, why type metadata is honored, and a
plausible gadget/injection path. A self-contained `compile_and_run`
PoC that feeds a crafted payload and demonstrates unintended object
construction or a side effect earns `confidence=confirmed` (attach
`poc_result`). An end-to-end trace without execution is `likely`;
inability to establish that a usable gadget exists in scope is
`speculative`.

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
