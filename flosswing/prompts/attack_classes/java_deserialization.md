# Attack class: java_deserialization

Java native deserialization of untrusted bytes reconstructs arbitrary
object graphs, and gadget chains present on the classpath turn that
reconstruction into remote code execution. The bug lives where an
attacker-controlled stream reaches a deserializer that will instantiate
whatever classes the bytes name, without a class allowlist or type
restriction. It also covers polymorphic-typing misconfigurations in
object mappers that let the payload choose the concrete type.

## What to look for

A deserialization sink fed bytes tracing back to attacker-controlled
input (HTTP bodies, headers/cookies carrying serialized blobs, message
queues, uploaded files, RMI/JMX endpoints, session stores) with no
look-ahead class filtering.

- **Native serialization.** `ObjectInputStream.readObject()` /
  `readUnshared()` over a stream built from request data, and any
  wrapper (`SerializationUtils.deserialize`, custom `readObject`
  helpers) that forwards to it. RMI/JMX/JNDI endpoints that
  deserialize are the classic remote reach.
- **Object mappers with default typing.** Jackson
  `ObjectMapper.enableDefaultTyping()` /
  `activateDefaultTyping(...)` or `@JsonTypeInfo(use = Id.CLASS /
  Id.MINIMAL_CLASS)` on a polymorphic field, letting the JSON name the
  class to construct.
- **Other binary/XML deserializers.** XStream `fromXML` without a
  configured permission allowlist, Kryo with default (unregistered)
  class resolution, and similar libraries that instantiate by embedded
  class name.
- **Gadget surface.** Note known gadget libraries on the classpath
  (Commons-Collections, Spring, Groovy, etc.) — their presence is what
  makes a `readObject` reachable-from-untrusted-input a critical RCE
  rather than a crash.

## Evidence

You have `read_file`, `list_dir`, `grep`, `find_definition`,
`find_callers`, `compile_and_run`, and `record_finding`. A finding
should carry `file`, `function`, `line_start`, `line_end` at the
deserialization sink; a `description` tracing where the untrusted bytes
enter, that the sink reconstructs arbitrary classes, whether a filter is
absent, and any gadget libraries present; and a `poc_code` sketch
describing the serialized gadget payload (naming the chain if
identifiable). A full RCE PoC needs the target's exact classpath and is
usually impractical to build in the sandbox — do not force it. Prefer
`confidence=likely` when you trace untrusted bytes into an unfiltered
`readObject`/default-typing sink end-to-end; reserve `confirmed` for a
reachability trace (or the rare runnable case) that establishes the sink
receives attacker bytes with no allowlist; use `speculative` when the
stream's untrustedness or a global filter's coverage is unclear.

## Common false positives

- No native deserialization of untrusted input occurs — the app parses
  plain JSON into DTOs with default typing disabled (Jackson's default),
  which does not instantiate attacker-named classes.
- A look-ahead / allowlist filter guards the stream: a JEP 290
  `ObjectInputFilter` (`setObjectInputFilter` / `jdk.serialFilter`),
  Apache Commons IO `ValidatingObjectInputStream` with an accept-list,
  or XStream/Kryo configured with an explicit class allowlist.
- The deserialized bytes are program-controlled (internal cache,
  trusted-peer stream), not attacker-reachable.
- Polymorphic typing is scoped to a validated base type via a
  `PolymorphicTypeValidator` allowlist rather than open default typing.

## Stop condition

After one pass through the `scope_hint`, stop. Record zero or more
findings via `record_finding`. Recording zero findings is a valid
outcome.
