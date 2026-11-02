# context-propagation-carrier

Extract and inject W3C-style trace context headers (`traceparent`, `tracestate`) from a flat string map, so a service can hand a trace to the next process over HTTP headers, gRPC metadata, or a message attribute.

```rust
use context_propagation_carrier::{extract, inject, Carrier, TraceContext};

// Receiving side: build a carrier from whatever the transport gave you.
let mut incoming = Carrier::new();
incoming.insert(
    "traceparent".to_string(),
    "00-0a1b2c3d4e5f60718293a4b5c6d7e8f9-1122334455667788-01".to_string(),
);
let ctx = extract(&incoming).expect("valid traceparent");
assert!(ctx.sampled);

// Sending side: inject into the carrier you are about to ship.
let mut outgoing = Carrier::new();
inject(&mut outgoing, &ctx);
assert_eq!(
    outgoing.get("traceparent").map(String::as_str),
    Some("00-0a1b2c3d4e5f60718293a4b5c6d7e8f9-1122334455667788-01"),
);
```

## Why this exists

Every tracing library ships its own carrier abstraction, and they all end up doing the same two things: pull a `traceparent` string out of a map, and push one back in. The interesting part is not the map — it is the parsing rules around it. Trace ids are fixed-width hex, versions other than `00` are forward-compatible in the spec but not round-trippable by a version-`00` writer, and an all-zero id is explicitly invalid. Getting those rules wrong produces a system that looks like it is propagating context until you try to join two traces and discover half your spans have a zero trace id.

The trade-off: I kept `Carrier` as a concrete `BTreeMap<String, String>` instead of a trait. Real transports are string-keyed maps, and a trait would force every caller to write an adapter for no gain. The cost is that callers who hold `HashMap` must convert, and header lookup is case-sensitive — normalise your keys before you call `extract`.

## The awkward edge

Header names are matched exactly. If your HTTP layer hands you `Traceparent` or `TRACEPARENT`, `extract` returns `ParseError::Missing` rather than guessing. This is deliberate: silently lowercasing keys would make the library's behaviour depend on which HTTP stack you happen to use, and would break callers whose carrier is not HTTP at all. Normalise on the way in.

Versions other than `00` are rejected with `ParseError::UnsupportedVersion`, not parsed best-effort. The spec allows a reader to skip unknown fields, but a writer that cannot reproduce the version it read would corrupt the trace, so failing loudly is the honest choice here.

## API

- `Carrier` — `BTreeMap<String, String>`.
- `TraceContext { trace_id: [u8; 16], span_id: [u8; 8], sampled: bool }`.
- `TraceContext::new(trace_id, span_id, sampled) -> Result<Self, ParseError>`.
- `TraceContext::to_traceparent(&self) -> String`.
- `TraceContext::from_traceparent(&str) -> Result<Self, ParseError>`.
- `extract(&Carrier) -> Result<TraceContext, ParseError>`.
- `inject(&mut Carrier, &TraceContext)`.
- `extract_tracestate(&Carrier) -> Option<&str>`.
- `inject_tracestate(&mut Carrier, &str)` — an empty string removes the header.
- `ParseError` — `Missing`, `Malformed`, `UnsupportedVersion(u8)`, `ZeroTraceId`, `ZeroSpanId`.
- Constants `TRACEPARENT` and `TRACESTATE` hold the canonical header names.
