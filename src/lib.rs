//! Extract and inject trace context headers from flat string maps for
//! cross-process distributed tracing.
//!
//! The carrier format follows the W3C Trace Context specification shape:
//! a `traceparent` header carrying `version-traceid-parentid-flags`, plus an
//! optional `tracestate` header carrying vendor key/value pairs. We only
//! implement the parts we can test deterministically: parsing, validating,
//! and serialising the headers. No clocks, no randomness, no I/O.
//!
//! Design choice: a `Carrier` is just a `BTreeMap<String, String>`, not a
//! trait. Distributed tracing libraries usually want to inject into HTTP
//! headers, gRPC metadata, or message attributes; every one of those is
//! a string-keyed map in practice. Keeping the carrier concrete avoids a
//! generic trait that callers would have to implement for no benefit.

use std::collections::BTreeMap;
use std::fmt;

/// A flat string map used as the transport for trace context headers.
///
/// We use `BTreeMap` rather than `HashMap` so iteration order is stable:
/// tests and diagnostics that print the carrier get the same order every
/// run, and serialised carriers are reproducible.
pub type Carrier = BTreeMap<String, String>;

/// The canonical header name for the trace context parent.
pub const TRACEPARENT: &str = "traceparent";

/// The canonical header name for vendor trace state.
pub const TRACESTATE: &str = "tracestate";

/// Errors that can occur while parsing a trace context header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The header was absent from the carrier.
    Missing,
    /// The header was present but structurally malformed.
    Malformed,
    /// The header used an unsupported version.
    UnsupportedVersion(u8),
    /// The header carried an all-zero trace id, which is invalid.
    ZeroTraceId,
    /// The header carried an all-zero span id, which is invalid.
    ZeroSpanId,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Missing => write!(f, "trace context header is missing"),
            ParseError::Malformed => write!(f, "trace context header is malformed"),
            ParseError::UnsupportedVersion(v) => {
                write!(f, "unsupported trace context version: {v}")
            }
            ParseError::ZeroTraceId => write!(f, "trace id must not be all zeroes"),
            ParseError::ZeroSpanId => write!(f, "span id must not be all zeroes"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed W3C-style trace context.
///
/// `trace_id` is 16 bytes (32 hex digits) and `span_id` is 8 bytes
/// (16 hex digits), matching the W3C Trace Context recommendation. We
/// store them as fixed-size arrays rather than `String` so that invalid
/// lengths are impossible to construct and comparisons are cheap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub sampled: bool,
}

impl TraceContext {
    /// Construct a context from raw bytes.
    ///
    /// Returns `ParseError::ZeroTraceId` or `ParseError::ZeroSpanId` if
    /// either id is all zeroes, since the specification forbids those.
    pub fn new(trace_id: [u8; 16], span_id: [u8; 8], sampled: bool) -> Result<Self, ParseError> {
        if trace_id.iter().all(|&b| b == 0) {
            return Err(ParseError::ZeroTraceId);
        }
        if span_id.iter().all(|&b| b == 0) {
            return Err(ParseError::ZeroSpanId);
        }
        Ok(TraceContext {
            trace_id,
            span_id,
            sampled,
        })
    }

    /// Serialise to the `traceparent` header value.
    ///
    /// We always emit version `00` and the two flag bits we understand.
    /// Lowercase hex is required by the specification.
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            hex_encode(&self.trace_id),
            hex_encode(&self.span_id),
            if self.sampled { 1u8 } else { 0u8 },
        )
    }

    /// Parse a `traceparent` header value.
    ///
    /// The grammar we accept is exactly:
    /// `version "-" trace-id "-" span-id "-" flags`, all lowercase hex,
    /// with version `00` and flags a single byte. Versions other than `00`
    /// are rejected with `UnsupportedVersion`; the specification allows
    /// forward-compatible parsing, but silently accepting unknown versions
    /// would let a caller inject a header we cannot round-trip, so we fail
    /// loudly instead.
    pub fn from_traceparent(value: &str) -> Result<Self, ParseError> {
        let mut parts = value.split('-');
        let version = parts.next().ok_or(ParseError::Malformed)?;
        let trace_hex = parts.next().ok_or(ParseError::Malformed)?;
        let span_hex = parts.next().ok_or(ParseError::Malformed)?;
        let flags_hex = parts.next().ok_or(ParseError::Malformed)?;
        if parts.next().is_some() {
            return Err(ParseError::Malformed);
        }
        if version.len() != 2 || !version.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ParseError::Malformed);
        }
        let version_byte = u8::from_str_radix(version, 16).map_err(|_| ParseError::Malformed)?;
        if version_byte != 0 {
            return Err(ParseError::UnsupportedVersion(version_byte));
        }
        if trace_hex.len() != 32 || !trace_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ParseError::Malformed);
        }
        if span_hex.len() != 16 || !span_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ParseError::Malformed);
        }
        if flags_hex.len() != 2 || !flags_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ParseError::Malformed);
        }
        let trace_id = hex_decode_16(trace_hex).ok_or(ParseError::Malformed)?;
        let span_id = hex_decode_8(span_hex).ok_or(ParseError::Malformed)?;
        let flags = u8::from_str_radix(flags_hex, 16).map_err(|_| ParseError::Malformed)?;
        TraceContext::new(trace_id, span_id, flags & 0x01 != 0)
    }
}

/// Extract a trace context from a carrier.
///
/// Returns `ParseError::Missing` if the `traceparent` key is absent.
/// Header lookup is case-sensitive on the key, because the carrier is a
/// plain map and the caller controls how it was populated; callers that
/// receive HTTP headers should normalise them before calling.
pub fn extract(carrier: &Carrier) -> Result<TraceContext, ParseError> {
    let value = carrier.get(TRACEPARENT).ok_or(ParseError::Missing)?;
    TraceContext::from_traceparent(value)
}

/// Inject a trace context into a carrier, overwriting any existing values.
pub fn inject(carrier: &mut Carrier, ctx: &TraceContext) {
    carrier.insert(TRACEPARENT.to_string(), ctx.to_traceparent());
}

/// Extract the vendor `tracestate` header, if present.
///
/// The value is returned as-is; we do not validate it because the
/// specification permits vendor-specific grammar that we cannot know.
pub fn extract_tracestate(carrier: &Carrier) -> Option<&str> {
    carrier.get(TRACESTATE).map(|s| s.as_str())
}

/// Inject a `tracestate` header into a carrier.
///
/// An empty string removes the header rather than storing an empty value,
/// because an empty `tracestate` is equivalent to an absent one and
/// storing it would confuse downstream parsers.
pub fn inject_tracestate(carrier: &mut Carrier, value: &str) {
    if value.is_empty() {
        carrier.remove(TRACESTATE);
    } else {
        carrier.insert(TRACESTATE.to_string(), value.to_string());
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode_16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_decode_8(s: &str) -> Option<[u8; 8]> {
    if s.len() != 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TraceContext {
        TraceContext::new(
            [
                0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7,
                0xe8, 0xf9,
            ],
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            true,
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_traceparent() {
        let ctx = sample();
        let header = ctx.to_traceparent();
        assert_eq!(header, "00-0a1b2c3d4e5f60718293a4b5c6d7e8f9-1122334455667788-01");
        let parsed = TraceContext::from_traceparent(&header).unwrap();
        assert_eq!(parsed, ctx);
    }

    #[test]
    fn unsampled_flag_roundtrips() {
        let ctx = TraceContext::new([1u8; 16], [2u8; 8], false).unwrap();
        let header = ctx.to_traceparent();
        assert!(header.ends_with("-00"));
        let parsed = TraceContext::from_traceparent(&header).unwrap();
        assert!(!parsed.sampled);
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        // The specification says lowercase, but we accept uppercase on input
        // because some HTTP stacks normalise hex case. We never emit it.
        let value = "00-0A1B2C3D4E5F60718293A4B5C6D7E8F9-1122334455667788-01";
        let parsed = TraceContext::from_traceparent(value).unwrap();
        assert_eq!(parsed.trace_id[0], 0x0a);
        assert!(parsed.sampled);
    }

    #[test]
    fn rejects_unknown_version() {
        let value = "01-0a1b2c3d4e5f60718293a4b5c6d7e8f9-1122334455667788-01";
        assert_eq!(
            TraceContext::from_traceparent(value),
            Err(ParseError::UnsupportedVersion(1))
        );
    }

    #[test]
    fn rejects_malformed_shapes() {
        let cases = [
            "",
            "00",
            "00-0a1b2c3d4e5f60718293a4b5c6d7e8f9",
            "00-0a1b2c3d4e5f60718293a4b5c6d7e8f9-1122334455667788",
            "00-0a1b2c3d4e5f60718293a4b5c6d7e8f9-1122334455667788-01-extra",
            "00-0a1b2c3d4e5f60718293a4b5c6d7e8f9-1122334455667788-0g",
            "00-0a1b2c3d4e5f60718293a4b5c6d7e8f9-112233445566778-01",
            "00-0a1b2c3d4e5f60718293a4b5c6d7e8f-1122334455667788-01",
        ];
        for case in cases {
            assert_eq!(
                TraceContext::from_traceparent(case),
                Err(ParseError::Malformed),
                "expected malformed for {case:?}"
            );
        }
    }

    #[test]
    fn rejects_all_zero_ids() {
        let zero_trace = "00-00000000000000000000000000000000-1122334455667788-01";
        assert_eq!(
            TraceContext::from_traceparent(zero_trace),
            Err(ParseError::ZeroTraceId)
        );
        let zero_span = "00-0a1b2c3d4e5f60718293a4b5c6d7e8f9-0000000000000000-01";
        assert_eq!(
            TraceContext::from_traceparent(zero_span),
            Err(ParseError::ZeroSpanId)
        );
    }

    #[test]
    fn extract_missing_returns_missing() {
        let carrier = Carrier::new();
        assert_eq!(extract(&carrier), Err(ParseError::Missing));
    }

    #[test]
    fn inject_then_extract() {
        let mut carrier = Carrier::new();
        let ctx = sample();
        inject(&mut carrier, &ctx);
        assert_eq!(extract(&carrier).unwrap(), ctx);
    }

    #[test]
    fn inject_overwrites_existing() {
        let mut carrier = Carrier::new();
        carrier.insert(TRACEPARENT.to_string(), "garbage".to_string());
        let ctx = sample();
        inject(&mut carrier, &ctx);
        assert_eq!(extract(&carrier).unwrap(), ctx);
    }

    #[test]
    fn tracestate_roundtrip_and_removal() {
        let mut carrier = Carrier::new();
        assert_eq!(extract_tracestate(&carrier), None);
        inject_tracestate(&mut carrier, "vendor=value");
        assert_eq!(extract_tracestate(&carrier), Some("vendor=value"));
        inject_tracestate(&mut carrier, "");
        assert_eq!(extract_tracestate(&carrier), None);
    }

    #[test]
    fn new_rejects_zero_ids() {
        assert_eq!(
            TraceContext::new([0u8; 16], [1u8; 8], false),
            Err(ParseError::ZeroTraceId)
        );
        assert_eq!(
            TraceContext::new([1u8; 16], [0u8; 8], false),
            Err(ParseError::ZeroSpanId)
        );
    }

    #[test]
    fn flags_other_bits_are_ignored() {
        // Only bit 0 is the sampled flag; other bits are reserved. We keep
        // parsing rather than rejecting, and we do not preserve them.
        let value = "00-0a1b2c3d4e5f60718293a4b5c6d7e8f9-1122334455667788-ff";
        let parsed = TraceContext::from_traceparent(value).unwrap();
        assert!(parsed.sampled);
        assert_eq!(parsed.to_traceparent(), "00-0a1b2c3d4e5f60718293a4b5c6d7e8f9-1122334455667788-01");
    }
}
