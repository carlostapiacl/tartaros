//! Effect log — the first-hand record of what an agent *attempts*, especially
//! toward the outside of its territory (a port scan, a read of a secret, a
//! write outside its roots), independent of whether the wall allowed it.
//!
//! Design goals (why it looks like this):
//! - **Everything, not just denials.** An attempt is a signal even when blocked;
//!   a burst of blocked connects is a port scan. Every event is recorded.
//! - **Modular.** `Collector`s observe (network, filesystem, secrets, …) and
//!   feed one common event stream. Adding an axis = adding a collector.
//! - **Extensible.** `EffectEvent` is an open shape with a free-form `action`
//!   and `target`; `EffectSink` is where events go (a file, a channel, an analyzer).
//! - **Trustworthy.** Collectors observe effects from outside the agent; nothing
//!   here trusts what the agent reports about itself.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Which kind of boundary the attempt touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Axis {
    File,
    Network,
    Secret,
    Process,
    Mcp,
    Other,
}

impl Axis {
    pub fn as_str(&self) -> &'static str {
        match self {
            Axis::File => "file",
            Axis::Network => "network",
            Axis::Secret => "secret",
            Axis::Process => "process",
            Axis::Mcp => "mcp",
            Axis::Other => "other",
        }
    }
}

/// Where the attempt points relative to the agent's territory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    WithinTerritory,
    OutsideTerritory,
    Unknown,
}

impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::WithinTerritory => "within",
            Direction::OutsideTerritory => "outside",
            Direction::Unknown => "unknown",
        }
    }
}

/// What the wall did with it, when known. A collector that only observes may not
/// know; it records `Attempted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Attempted,
    Allowed,
    Denied,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Attempted => "attempted",
            Outcome::Allowed => "allowed",
            Outcome::Denied => "denied",
        }
    }
}

/// One observed attempt. `action` and `target` are free-form so new collectors
/// need no change here: e.g. ("connect", "8.8.8.8:53"), ("write", "/etc/hosts"),
/// ("read", "~/.ssh/id_ed25519"), ("scan", "127.0.0.1:1-1024").
#[derive(Debug, Clone)]
pub struct EffectEvent {
    pub ts_unix_ms: u128,
    pub role: String,
    pub axis: Axis,
    pub action: String,
    pub target: String,
    pub direction: Direction,
    pub outcome: Outcome,
    /// Which collector produced this, e.g. "net/proc", "net/lsof", "seatbelt-log".
    pub source: String,
}

impl EffectEvent {
    pub fn now(
        role: impl Into<String>,
        axis: Axis,
        action: impl Into<String>,
        target: impl Into<String>,
        direction: Direction,
        outcome: Outcome,
        source: impl Into<String>,
    ) -> Self {
        EffectEvent {
            ts_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            role: role.into(),
            axis,
            action: action.into(),
            target: target.into(),
            direction,
            outcome,
            source: source.into(),
        }
    }

    /// One JSON object, no trailing newline. Hand-rolled to keep `core`
    /// dependency-free; the field set is stable so external readers can rely on it.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"ts\":{},\"role\":{},\"axis\":\"{}\",\"action\":{},\"target\":{},\"direction\":\"{}\",\"outcome\":\"{}\",\"source\":{}}}",
            self.ts_unix_ms,
            json_str(&self.role),
            self.axis.as_str(),
            json_str(&self.action),
            json_str(&self.target),
            self.direction.as_str(),
            self.outcome.as_str(),
            json_str(&self.source),
        )
    }
}

/// Minimal JSON string escaping.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Where events go. Object-safe so backends can hold `&mut dyn EffectSink`.
pub trait EffectSink {
    fn emit(&mut self, event: &EffectEvent);
}

/// Append events as JSON Lines to any writer (a file, stdout, a pipe to an analyzer).
pub struct JsonlSink<W: Write> {
    writer: W,
}

impl<W: Write> JsonlSink<W> {
    pub fn new(writer: W) -> Self {
        JsonlSink { writer }
    }
}

impl<W: Write> EffectSink for JsonlSink<W> {
    fn emit(&mut self, event: &EffectEvent) {
        // Best-effort: a logging failure must never break enforcement. One write per
        // line: the supervisor and the egress broker append to the same log file from
        // two handles, and `writeln!` may split a line across several writes, which
        // could interleave with the other writer's line.
        let _ = self.writer.write_all(format!("{}\n", event.to_json()).as_bytes());
    }
}

/// W3C Trace Context of the launcher (`TRACEPARENT`), so the records of a run join
/// the launcher's own spans in any OpenTelemetry tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
}

impl TraceContext {
    /// `00-<32 hex trace id>-<16 hex span id>-<2 hex flags>`; `None` if malformed or
    /// an all-zero id (invalid by the spec).
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.trim().split('-').collect();
        let hex = |x: &str, n: usize| x.len() == n && x.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        if parts.len() < 4 || !hex(parts[0], 2) || parts[0] == "ff" || !hex(parts[1], 32) || !hex(parts[2], 16) || !hex(parts[3], 2) {
            return None;
        }
        if parts[0] == "00" && parts.len() != 4 {
            return None;
        }
        if parts[1].bytes().all(|b| b == b'0') || parts[2].bytes().all(|b| b == b'0') {
            return None;
        }
        Some(TraceContext { trace_id: parts[1].to_string(), span_id: parts[2].to_string() })
    }

    /// From this process's `TRACEPARENT`, if set and valid.
    pub fn from_env() -> Option<Self> {
        std::env::var("TRACEPARENT").ok().and_then(|v| Self::parse(&v))
    }
}

impl EffectEvent {
    /// One OpenTelemetry Event Record as an OTLP/JSON `ExportLogsServiceRequest`, no
    /// trailing newline: the open effect schema (`effect.*` attributes, readable by any
    /// OTLP tool), stamped with the launcher's trace context when there is one. The
    /// broker's connect decisions use the generic action `connect` (the outcome says
    /// allowed or denied); the original action is kept in `tartaros.action`.
    pub fn to_otlp(&self, trace: Option<&TraceContext>) -> String {
        let action = if self.action.starts_with("broker-connect") { "connect" } else { self.action.as_str() };
        let attr = |k: &str, v: &str| format!("{{\"key\":\"{k}\",\"value\":{{\"stringValue\":{}}}}}", json_str(v));
        let attrs = [
            attr("effect.axis", self.axis.as_str()),
            attr("effect.action", action),
            attr("effect.target", &self.target),
            attr("effect.outcome", self.outcome.as_str()),
            attr("effect.source", &format!("tartaros/{}", self.source)),
            attr("tartaros.action", &self.action),
            attr("tartaros.direction", self.direction.as_str()),
            attr("tartaros.role", &self.role),
        ]
        .join(",");
        let ts = self.ts_unix_ms * 1_000_000;
        let trace = trace
            .map(|t| format!(",\"traceId\":\"{}\",\"spanId\":\"{}\"", t.trace_id, t.span_id))
            .unwrap_or_default();
        let body = format!("{action} {}", self.target);
        format!(
            "{{\"resourceLogs\":[{{\"resource\":{{\"attributes\":[{}]}},\"scopeLogs\":[{{\"scope\":{{\"name\":\"tartaros\",\"version\":\"{}\"}},\"logRecords\":[{{\"timeUnixNano\":\"{ts}\",\"observedTimeUnixNano\":\"{ts}\",\"eventName\":\"effect.{}\",\"severityText\":\"INFO\",\"body\":{{\"stringValue\":{}}},\"attributes\":[{attrs}]{trace}}}]}}]}}]}}",
            attr("service.name", "tartaros"),
            env!("CARGO_PKG_VERSION"),
            self.axis.as_str(),
            json_str(&body),
        )
    }
}

/// Append events as OTLP/JSON lines (one `ExportLogsServiceRequest` per line, the
/// OpenTelemetry Collector file exporter's shape) with the launcher's trace context.
pub struct OtlpSink<W: Write> {
    writer: W,
    trace: Option<TraceContext>,
}

impl<W: Write> OtlpSink<W> {
    pub fn new(writer: W, trace: Option<TraceContext>) -> Self {
        OtlpSink { writer, trace }
    }
}

impl<W: Write> EffectSink for OtlpSink<W> {
    fn emit(&mut self, event: &EffectEvent) {
        // one write per line, as JsonlSink
        let _ = self.writer.write_all(format!("{}\n", event.to_otlp(self.trace.as_ref())).as_bytes());
    }
}

/// Drops every event: a sink for when nothing is recorded.
pub struct DiscardSink;

impl EffectSink for DiscardSink {
    fn emit(&mut self, _event: &EffectEvent) {}
}

/// How much to record. Pick the mode per run (or per role).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordMode {
    /// Record nothing.
    Off,
    /// Only attempts the wall blocked.
    DeniedOnly,
    /// Only attempts that reach outside the territory (the security-relevant
    /// ones), whether allowed or not — a port scan, a read of a secret.
    OutsideOnly,
    /// Everything that crosses a boundary: outside-territory OR denied.
    Boundary,
    /// Everything observed, including within-territory activity.
    All,
}

impl RecordMode {
    fn keeps(&self, e: &EffectEvent) -> bool {
        match self {
            RecordMode::Off => false,
            RecordMode::DeniedOnly => e.outcome == Outcome::Denied,
            RecordMode::OutsideOnly => e.direction == Direction::OutsideTerritory,
            RecordMode::Boundary => {
                e.direction == Direction::OutsideTerritory || e.outcome == Outcome::Denied
            }
            RecordMode::All => true,
        }
    }
}

/// Wraps any sink and forwards only events that match the mode (and, optionally,
/// a set of axes). Compose it around a `JsonlSink` to get a logging mode.
pub struct FilterSink<S: EffectSink> {
    mode: RecordMode,
    axes: Option<std::collections::HashSet<Axis>>,
    inner: S,
}

impl<S: EffectSink> FilterSink<S> {
    pub fn new(inner: S, mode: RecordMode) -> Self {
        FilterSink { mode, axes: None, inner }
    }

    /// Restrict to these axes as well (e.g. only network + secret).
    pub fn with_axes(mut self, axes: impl IntoIterator<Item = Axis>) -> Self {
        self.axes = Some(axes.into_iter().collect());
        self
    }

    fn passes(&self, e: &EffectEvent) -> bool {
        if let Some(axes) = &self.axes {
            if !axes.contains(&e.axis) {
                return false;
            }
        }
        self.mode.keeps(e)
    }
}

impl<S: EffectSink> EffectSink for FilterSink<S> {
    fn emit(&mut self, event: &EffectEvent) {
        if self.passes(event) {
            self.inner.emit(event);
        }
    }
}

/// Collect events into memory — handy for tests and for buffering.
#[derive(Default)]
pub struct VecSink {
    pub events: Vec<EffectEvent>,
}

impl EffectSink for VecSink {
    fn emit(&mut self, event: &EffectEvent) {
        self.events.push(event.clone());
    }
}

/// An observer of one axis. Poll it periodically during a run; it emits what it
/// has seen since last time. Implementations live in the `collect` crate so new
/// ones can be added without touching `core`.
pub trait Collector {
    fn name(&self) -> &str;
    /// Observe now and emit any new effects into `sink`.
    fn poll(&mut self, sink: &mut dyn EffectSink);
}

#[cfg(test)]
mod tests {
    #[test]
    fn traceparent_is_parsed_per_the_w3c_format() {
        let t = TraceContext::parse("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01").unwrap();
        assert_eq!((t.trace_id.as_str(), t.span_id.as_str()), ("0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331"));
        for bad in [
            "",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331",       // no flags
            "00-0AF7651916CD43DD8448EB211C80319C-b7ad6b7169203331-01",   // uppercase
            "00-00000000000000000000000000000000-b7ad6b7169203331-01",   // zero trace id
            "00-0af7651916cd43dd8448eb211c80319c-0000000000000000-01",   // zero span id
            "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",   // invalid version
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01-x", // v00 has exactly 4 parts
            "00-0af7651916cd43dd8448eb211c8031-b7ad6b7169203331-01",     // short trace id
        ] {
            assert!(TraceContext::parse(bad).is_none(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn otlp_lines_carry_the_open_effect_schema_and_the_trace() {
        let e = EffectEvent::now("agent", Axis::Network, "broker-connect-denied", "github.com:443",
            Direction::OutsideTerritory, Outcome::Denied, "broker");
        let t = TraceContext::parse("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01");
        let v: serde_json::Value = serde_json::from_str(&e.to_otlp(t.as_ref())).expect("valid JSON");
        let r = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(r["eventName"], "effect.network");
        assert_eq!(r["traceId"], "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(r["spanId"], "b7ad6b7169203331");
        assert_eq!(r["timeUnixNano"], (e.ts_unix_ms * 1_000_000).to_string());
        let a = |k: &str| r["attributes"].as_array().unwrap().iter().find(|x| x["key"] == k).map(|x| x["value"]["stringValue"].clone());
        assert_eq!(a("effect.action").unwrap(), "connect", "the broker's verbs map to the generic connect");
        assert_eq!(a("effect.outcome").unwrap(), "denied");
        assert_eq!(a("effect.target").unwrap(), "github.com:443");
        assert_eq!(a("effect.source").unwrap(), "tartaros/broker");
        assert_eq!(a("tartaros.action").unwrap(), "broker-connect-denied");
        // no trace: no ids; and hostile text stays inside its JSON string
        let odd = EffectEvent::now("r\"o", Axis::File, "read", "/a\"b\\c\n", Direction::WithinTerritory, Outcome::Allowed, "x");
        let v: serde_json::Value = serde_json::from_str(&odd.to_otlp(None)).expect("valid JSON with quotes in it");
        assert!(v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0].get("traceId").is_none());
    }

    #[test]
    fn a_line_is_written_in_one_write() {
        // two writers append to the same log: a line split over several writes could interleave
        struct Count(Vec<usize>);
        impl std::io::Write for Count {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> { self.0.push(b.len()); Ok(b.len()) }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let e = EffectEvent::now("agent", Axis::File, "write", "/x", Direction::WithinTerritory, Outcome::Allowed, "fs");
        let mut j = JsonlSink::new(Count(vec![]));
        j.emit(&e);
        assert_eq!(j.writer.0.len(), 1, "jsonl: one write per line");
        let mut o = OtlpSink::new(Count(vec![]), None);
        o.emit(&e);
        assert_eq!(o.writer.0.len(), 1, "otlp: one write per line");
    }

    use super::*;

    #[test]
    fn json_is_well_formed_and_escaped() {
        let e = EffectEvent::now(
            "qa",
            Axis::Network,
            "connect",
            "8.8.8.8:53",
            Direction::OutsideTerritory,
            Outcome::Denied,
            "net/proc",
        );
        let j = e.to_json();
        assert!(j.starts_with('{') && j.ends_with('}'));
        assert!(j.contains("\"axis\":\"network\""));
        assert!(j.contains("\"direction\":\"outside\""));
        assert!(j.contains("\"outcome\":\"denied\""));
        assert!(j.contains("\"target\":\"8.8.8.8:53\""));
    }

    #[test]
    fn jsonl_sink_writes_one_line_per_event() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut sink = JsonlSink::new(&mut buf);
            sink.emit(&EffectEvent::now("r", Axis::File, "write", "/etc/hosts", Direction::OutsideTerritory, Outcome::Denied, "t"));
            sink.emit(&EffectEvent::now("r", Axis::Secret, "read", "~/.ssh/id", Direction::OutsideTerritory, Outcome::Attempted, "t"));
        }
        let s = String::from_utf8(buf).unwrap();
        assert_eq!(s.lines().count(), 2);
        assert!(s.lines().all(|l| l.starts_with('{') && l.ends_with('}')));
    }

    #[test]
    fn vec_sink_collects() {
        let mut sink = VecSink::default();
        sink.emit(&EffectEvent::now("r", Axis::Network, "connect", "x", Direction::Unknown, Outcome::Attempted, "t"));
        assert_eq!(sink.events.len(), 1);
    }

    fn ev(dir: Direction, out: Outcome, axis: Axis) -> EffectEvent {
        EffectEvent::now("r", axis, "a", "t", dir, out, "s")
    }

    #[test]
    fn record_modes_filter_as_expected() {
        use Direction::*;
        use Outcome::*;
        let within_allowed = ev(WithinTerritory, Allowed, Axis::Network);
        let outside_allowed = ev(OutsideTerritory, Allowed, Axis::Network);
        let within_denied = ev(WithinTerritory, Denied, Axis::File);

        let run = |mode: RecordMode, e: &EffectEvent| {
            let mut s = FilterSink::new(VecSink::default(), mode);
            s.emit(e);
            s.inner.events.len()
        };

        assert_eq!(run(RecordMode::Off, &outside_allowed), 0);
        assert_eq!(run(RecordMode::All, &within_allowed), 1);
        assert_eq!(run(RecordMode::OutsideOnly, &within_allowed), 0);
        assert_eq!(run(RecordMode::OutsideOnly, &outside_allowed), 1);
        assert_eq!(run(RecordMode::DeniedOnly, &outside_allowed), 0);
        assert_eq!(run(RecordMode::DeniedOnly, &within_denied), 1);
        assert_eq!(run(RecordMode::Boundary, &within_denied), 1); // denied
        assert_eq!(run(RecordMode::Boundary, &outside_allowed), 1); // outside
        assert_eq!(run(RecordMode::Boundary, &within_allowed), 0); // neither
    }

    #[test]
    fn axis_filter_restricts() {
        let mut s = FilterSink::new(VecSink::default(), RecordMode::All).with_axes([Axis::Secret]);
        s.emit(&ev(Direction::OutsideTerritory, Outcome::Attempted, Axis::Network));
        s.emit(&ev(Direction::OutsideTerritory, Outcome::Attempted, Axis::Secret));
        assert_eq!(s.inner.events.len(), 1);
        assert_eq!(s.inner.events[0].axis, Axis::Secret);
    }
}
