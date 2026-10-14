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
        // Best-effort: a logging failure must never break enforcement.
        let _ = writeln!(self.writer, "{}", event.to_json());
    }
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
