//! `--log` and `--egress-log`: where the effect log goes and in which format.

/// Two sinks fed the same events: the egress broker's refusals go to stderr and
/// to the run's --log.
pub(crate) struct Tee<A, B>(pub(crate) A, pub(crate) B);

impl<A: tartaros_core::EffectSink, B: tartaros_core::EffectSink + ?Sized> tartaros_core::EffectSink for Tee<A, Box<B>> {
    fn emit(&mut self, e: &tartaros_core::EffectEvent) {
        self.0.emit(e);
        self.1.emit(e);
    }
}

/// Where and how `--log` writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogSpec {
    pub(crate) path: String,
    pub(crate) format: LogFormat,
}

/// `--egress-log FILE`: only the egress broker's decisions, as JSON lines, with
/// no effect collectors. `--log` turns those on too, and they cost a launcher
/// that only wants the refused hosts more than a second a run (measured, macOS).
pub(crate) static EGRESS_LOG: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogFormat {
    Jsonl,
    Otlp,
}

/// The `--log` sink: one of the two formats over an append-mode file. Each line
/// goes out in one write, so the supervisor and the egress broker can append to
/// the same file from their own handles.
pub(crate) enum LogSink {
    Jsonl(tartaros_core::JsonlSink<std::fs::File>),
    Otlp(tartaros_core::OtlpSink<std::fs::File>),
}

impl tartaros_core::EffectSink for LogSink {
    fn emit(&mut self, e: &tartaros_core::EffectEvent) {
        match self {
            LogSink::Jsonl(s) => s.emit(e),
            LogSink::Otlp(s) => s.emit(e),
        }
    }
}

impl LogSpec {
    pub(crate) fn open(&self) -> std::io::Result<LogSink> {
        let f = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        Ok(match self.format {
            LogFormat::Jsonl => LogSink::Jsonl(tartaros_core::JsonlSink::new(f)),
            LogFormat::Otlp => LogSink::Otlp(tartaros_core::OtlpSink::new(f, tartaros_core::TraceContext::from_env())),
        })
    }
}
