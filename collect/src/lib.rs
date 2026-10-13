//! Effect collectors — observe what an agent attempts, from outside the agent,
//! and emit [`EffectEvent`]s. Collectors attach to a process tree by pid; they
//! do **not** depend on seisin-sandbox's enforcement, and nothing here depends
//! on the intent layer. The effect log (JSON Lines) is the neutral interface: a collector
//! writes it, the intent layer (or anything) reads it via its own adapter.
//!
//! Modular and extensible: each axis is a [`Collector`]. Add one by implementing
//! the trait; `core::catalog` is the shared classification so they agree on what
//! counts as "outside the territory".
//!
//! [`EffectEvent`]: seisin_sandbox_core::EffectEvent
//! [`Collector`]: seisin_sandbox_core::Collector

mod proc;

pub mod mcp;
pub mod net;
pub mod process;
pub mod secret;

pub use mcp::McpCollector;
pub use net::NetworkCollector;
pub use process::ProcessCollector;
pub use secret::SecretCollector;
