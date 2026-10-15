pub mod assemble;
pub mod buyer;
mod canary_scenarios;
pub mod capture;
pub mod cloud_acceptance;
pub mod cloud_ingest;
pub mod collector;
pub mod enrich;
pub mod ingest;
pub mod jsonl;
mod lifecycle;
pub mod managed_models;
pub mod model_interaction;
pub mod object_store;
pub mod otlp_delivery;
pub mod platform_acceptance;
mod platform_evidence;
pub mod platform_inspection;
pub mod platform_projection;
pub mod platform_turns;
pub mod publish;
pub mod raw_archive;
pub mod relay;
pub mod release;
pub mod schema;
pub mod score;
mod session_lineage;
pub mod session_view;
pub mod sharded;
pub mod source_context;
mod standalone_compaction;
pub mod store;
pub mod telemetry;
pub mod tool_schema;
mod turn_identity;
pub mod wire_tools;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_REVISION: &str = match option_env!("CHIPTRACE_BUILD_REVISION") {
    Some(value) => value,
    None => "unknown",
};
