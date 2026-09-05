use anyhow::{Result, anyhow, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

pub const MANAGED_MODEL: &str = "gpt-5.6-sol";
pub const CATALOG_SOURCE_VERSION: &str = "0.152.0-alpha.7.2";
const CATALOG_BYTES: &[u8] = include_bytes!("../../../integrations/codex/managed-models.json");

#[derive(Debug)]
pub struct ManagedModelCatalog {
    pub bytes: &'static [u8],
    pub etag: String,
}

static CATALOG: LazyLock<std::result::Result<ManagedModelCatalog, String>> =
    LazyLock::new(|| build_catalog().map_err(|error| format!("{error:#}")));

pub fn managed_model_catalog() -> Result<&'static ManagedModelCatalog> {
    CATALOG.as_ref().map_err(|error| anyhow!(error.to_owned()))
}

fn build_catalog() -> Result<ManagedModelCatalog> {
    let value: Value = serde_json::from_slice(CATALOG_BYTES)?;
    let models = value
        .get("models")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("managed model catalog requires models"))?;
    if models.len() != 1 {
        bail!("managed model catalog must contain exactly one model");
    }
    let model = models[0]
        .as_object()
        .ok_or_else(|| anyhow!("managed model entry must be an object"))?;
    if model.get("slug").and_then(Value::as_str) != Some(MANAGED_MODEL) {
        bail!("managed model catalog must retain the real model name");
    }
    if model.get("tool_mode").and_then(Value::as_str) != Some("direct") {
        bail!("managed model must use direct tools");
    }
    if model.contains_key("apply_patch_tool_type") {
        bail!("managed model must not advertise a freeform apply_patch tool");
    }
    for required in [
        "model_messages",
        "supported_reasoning_levels",
        "shell_type",
        "multi_agent_version",
        "input_modalities",
        "supports_search_tool",
    ] {
        if model.get(required).is_none_or(Value::is_null) {
            bail!("managed model metadata is missing {required}");
        }
    }
    for required in [
        "supports_reasoning_summaries",
        "supports_parallel_tool_calls",
    ] {
        if !model.get(required).is_some_and(Value::is_boolean) {
            bail!("managed model metadata requires boolean {required}");
        }
    }
    let digest = hex::encode(Sha256::digest(CATALOG_BYTES));
    Ok(ManagedModelCatalog {
        bytes: CATALOG_BYTES,
        etag: format!("\"sha256-{digest}\""),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_preserves_stock_capabilities_and_forces_json_tools() {
        let catalog = managed_model_catalog().unwrap();
        let value: Value = serde_json::from_slice(catalog.bytes).unwrap();
        let model = &value["models"][0];
        assert_eq!(model["slug"], MANAGED_MODEL);
        assert_eq!(model["tool_mode"], "direct");
        assert!(model.get("apply_patch_tool_type").is_none());
        assert_eq!(model["multi_agent_version"], "v2");
        assert_eq!(model["supports_search_tool"], true);
        assert_eq!(model["supports_reasoning_summaries"], true);
        assert_eq!(model["supports_parallel_tool_calls"], true);
        assert!(model["model_messages"]["instructions_template"].is_string());
        assert!(catalog.etag.starts_with("\"sha256-"));
    }
}
