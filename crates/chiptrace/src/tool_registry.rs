use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub const TOOL_REGISTRY_SCHEMA_VERSION: &str = "chiptrace.tool-registry.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRegistry {
    pub schema_version: String,
    pub producer: String,
    pub producer_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    pub tools: Vec<ToolRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRegistryEntry {
    pub runtime_item_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_namespace: Option<String>,
    pub tool: Value,
}

#[derive(Debug, Clone)]
pub struct LoadedToolRegistry {
    pub registry: ToolRegistry,
    pub sha256: String,
}

pub fn load_tool_registry(path: Option<&Path>) -> Result<Option<LoadedToolRegistry>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let raw = fs::read(path)
        .with_context(|| format!("read Tool Registry snapshot {}", path.display()))?;
    let value: Value = serde_json::from_slice(&raw)
        .with_context(|| format!("parse Tool Registry snapshot {}", path.display()))?;
    let registry = parse_tool_registry_value(&value)
        .with_context(|| format!("parse Tool Registry snapshot {}", path.display()))?;
    Ok(Some(LoadedToolRegistry {
        registry,
        sha256: canonical_tool_registry_sha256(&value)?,
    }))
}

pub fn load_tool_registry_value(value: &Value) -> Result<LoadedToolRegistry> {
    let registry = parse_tool_registry_value(value)?;
    Ok(LoadedToolRegistry {
        registry,
        sha256: canonical_tool_registry_sha256(value)?,
    })
}

pub fn parse_tool_registry(raw: &[u8]) -> Result<ToolRegistry> {
    let value: Value = serde_json::from_slice(raw)?;
    parse_tool_registry_value(&value)
}

fn parse_tool_registry_value(value: &Value) -> Result<ToolRegistry> {
    let registry: ToolRegistry = serde_json::from_value(value.clone())?;
    validate_tool_registry(&registry)?;
    Ok(registry)
}

pub fn validate_tool_registry_value(value: &Value) -> Result<()> {
    parse_tool_registry_value(value).map(|_| ())
}

pub fn canonical_tool_registry_sha256(value: &Value) -> Result<String> {
    validate_tool_registry_value(value)?;
    let mut semantic = value.clone();
    semantic
        .as_object_mut()
        .expect("validated Tool Registry must be an object")
        .remove("captured_at");
    Ok(hex::encode(Sha256::digest(canonical_json_bytes(
        &semantic,
    )?)))
}

/// Content address for one captured tool definition. Ingest adapters and
/// offline Assembly use the same projection, so metadata fields never make the
/// same source Schema appear to drift between stages.
pub fn canonical_tool_schema_sha256(value: &Value) -> Result<String> {
    let nested = value.get("function").unwrap_or(value);
    let name = nested
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("tool schema name is required"))?;
    let semantic = json!({
        "name": name,
        "description": nested.get("description"),
        "parameters": nested.get("parameters").or_else(|| nested.get("input_schema")),
        "format": nested.get("format"),
        "type": value.get("type").and_then(Value::as_str).unwrap_or("function"),
    });
    Ok(hex::encode(Sha256::digest(canonical_json_bytes(
        &semantic,
    )?)))
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    fn normalize(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut normalized = serde_json::Map::new();
                let mut entries: Vec<_> = object.iter().collect();
                entries.sort_by(|left, right| left.0.cmp(right.0));
                for (key, value) in entries {
                    normalized.insert(key.clone(), normalize(value));
                }
                Value::Object(normalized)
            }
            Value::Array(values) => Value::Array(values.iter().map(normalize).collect()),
            _ => value.clone(),
        }
    }
    Ok(serde_json::to_vec(&normalize(value))?)
}

fn validate_tool_registry(registry: &ToolRegistry) -> Result<()> {
    if registry.schema_version != TOOL_REGISTRY_SCHEMA_VERSION
        || registry.producer.trim().is_empty()
        || registry.producer_version.trim().is_empty()
        || registry.tools.is_empty()
    {
        bail!("invalid Tool Registry snapshot");
    }
    let mut identities = BTreeSet::new();
    for entry in &registry.tools {
        validate_registry_tool(entry)?;
        let identity = registry_entry_identity(entry)?;
        if !identities.insert(identity.clone()) {
            bail!("Tool Registry contains duplicate runtime tool {identity}");
        }
    }
    Ok(())
}

/// Stable buyer-facing identity for a runtime tool. The default OpenAI
/// `functions` namespace remains backward compatible; all other namespaces
/// stay distinguishable while their original components remain in metadata.
pub fn canonical_runtime_tool_name(namespace: Option<&str>, name: &str) -> String {
    match namespace.map(str::trim).filter(|value| !value.is_empty()) {
        None | Some("functions") => name.to_owned(),
        Some(namespace) => format!("{namespace}.{name}"),
    }
}

pub fn registry_entry_identity(entry: &ToolRegistryEntry) -> Result<String> {
    let definition_name = entry
        .tool
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("Tool Registry tool.name is required"))?;
    let runtime_tool = entry.runtime_tool.as_deref().unwrap_or(definition_name);
    Ok(canonical_runtime_tool_name(
        entry.runtime_namespace.as_deref(),
        runtime_tool,
    ))
}

/// Buyer-facing completeness is a quality property, not an ingestion
/// precondition. Runtime registries are preserved even when the producer did
/// not describe every parameter; callers use this predicate to keep those
/// schemas out of strict releases without fabricating the missing fields.
pub fn tool_definition_source_complete(value: &Value, expected_name: &str) -> bool {
    let nested = value.get("function").unwrap_or(value);
    if nested.get("name").and_then(Value::as_str) != Some(expected_name)
        || nested
            .get("description")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        || nested
            .pointer("/schema_provenance/generated_adapter")
            .and_then(Value::as_bool)
            == Some(true)
        || nested
            .pointer("/schema_provenance/source_complete")
            .and_then(Value::as_bool)
            == Some(false)
    {
        return false;
    }

    complete_json_parameters(nested) || complete_native_format(nested)
}

fn complete_json_parameters(tool: &Value) -> bool {
    tool.get("parameters")
        .and_then(Value::as_object)
        .is_some_and(|parameters| {
            parameters.get("type").and_then(Value::as_str) == Some("object")
                && parameters
                    .get("properties")
                    .and_then(Value::as_object)
                    .is_some_and(|properties| {
                        properties.values().all(|property| {
                            property.as_object().is_some_and(|property| {
                                (property.get("type").is_some()
                                    || property.get("oneOf").is_some()
                                    || property.get("anyOf").is_some()
                                    || property.get("$ref").is_some())
                                    && property
                                        .get("description")
                                        .and_then(Value::as_str)
                                        .is_some_and(|value| !value.trim().is_empty())
                            })
                        })
                    })
                && parameters.get("required").is_none_or(|required| {
                    required.as_array().is_some_and(|required| {
                        required.iter().all(|name| {
                            name.as_str().is_some_and(|name| {
                                parameters
                                    .get("properties")
                                    .and_then(Value::as_object)
                                    .is_some_and(|properties| properties.contains_key(name))
                            })
                        })
                    })
                })
        })
}

fn complete_native_format(tool: &Value) -> bool {
    tool.get("format")
        .and_then(Value::as_object)
        .is_some_and(|format| {
            ["type", "syntax", "definition"].into_iter().all(|field| {
                format
                    .get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
            })
        })
}

fn validate_registry_tool(entry: &ToolRegistryEntry) -> Result<()> {
    if entry.runtime_item_type.trim().is_empty() {
        bail!("Tool Registry runtime_item_type must not be empty");
    }
    let tool = entry
        .tool
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Tool Registry tool must be an object"))?;
    if entry
        .runtime_tool
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("Tool Registry runtime_tool must not be empty");
    }
    if entry
        .runtime_namespace
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        bail!("Tool Registry runtime_namespace must not be empty");
    }
    tool.get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("Tool Registry tool.name is required"))?;
    if tool.get("parameters").is_some_and(Value::is_object) {
        return Ok(());
    }

    let format = tool
        .get("format")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            anyhow::anyhow!("Tool Registry tool requires parameters or a native format")
        })?;
    if format.is_empty() {
        bail!("Tool Registry native format must not be empty");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn registry_preserves_incomplete_parameter_schemas_for_quality_gating() {
        let registry = json!({
            "schema_version":TOOL_REGISTRY_SCHEMA_VERSION,
            "producer":"codex-cli",
            "producer_version":"0.150.0-alpha.9",
            "tools":[{"runtime_item_type":"CommandExecution","tool":{
                "name":"exec_command","description":"Execute a command.",
                "parameters":{"type":"object","properties":{
                    "cmd":{"type":"string","description":"Command to execute."}
                },"required":["cmd"]}
            }}]
        });
        validate_tool_registry_value(&registry).unwrap();
        let mut invalid = registry;
        invalid["tools"][0]["tool"]["parameters"]["properties"]["cmd"]
            .as_object_mut()
            .unwrap()
            .remove("description");
        validate_tool_registry_value(&invalid).unwrap();
        assert!(!tool_definition_source_complete(
            &invalid["tools"][0]["tool"],
            "exec_command"
        ));
    }

    #[test]
    fn generic_dispatcher_registry_uses_the_same_contract() {
        let registry = json!({
            "schema_version":TOOL_REGISTRY_SCHEMA_VERSION,
            "producer":"chip-agent-dispatcher",
            "producer_version":"2.4.0",
            "tools":[{"runtime_item_type":"rtl_compile","tool":{
                "name":"compile_rtl","description":"Compile an RTL target.",
                "parameters":{"type":"object","properties":{
                    "target":{"type":"string","description":"RTL build target."}
                },"required":["target"]}
            }}]
        });
        validate_tool_registry_value(&registry).unwrap();
    }

    #[test]
    fn registry_preserves_native_freeform_contract_without_inventing_parameters() {
        let registry = json!({
            "schema_version":TOOL_REGISTRY_SCHEMA_VERSION,
            "producer":"codex-cli",
            "producer_version":"0.150.0-alpha.9",
            "tools":[{"runtime_item_type":"custom","runtime_tool":"apply_patch","tool":{
                "name":"apply_patch",
                "description":"Apply a patch.",
                "format":{"type":"grammar","syntax":"lark","definition":"start: /.+/"}
            }}]
        });
        validate_tool_registry_value(&registry).unwrap();
        assert!(registry["tools"][0]["tool"].get("parameters").is_none());
    }

    #[test]
    fn registry_keeps_same_named_tools_in_distinct_namespaces() {
        let definition = || {
            json!({
                "name":"lookup",
                "description":"Look up one value.",
                "parameters":{"type":"object","properties":{}}
            })
        };
        let registry = json!({
            "schema_version":TOOL_REGISTRY_SCHEMA_VERSION,
            "producer":"codex-cli",
            "producer_version":"0.150.0-alpha.9",
            "tools":[
                {"runtime_item_type":"function","runtime_tool":"lookup",
                 "runtime_namespace":"catalog","tool":definition()},
                {"runtime_item_type":"function","runtime_tool":"lookup",
                 "runtime_namespace":"symbols","tool":definition()}
            ]
        });
        let parsed = parse_tool_registry_value(&registry).unwrap();
        assert_eq!(
            registry_entry_identity(&parsed.tools[0]).unwrap(),
            "catalog.lookup"
        );
        assert_eq!(
            registry_entry_identity(&parsed.tools[1]).unwrap(),
            "symbols.lookup"
        );
    }

    #[test]
    fn registry_rejects_duplicate_default_namespace_aliases() {
        let registry = json!({
            "schema_version":TOOL_REGISTRY_SCHEMA_VERSION,
            "producer":"codex-cli",
            "producer_version":"0.150.0-alpha.9",
            "tools":[
                {"runtime_item_type":"function","runtime_tool":"lookup","tool":{
                    "name":"lookup","description":"Look up one value.",
                    "parameters":{"type":"object","properties":{}}
                }},
                {"runtime_item_type":"function","runtime_tool":"lookup",
                 "runtime_namespace":"functions","tool":{
                    "name":"lookup","description":"Look up one value.",
                    "parameters":{"type":"object","properties":{}}
                }}
            ]
        });
        assert!(validate_tool_registry_value(&registry).is_err());
    }

    #[test]
    fn tool_schema_hash_ignores_content_address_metadata() {
        let mut schema = json!({
            "type":"function",
            "name":"exec_command",
            "description":"Execute a command.",
            "parameters":{"type":"object","properties":{"cmd":{
                "type":"string","description":"Command."
            }}}
        });
        let first = canonical_tool_schema_sha256(&schema).unwrap();
        schema["schema_hash"] = json!(first);
        schema["schema_version"] = json!("dispatcher-v1");
        assert_eq!(canonical_tool_schema_sha256(&schema).unwrap(), first);
    }

    #[test]
    fn registry_hash_is_independent_of_json_object_key_order() {
        let first = json!({
            "schema_version":TOOL_REGISTRY_SCHEMA_VERSION,
            "producer":"codex-cli",
            "producer_version":"0.150.0-alpha.9",
            "tools":[{"runtime_item_type":"function","tool":{
                "name":"lookup","description":"Look up one value.",
                "parameters":{"type":"object","properties":{},"required":[]}
            }}]
        });
        let second = json!({
            "tools":[{"tool":{"parameters":{"required":[],"properties":{},"type":"object"},
                "description":"Look up one value.","name":"lookup"},
                "runtime_item_type":"function"}],
            "producer_version":"0.150.0-alpha.9",
            "producer":"codex-cli",
            "schema_version":TOOL_REGISTRY_SCHEMA_VERSION
        });
        assert_eq!(
            canonical_tool_registry_sha256(&first).unwrap(),
            canonical_tool_registry_sha256(&second).unwrap()
        );
    }

    #[test]
    fn registry_hash_ignores_capture_time() {
        let registry = json!({
            "schema_version":TOOL_REGISTRY_SCHEMA_VERSION,
            "producer":"codex-cli",
            "producer_version":"0.150.0-alpha.9",
            "tools":[{"runtime_item_type":"function","tool":{
                "name":"lookup","description":"Look up one value.",
                "parameters":{"type":"object","properties":{},"required":[]}
            }}]
        });
        let mut later = registry.clone();
        later["captured_at"] = json!("2026-08-30T08:00:00Z");
        assert_eq!(
            canonical_tool_registry_sha256(&registry).unwrap(),
            canonical_tool_registry_sha256(&later).unwrap()
        );
    }
}
