use anyhow::{Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

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

pub fn canonical_runtime_tool_name(namespace: Option<&str>, name: &str) -> String {
    match namespace.map(str::trim).filter(|value| !value.is_empty()) {
        None | Some("functions") => name.to_owned(),
        Some(namespace) => format!("{namespace}.{name}"),
    }
}

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

pub fn require_json_parameters(value: &Value) -> Result<()> {
    let nested = value.get("function").unwrap_or(value);
    let name = nested
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");
    if !complete_json_parameters(nested) {
        bail!("tool {name:?} has no complete JSON parameters schema");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_hash_ignores_projection_metadata() {
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
        schema["schema_version"] = json!("sha256:content-addressed");
        assert_eq!(canonical_tool_schema_sha256(&schema).unwrap(), first);
    }

    #[test]
    fn buyer_completeness_requires_real_json_parameter_descriptions() {
        let complete = json!({
            "name":"exec_command","description":"Execute a command.",
            "parameters":{"type":"object","properties":{
                "cmd":{"type":"string","description":"Command."}
            },"required":["cmd"]}
        });
        assert!(tool_definition_source_complete(&complete, "exec_command"));
        let mut incomplete = complete;
        incomplete["parameters"]["properties"]["cmd"]
            .as_object_mut()
            .unwrap()
            .remove("description");
        assert!(!tool_definition_source_complete(
            &incomplete,
            "exec_command"
        ));
        assert!(require_json_parameters(&incomplete).is_err());
    }

    #[test]
    fn namespace_identity_is_reversible() {
        assert_eq!(canonical_runtime_tool_name(None, "lookup"), "lookup");
        assert_eq!(
            canonical_runtime_tool_name(Some("catalog"), "lookup"),
            "catalog.lookup"
        );
    }
}
