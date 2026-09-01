use crate::tool_registry::canonical_runtime_tool_name;
use serde_json::Value;

/// One tool definition exactly as observed on the OpenAI-compatible wire,
/// plus the namespace inherited from any enclosing tool container.
#[derive(Debug, Clone, PartialEq)]
pub struct CapturedToolDefinition {
    pub raw: Value,
    pub namespace_path: Vec<String>,
}

impl CapturedToolDefinition {
    pub fn nested(&self) -> &Value {
        self.raw.get("function").unwrap_or(&self.raw)
    }

    pub fn source_name(&self) -> Option<&str> {
        self.nested().get("name").and_then(Value::as_str)
    }

    pub fn namespace(&self) -> Option<String> {
        self.namespace_path_string()
    }

    pub fn namespace_path_string(&self) -> Option<String> {
        (!self.namespace_path.is_empty()).then(|| self.namespace_path.join("."))
    }

    pub fn canonical_name(&self) -> Option<String> {
        let namespace = self.namespace();
        self.source_name()
            .map(|name| canonical_runtime_tool_name(namespace.as_deref(), name))
    }

    pub fn definition_key(&self) -> Option<String> {
        self.source_name()
            .map(|name| tool_definition_key(&self.namespace_path, name))
    }
}

/// Reversible internal identity for one tool definition. Dot-joined names are
/// retained for display and buyer compatibility, but cannot distinguish a
/// dotted namespace segment from multiple nested segments.
pub fn tool_definition_key(namespace_path: &[String], source_name: &str) -> String {
    // OpenAI's conventional `functions` wrapper and an unwrapped function have
    // the same public identity. Preserve the observed wrapper in metadata, but
    // do not let it create a second internal definition for the same tool.
    let identity_path = if namespace_path.len() == 1 && namespace_path[0] == "functions" {
        &[][..]
    } else {
        namespace_path
    };
    let components: Vec<&str> = identity_path
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(source_name))
        .collect();
    serde_json::to_string(&components).expect("string arrays are always JSON serializable")
}

pub fn projected_tool_definition_key(value: &Value) -> Option<String> {
    if let Some(key) = value
        .get("definition_key")
        .and_then(Value::as_str)
        .filter(|key| !key.trim().is_empty())
    {
        return Some(key.to_owned());
    }
    let nested = value.get("function").unwrap_or(value);
    let source_name = nested
        .get("runtime_tool")
        .or_else(|| value.get("runtime_tool"))
        .or_else(|| nested.get("name"))
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())?;
    let namespace_path = value
        .get("runtime_namespace_path")
        .or_else(|| nested.get("runtime_namespace_path"))
        .and_then(Value::as_array)
        .map(|path| {
            path.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|path| !path.is_empty())
        .or_else(|| {
            nested
                .get("runtime_namespace")
                .or_else(|| nested.get("namespace"))
                .or_else(|| value.get("runtime_namespace"))
                .or_else(|| value.get("namespace"))
                .and_then(Value::as_str)
                .filter(|namespace| !namespace.trim().is_empty())
                .map(|namespace| vec![namespace.to_owned()])
        })
        .unwrap_or_default();
    Some(tool_definition_key(&namespace_path, source_name))
}

/// Enumerate all tool definitions in one request. This is the sole recursive
/// parser for `tools`, `additional_tools`, namespace containers, and tool
/// definitions embedded in Responses input items. Consumers decide how to
/// project the captured definitions, but all see the same source records.
pub fn request_tool_definitions(request: &Value) -> Vec<CapturedToolDefinition> {
    let mut output = Vec::new();
    for field in ["tools", "additional_tools"] {
        for value in request
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            collect_tool_definitions(value, &[], &mut output);
        }
    }
    for item in request
        .get("input")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("additional_tools"))
    {
        collect_tool_definitions(item, &[], &mut output);
    }
    output
}

fn collect_tool_definitions(
    value: &Value,
    inherited_namespace_path: &[String],
    output: &mut Vec<CapturedToolDefinition>,
) {
    let mut namespace_path = inherited_namespace_path.to_vec();
    let namespace_container = value.get("type").and_then(Value::as_str) == Some("namespace");
    let declared_namespace = if namespace_container {
        value.get("name").and_then(Value::as_str)
    } else {
        value
            .get("runtime_namespace")
            .or_else(|| value.get("namespace"))
            .and_then(Value::as_str)
    };
    append_namespace(&mut namespace_path, declared_namespace, namespace_container);
    let mut children_found = false;
    for field in ["tools", "additional_tools", "definitions"] {
        for child in value
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            children_found = true;
            collect_tool_definitions(child, &namespace_path, output);
        }
    }
    if namespace_container
        || children_found
            && (value.get("parameters").is_none()
                && value.get("input_schema").is_none()
                && value.get("format").is_none())
    {
        return;
    }

    let nested = value.get("function").unwrap_or(value);
    if nested
        .get("name")
        .and_then(Value::as_str)
        .is_none_or(|name| name.trim().is_empty())
    {
        return;
    }
    if !std::ptr::eq(nested, value) {
        append_namespace(
            &mut namespace_path,
            nested
                .get("runtime_namespace")
                .or_else(|| nested.get("namespace"))
                .and_then(Value::as_str),
            false,
        );
    }

    output.push(CapturedToolDefinition {
        raw: value.clone(),
        namespace_path,
    });
}

fn append_namespace(path: &mut Vec<String>, namespace: Option<&str>, preserve_repetition: bool) {
    let Some(namespace) = namespace.map(str::trim).filter(|value| !value.is_empty()) else {
        return;
    };
    if preserve_repetition || path.last().is_none_or(|existing| existing != namespace) {
        path.push(namespace.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn enumerates_top_level_and_nested_responses_tools_once() {
        let request = json!({
            "tools":[{
                "type":"function","name":"plain","description":"Plain.",
                "parameters":{"type":"object","properties":{}}
            }],
            "input":[{
                "type":"additional_tools","role":"developer","tools":[{
                    "type":"namespace","name":"catalog","tools":[
                        {"type":"function","name":"lookup","parameters":{"type":"object","properties":{}}},
                        {"type":"custom","name":"query","format":{"type":"grammar"}}
                    ]
                }]
            }]
        });

        let captured = request_tool_definitions(&request);
        assert_eq!(captured.len(), 3);
        assert_eq!(captured[0].canonical_name().as_deref(), Some("plain"));
        assert_eq!(
            captured[1].canonical_name().as_deref(),
            Some("catalog.lookup")
        );
        assert_eq!(
            captured[2].canonical_name().as_deref(),
            Some("catalog.query")
        );
        assert_eq!(captured[2].raw["name"], "query");
    }

    #[test]
    fn default_functions_namespace_keeps_openai_tool_name() {
        let request = json!({
            "additional_tools":[{
                "type":"namespace","name":"functions","tools":[{
                    "type":"function","name":"exec_command",
                    "parameters":{"type":"object","properties":{}}
                }]
            }]
        });
        let captured = request_tool_definitions(&request);
        assert_eq!(
            captured[0].canonical_name().as_deref(),
            Some("exec_command")
        );
        assert_eq!(captured[0].namespace().as_deref(), Some("functions"));
        assert_eq!(
            captured[0].definition_key(),
            Some(tool_definition_key(&[], "exec_command"))
        );
    }

    #[test]
    fn empty_namespace_is_raw_only_not_a_tool_definition() {
        let request = json!({"tools":[{"type":"namespace","name":"empty","tools":[]}]});
        assert!(request_tool_definitions(&request).is_empty());
    }

    #[test]
    fn nested_namespace_path_is_reversible() {
        let request = json!({"tools":[{
            "type":"namespace","name":"catalog","tools":[{
                "type":"namespace","name":"admin","tools":[{
                    "type":"function","name":"lookup","parameters":{"type":"object","properties":{}}
                }]
            }]
        }]});
        let captured = request_tool_definitions(&request);
        assert_eq!(captured[0].namespace_path, ["catalog", "admin"]);
        assert_eq!(
            captured[0].canonical_name().as_deref(),
            Some("catalog.admin.lookup")
        );
    }

    #[test]
    fn repeated_and_dotted_namespace_segments_remain_distinct() {
        let request = json!({"tools":[{
            "type":"namespace","name":"same","tools":[{
                "type":"namespace","name":"same","tools":[{
                    "type":"namespace","name":"segment.with.dot","tools":[{
                        "type":"function","name":"lookup","parameters":{"type":"object","properties":{}}
                    }]
                }]
            }]
        }]});
        let captured = request_tool_definitions(&request);
        assert_eq!(
            captured[0].namespace_path,
            ["same", "same", "segment.with.dot"]
        );
    }

    #[test]
    fn definition_key_cannot_collide_on_dotted_namespace_segments() {
        let dotted_segment = request_tool_definitions(&json!({"tools":[{
            "type":"namespace","name":"a.b","tools":[{
                "type":"function","name":"c.lookup","parameters":{"type":"object"}
            }]
        }]}));
        let nested_segments = request_tool_definitions(&json!({"tools":[{
            "type":"namespace","name":"a","tools":[{
                "type":"namespace","name":"b.c","tools":[{
                    "type":"function","name":"lookup","parameters":{"type":"object"}
                }]
            }]
        }]}));

        assert_eq!(
            dotted_segment[0].canonical_name(),
            nested_segments[0].canonical_name()
        );
        assert_ne!(
            dotted_segment[0].definition_key(),
            nested_segments[0].definition_key()
        );
    }
}
