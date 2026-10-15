//! Streaming metadata for an already recorded projection Manifest download.
//! This does not replace full projection or Session acceptance verification.

use crate::platform_evidence::JsonEvidence;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;

pub const PROJECTION_METADATA_SCHEMA_VERSION: &str = "chiptrace.projection-manifest-metadata.v1";

#[derive(Deserialize, Serialize)]
struct ProjectionMetadata {
    schema_version: String,
    #[serde(default)]
    session_id: Option<String>,
    interactions: u64,
    runtime_spans: u64,
    links: u64,
    parts: Vec<PartMetadata>,
}

#[derive(Deserialize, Serialize)]
struct PartMetadata {
    file: String,
    bytes: u64,
    sha256: String,
    #[serde(default)]
    records: Option<u64>,
    #[serde(default)]
    uncompressed_bytes: Option<u64>,
}

/// Read-only metadata and digest, with large Session/Turn/metrics values
/// skipped by Serde. Callers must compare both to the recorded job evidence.
pub fn projection_manifest_metadata(input: &Path) -> Result<Value> {
    let mut file = JsonEvidence::open(input, None)?;
    let projection: ProjectionMetadata =
        serde_json::from_reader(&mut file.reader).context("read projection Manifest metadata")?;
    if projection.schema_version != crate::model_interaction::INTERACTION_PROJECTION_SCHEMA_VERSION
    {
        bail!("unsupported projection Manifest schema");
    }
    let digest = file.finish()?;
    Ok(json!({
        "schema_version":PROJECTION_METADATA_SCHEMA_VERSION,
        "session_delivery_claimed":false,
        "projection":projection,
        "manifest":{"file":"manifest.json","bytes":digest.bytes,
            "sha256":digest.sha256}
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::{BufWriter, Write};

    fn manifest() -> Value {
        json!({"schema_version":"chiptrace.interaction-projection.v1",
            "session_id":"会话\\\"🙂", "interactions":7,"runtime_spans":13,"links":19,
            "parts":[{"file":"interactions/model-interactions.jsonl.zst","bytes":123,
                "sha256":"a".repeat(64),"records":7}],
            "session_view":{"turns":[{"raw_capture_refs":["private-synthetic-marker"]}]},
            "metrics":{"nested":[null,true,false,1.25,{"unicode":"边界🙂"}]}})
    }

    #[test]
    fn metadata_preserves_selected_fields_and_hashes_all_original_bytes() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("manifest.json");
        let original = manifest();
        for session_id_present in [true, false] {
            let mut value = original.clone();
            if !session_id_present {
                value.as_object_mut().unwrap().remove("session_id");
            }
            let bytes = serde_json::to_vec_pretty(&value).unwrap();
            fs::write(&file, &bytes).unwrap();
            let report = projection_manifest_metadata(&file).unwrap();
            assert_eq!(report["session_delivery_claimed"], false);
            assert_eq!(report["manifest"]["bytes"], bytes.len());
            assert_eq!(
                report["manifest"]["sha256"],
                hex::encode(Sha256::digest(&bytes))
            );
            let mut expected = value;
            let fields = [
                "schema_version",
                "session_id",
                "interactions",
                "runtime_spans",
                "links",
                "parts",
            ];
            expected
                .as_object_mut()
                .unwrap()
                .retain(|key, _| fields.contains(&key.as_str()));
            expected["session_id"] = original["session_id"].clone();
            if !session_id_present {
                expected["session_id"] = Value::Null;
            }
            expected["parts"][0]["uncompressed_bytes"] = Value::Null;
            assert_eq!(report["projection"], expected);
            assert!(!report.to_string().contains("private-synthetic-marker"));
            assert_eq!(fs::read(&file).unwrap(), bytes);
        }
    }

    #[test]
    fn metadata_rejects_malformed_skipped_values_and_nonregular_files() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("manifest.json");
        let valid = serde_json::to_string(&manifest()).unwrap();
        for invalid in [
            valid.replace("private-synthetic-marker", "bad\\q"),
            valid.replace("private-synthetic-marker", "bad\nstring"),
            format!("{valid} {{}}"),
            valid[..valid.len() - 1].to_owned(),
            valid.replacen(
                "\"interactions\":7",
                "\"interactions\":7,\"interactions\":7",
                1,
            ),
        ] {
            fs::write(&file, invalid).unwrap();
            assert!(projection_manifest_metadata(&file).is_err());
        }
        let invalid_utf8 = valid.replace("private-synthetic-marker", "XX").into_bytes();
        let offset = invalid_utf8
            .windows(2)
            .position(|bytes| bytes == b"XX")
            .unwrap();
        for bad in [vec![0xc3, b'X'], vec![0xff, 0xff]] {
            let mut bytes = invalid_utf8.clone();
            bytes[offset..offset + 2].copy_from_slice(&bad);
            fs::write(&file, bytes).unwrap();
            assert!(projection_manifest_metadata(&file).is_err());
        }
        assert!(projection_manifest_metadata(root.path()).is_err());
        #[cfg(unix)]
        {
            let link = root.path().join("link.json");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(projection_manifest_metadata(&link).is_err());
        }
    }

    #[test]
    #[ignore = "large synthetic projection Manifest RSS gate runs separately"]
    fn large_manifest_metadata_memory() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("manifest.json");
        {
            let mut writer = BufWriter::new(fs::File::create(&file).unwrap());
            writer
                .write_all(b"{\"session_view\":{\"turns\":[{\"raw_capture_refs\":[")
                .unwrap();
            for index in 0..400_000 {
                if index > 0 {
                    writer.write_all(b",").unwrap();
                }
                write!(writer, "\"cap-memory-{index:06}-{}\"", "x".repeat(180)).unwrap();
            }
            let mut tail = manifest();
            tail.as_object_mut().unwrap().remove("session_view");
            writer.write_all(b"]}]},").unwrap();
            writer
                .write_all(&serde_json::to_vec(&tail).unwrap()[1..])
                .unwrap();
            writer.flush().unwrap();
        }
        let report = projection_manifest_metadata(&file).unwrap();
        let bytes = report["manifest"]["bytes"].as_u64().unwrap();
        assert!(bytes > 64 * 1024 * 1024);
        assert_eq!(report["projection"]["interactions"], 7);
        assert_eq!(
            report["manifest"]["sha256"],
            crate::jsonl::sha256_file(&file).unwrap()
        );
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let peak: u64 = status
            .lines()
            .find_map(|line| line.strip_prefix("VmHWM:"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        println!(
            "{}",
            json!({"schema_version":"chiptrace.projection-reader-memory.v1",
            "synthetic":true,"session_delivery_claimed":false,"references":400_000,
            "manifest_bytes":bytes,"max_rss_kib":peak,"memory_budget_kib":48 * 1024})
        );
        assert!(
            peak <= 48 * 1024,
            "Manifest reader RSS {peak} KiB exceeds 48 MiB metadata fixture budget"
        );
    }
}
