//! Read-only JSONL validation and byte ranges for streaming a full Turn page.

use crate::platform_evidence::JsonEvidence;
use anyhow::{Context, Result, bail};
use serde::de::IgnoredAny;
use serde_json::{Value, json};
use std::io::{BufRead, Read};
use std::path::Path;

pub const TURN_PAGE_METADATA_SCHEMA_VERSION: &str = "chiptrace.turn-page-metadata.v1";

// Supply precisely one JSONL record without allocating its complete line.
struct JsonLine<'a, R> {
    inner: &'a mut R,
    bytes: u64,
    newline: bool,
}

impl<R: BufRead> Read for JsonLine<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if self.newline || output.is_empty() {
            return Ok(0);
        }
        let available = self.inner.fill_buf()?;
        let count = output.len().min(available.len());
        let count = if let Some(index) = available[..count].iter().position(|byte| *byte == b'\n') {
            self.newline = true;
            index + 1
        } else {
            count
        };
        output[..count].copy_from_slice(&available[..count]);
        self.inner.consume(count);
        self.bytes += count as u64;
        Ok(count)
    }
}

/// Validate every line and hash every byte. Only up to `limit` byte ranges are
/// retained; no Turn payload is materialized or returned on stdout.
pub fn turn_page_metadata(input: &Path, offset: u64, limit: u64, max_bytes: u64) -> Result<Value> {
    if limit == 0 || limit > 100 || max_bytes == 0 {
        bail!("Turn page limits must be positive; at most 100 rows may be selected");
    }
    let mut file = JsonEvidence::open(input, Some(max_bytes))?;
    let mut records = 0_u64;
    let mut position = 0_u64;
    let mut rows = Vec::new();
    while !file.reader.fill_buf()?.is_empty() {
        let mut line = JsonLine {
            inner: &mut file.reader,
            bytes: 0,
            newline: false,
        };
        serde_json::from_reader::<_, IgnoredAny>(&mut line)
            .context("validate Turn JSONL record")?;
        if records >= offset && records - offset < limit {
            rows.push(json!({"start":position,"bytes":line.bytes - u64::from(line.newline)}));
        }
        position += line.bytes;
        records += 1;
    }
    let digest = file.finish()?;
    if position != digest.bytes {
        bail!("Turn JSONL byte count is inconsistent");
    }
    Ok(json!({"schema_version":TURN_PAGE_METADATA_SCHEMA_VERSION,
        "session_delivery_claimed":false,"offset":offset,"limit":limit,
        "evidence":{"records":records,"bytes":digest.bytes,"sha256":digest.sha256},
        "rows":rows}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::{BufWriter, Write};

    #[test]
    fn page_ranges_preserve_jsonl_bytes_and_validate_outside_the_page() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("turns.jsonl");
        let first = serde_json::to_string(&json!({"turn_id":"边界🙂","refs":["x".repeat(65_500)]}))
            .unwrap();
        for separator in ["\n", "\r\n"] {
            for trailing in ["", "\n"] {
                let bytes =
                    format!("{first}{separator}{{\"turn_id\":\"second\"}}{trailing}").into_bytes();
                fs::write(&file, &bytes).unwrap();
                for (offset, count) in [(0, 1), (1, 1), (2, 0), (u64::MAX, 0)] {
                    let report = turn_page_metadata(&file, offset, 1, bytes.len() as u64).unwrap();
                    assert_eq!(report["evidence"]["records"], 2);
                    assert_eq!(
                        report["evidence"]["sha256"],
                        hex::encode(Sha256::digest(&bytes))
                    );
                    let rows = report["rows"].as_array().unwrap();
                    assert_eq!(rows.len(), count);
                    for row in rows {
                        let start = row["start"].as_u64().unwrap() as usize;
                        let end = start + row["bytes"].as_u64().unwrap() as usize;
                        let value: Value = serde_json::from_slice(&bytes[start..end]).unwrap();
                        assert_eq!(
                            value["turn_id"],
                            if offset == 0 { "边界🙂" } else { "second" }
                        );
                    }
                }
                assert_eq!(fs::read(&file).unwrap(), bytes);
                assert!(turn_page_metadata(&file, 0, 1, bytes.len() as u64 - 1).is_err());
            }
        }
        fs::write(&file, b"").unwrap();
        assert_eq!(
            turn_page_metadata(&file, 0, 1, 1).unwrap()["rows"],
            json!([])
        );
        for bad in [
            b"{}\n\n".as_slice(),
            b"{} {}\n",
            b"{\n}\n",
            b"{\"x\":\"\xff\"}\n",
            b"{\"x\":\"bad\\q\"}\n",
        ] {
            fs::write(&file, bad).unwrap();
            // Selecting no rows still validates the entire recorded sidecar.
            assert!(turn_page_metadata(&file, 100, 1, 1024).is_err());
        }
        assert!(turn_page_metadata(root.path(), 0, 1, 1024).is_err());
        assert!(turn_page_metadata(&file, 0, 0, 1024).is_err());
        assert!(turn_page_metadata(&file, 0, 101, 1024).is_err());
        #[cfg(unix)]
        {
            let link = root.path().join("link.jsonl");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(turn_page_metadata(&link, 0, 1, 1024).is_err());
        }
    }

    #[test]
    #[ignore = "large synthetic selected Turn page RSS gate runs separately"]
    fn large_turn_page_metadata_memory() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("turns.jsonl");
        {
            let mut writer = BufWriter::new(fs::File::create(&file).unwrap());
            writer.write_all(b"{\"raw_capture_refs\":[").unwrap();
            for index in 0..400_000 {
                if index > 0 {
                    writer.write_all(b",").unwrap();
                }
                write!(writer, "\"cap-memory-{index:06}-{}\"", "x".repeat(180)).unwrap();
            }
            writer
                .write_all(b"],\"turn_id\":\"huge\"}\n{\"turn_id\":\"small\"}\n")
                .unwrap();
            writer.flush().unwrap();
        }
        let report = turn_page_metadata(&file, 0, 1, 128 * 1024 * 1024).unwrap();
        let bytes = report["evidence"]["bytes"].as_u64().unwrap();
        assert!(bytes > 64 * 1024 * 1024);
        assert_eq!(report["evidence"]["records"], 2);
        assert_eq!(report["rows"].as_array().unwrap().len(), 1);
        assert_eq!(
            report["evidence"]["sha256"],
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
            json!({"schema_version":"chiptrace.turn-page-reader-memory.v1",
            "synthetic":true,"session_delivery_claimed":false,"references":400_000,
            "turn_bytes":bytes,"max_rss_kib":peak,"memory_budget_kib":48 * 1024})
        );
        assert!(
            peak <= 48 * 1024,
            "Turn page reader RSS {peak} KiB exceeds 48 MiB fixture budget"
        );
    }
}
