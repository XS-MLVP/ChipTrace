use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub fn utc_now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC 3339 formatting cannot fail")
}

pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).context("serialize canonical JSON")
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut input = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 8 * 1024 * 1024];
    loop {
        let count = input
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

pub fn open_jsonl_reader(path: &Path) -> Result<Box<dyn BufRead>> {
    let file = File::open(path).with_context(|| format!("open JSONL input {}", path.display()))?;
    let reader: Box<dyn Read> = if path.extension().and_then(|v| v.to_str()) == Some("zst") {
        Box::new(
            zstd::stream::read::Decoder::new(file)
                .with_context(|| format!("open zstd input {}", path.display()))?,
        )
    } else {
        Box::new(file)
    };
    Ok(Box::new(BufReader::with_capacity(8 * 1024 * 1024, reader)))
}

pub fn visit_jsonl<F>(paths: &[PathBuf], mut visit: F) -> Result<u64>
where
    F: FnMut(&Path, u64, &[u8]) -> Result<()>,
{
    let mut records = 0_u64;
    for path in paths {
        let mut reader = open_jsonl_reader(path)?;
        let mut line = Vec::new();
        let mut line_number = 0_u64;
        loop {
            line.clear();
            let bytes = reader
                .read_until(b'\n', &mut line)
                .with_context(|| format!("read JSONL input {}", path.display()))?;
            if bytes == 0 {
                break;
            }
            line_number += 1;
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            visit(path, line_number, &line)
                .with_context(|| format!("process {} line {}", path.display(), line_number))?;
            records += 1;
        }
    }
    Ok(records)
}

pub enum JsonlWriter {
    Plain(BufWriter<File>),
    Zstd(zstd::stream::write::Encoder<'static, BufWriter<File>>),
}

impl JsonlWriter {
    pub fn create(path: &Path, zstd_level: i32) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create directory {}", parent.display()))?;
        }
        let file = File::create(path).with_context(|| format!("create {}", path.display()))?;
        let writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
        if path.extension().and_then(|v| v.to_str()) == Some("zst") {
            let encoder = zstd::stream::write::Encoder::new(writer, zstd_level)
                .with_context(|| format!("create zstd output {}", path.display()))?;
            Ok(Self::Zstd(encoder))
        } else {
            Ok(Self::Plain(writer))
        }
    }

    pub fn write_value(&mut self, value: &Value) -> Result<u64> {
        let bytes = canonical_bytes(value)?;
        self.write_line(&bytes)?;
        Ok((bytes.len() + 1) as u64)
    }

    pub fn write_line(&mut self, bytes: &[u8]) -> Result<()> {
        match self {
            Self::Plain(writer) => {
                writer.write_all(bytes)?;
                writer.write_all(b"\n")?;
            }
            Self::Zstd(writer) => {
                writer.write_all(bytes)?;
                writer.write_all(b"\n")?;
            }
        }
        Ok(())
    }

    pub fn finish(self) -> Result<()> {
        match self {
            Self::Plain(mut writer) => {
                writer.flush()?;
                writer.get_ref().sync_all()?;
            }
            Self::Zstd(writer) => {
                let mut writer = writer.finish()?;
                writer.flush()?;
                writer.get_ref().sync_all()?;
            }
        }
        Ok(())
    }
}

pub fn object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

pub fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.trim().is_empty())
}

pub fn u64_field(value: &Value, keys: &[&str]) -> u64 {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(value_as_u64))
        .unwrap_or(0)
}

pub fn value_as_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64().or_else(|| {
            number
                .as_i64()
                .and_then(|v| if v >= 0 { Some(v as u64) } else { None })
        }),
        Value::String(text) => text.parse::<u64>().ok(),
        _ => None,
    }
}

pub fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

pub fn ensure_safe_relative_path(name: &str) -> Result<()> {
    let path = Path::new(name);
    if name.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("unsafe relative path in manifest: {name:?}");
    }
    Ok(())
}
