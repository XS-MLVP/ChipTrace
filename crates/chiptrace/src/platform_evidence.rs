//! Bounded, read-only JSON evidence I/O shared by platform metadata readers.

use anyhow::{Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{BufReader, Read};
use std::path::Path;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct EvidenceDigest {
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

pub(crate) struct JsonEvidence {
    pub(crate) reader: BufReader<CheckedReader<File>>,
    before: Metadata,
}

impl JsonEvidence {
    pub(crate) fn open(input: &Path, max_bytes: Option<u64>) -> Result<Self> {
        let stat = fs::symlink_metadata(input)?;
        if !stat.is_file() || stat.file_type().is_symlink() {
            bail!("JSON evidence is not a regular file");
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(input)?;
        let before = file.metadata()?;
        if !before.is_file() {
            bail!("JSON evidence is not a regular file");
        }
        if max_bytes.is_some_and(|limit| before.len() > limit) {
            bail!("JSON evidence exceeds byte limit");
        }
        Ok(Self {
            reader: BufReader::with_capacity(64 * 1024, CheckedReader::new(file, before.len())),
            before,
        })
    }

    pub(crate) fn finish(self) -> Result<EvidenceDigest> {
        let reader = self.reader.into_inner();
        let after = reader.inner.metadata()?;
        let changed =
            self.before.len() != after.len() || self.before.modified()? != after.modified()?;
        #[cfg(unix)]
        let changed = {
            use std::os::unix::fs::MetadataExt;
            changed
                || self.before.ctime() != after.ctime()
                || self.before.ctime_nsec() != after.ctime_nsec()
        };
        if changed || reader.bytes != self.before.len() {
            bail!("JSON evidence changed during inspection");
        }
        Ok(EvidenceDigest {
            bytes: reader.bytes,
            sha256: hex::encode(reader.digest.finalize()),
        })
    }
}

pub(crate) struct CheckedReader<R> {
    inner: R,
    digest: Sha256,
    bytes: u64,
    limit: u64,
    utf8: Vec<u8>,
}

impl<R> CheckedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            bytes: 0,
            limit,
            utf8: Vec::new(),
        }
    }
}

impl<R: Read> Read for CheckedReader<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        // One extra byte detects growth without following an unbounded writer.
        let limit = self
            .limit
            .saturating_sub(self.bytes)
            .saturating_add(1)
            .min(output.len() as u64) as usize;
        let count = self.inner.read(&mut output[..limit])?;
        self.bytes += count as u64;
        if self.bytes > self.limit {
            return Err(std::io::Error::other("JSON evidence grew"));
        }
        // Serde IgnoredAny does not validate raw UTF-8 in skipped strings.
        // Keep at most an unfinished UTF-8 scalar between buffered reads.
        self.utf8.extend_from_slice(&output[..count]);
        match std::str::from_utf8(&self.utf8) {
            Ok(_) => self.utf8.clear(),
            Err(error) if error.error_len().is_none() && count > 0 => {
                self.utf8.drain(..error.valid_up_to());
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "JSON evidence must be valid UTF-8",
                ));
            }
        }
        self.digest.update(&output[..count]);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn utf8_validation_handles_read_boundaries_eof_and_growth() {
        for input in ["边界🙂", "a🙂中z"] {
            for width in 1..=4 {
                let mut reader =
                    CheckedReader::new(Cursor::new(input.as_bytes()), input.len() as u64);
                let mut output = Vec::new();
                let mut buffer = vec![0; width];
                loop {
                    let count = reader.read(&mut buffer).unwrap();
                    if count == 0 {
                        break;
                    }
                    output.extend_from_slice(&buffer[..count]);
                }
                assert_eq!(output, input.as_bytes());
            }
        }
        for input in [vec![0xc3], vec![0xf0, 0x9f, 0x99], vec![0xc3, b'x']] {
            let mut reader = CheckedReader::new(Cursor::new(&input), input.len() as u64);
            assert!(reader.read_to_end(&mut Vec::new()).is_err());
        }
        let mut reader = CheckedReader::new(Cursor::new(b"grew"), 3);
        assert!(reader.read_to_end(&mut Vec::new()).is_err());
    }
}
