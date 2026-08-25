from __future__ import annotations

import unittest

from trace_pipeline.compression import (
    ChunkCompressor,
    CompressionError,
    codec_available,
    compress_chunk,
    decompress_chunk,
    validate_compression,
)


class CompressionTest(unittest.TestCase):
    def test_parallel_zlib_round_trip_preserves_order(self) -> None:
        chunks = [bytes([index]) * (4096 + index) for index in range(16)]
        with ChunkCompressor("zlib", 1, workers=4) as compressor:
            payloads = compressor.compress_batch(chunks)
        rebuilt = [
            decompress_chunk(payload, "zlib-1", expected_raw_bytes=len(chunk))
            for chunk, payload in zip(chunks, payloads, strict=True)
        ]
        self.assertEqual(rebuilt, chunks)

    @unittest.skipUnless(codec_available("zstd"), "optional zstandard package is unavailable")
    def test_parallel_zstd_round_trip_preserves_order(self) -> None:
        chunks = [(f'{{"index":{index},"text":"' + "trace " * 4096 + '"}').encode() for index in range(16)]
        with ChunkCompressor("zstd", 1, workers=4) as compressor:
            payloads = compressor.compress_batch(chunks)
        rebuilt = [
            decompress_chunk(payload, "zstd-1", expected_raw_bytes=len(chunk))
            for chunk, payload in zip(chunks, payloads, strict=True)
        ]
        self.assertEqual(rebuilt, chunks)

    def test_codec_validation_rejects_unsupported_values(self) -> None:
        with self.assertRaises(ValueError):
            validate_compression("unknown", 1)
        with self.assertRaises(ValueError):
            validate_compression("zlib", 10)
        with self.assertRaises(CompressionError):
            decompress_chunk(b"not-compressed", "unknown-1")

    def test_corrupt_zlib_payload_is_rejected(self) -> None:
        payload = compress_chunk(b"valid", "zlib", 1)
        with self.assertRaises(CompressionError):
            decompress_chunk(payload[:-1] + b"x", "zlib-1")


if __name__ == "__main__":
    unittest.main()
