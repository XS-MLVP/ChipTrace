from __future__ import annotations

import concurrent.futures
import itertools
import threading
import zlib
from collections.abc import Sequence

try:
    import zstandard
except ImportError:  # pragma: no cover - exercised on minimal installations
    zstandard = None


SUPPORTED_CODECS = ("zlib", "zstd")


class CompressionError(RuntimeError):
    pass


_thread_local = threading.local()


def codec_available(codec: str) -> bool:
    normalized = str(codec).lower()
    if normalized == "zlib":
        return True
    if normalized == "zstd":
        return zstandard is not None
    return False


def validate_compression(codec: str, level: int) -> tuple[str, int]:
    normalized = str(codec).lower()
    if normalized not in SUPPORTED_CODECS:
        raise ValueError(f"unsupported compression codec: {codec}")
    if normalized == "zlib" and not 0 <= int(level) <= 9:
        raise ValueError("zlib compression level must be between 0 and 9")
    if normalized == "zstd" and not 1 <= int(level) <= 22:
        raise ValueError("zstd compression level must be between 1 and 22")
    if not codec_available(normalized):
        raise CompressionError(
            "zstd compression requires the optional 'zstandard' package; "
            "install chiptrace-governance[performance]"
        )
    return normalized, int(level)


def codec_label(codec: str, level: int) -> str:
    normalized, checked_level = validate_compression(codec, level)
    return f"{normalized}-{checked_level}"


def compress_chunk(raw: bytes, codec: str, level: int) -> bytes:
    normalized, checked_level = validate_compression(codec, level)
    return _compress_validated(raw, normalized, checked_level)


def _compress_validated(raw: bytes, codec: str, level: int) -> bytes:
    if codec == "zlib":
        return zlib.compress(raw, level)
    cache_key = f"zstd_compressor_{level}"
    compressor = getattr(_thread_local, cache_key, None)
    if compressor is None:
        compressor = zstandard.ZstdCompressor(level=level)
        setattr(_thread_local, cache_key, compressor)
    return compressor.compress(raw)


def decompress_chunk(payload: bytes, codec: str, *, expected_raw_bytes: int | None = None) -> bytes:
    try:
        family, raw_level = str(codec).rsplit("-", 1)
        level = int(raw_level)
        validate_compression(family, level)
    except (CompressionError, TypeError, ValueError) as exc:
        raise CompressionError(f"unsupported compressed chunk codec: {codec}") from exc
    if family == "zlib":
        try:
            return zlib.decompress(payload)
        except zlib.error as exc:
            raise CompressionError("invalid zlib payload") from exc
    try:
        decompressor = getattr(_thread_local, "zstd_decompressor", None)
        if decompressor is None:
            decompressor = zstandard.ZstdDecompressor()
            _thread_local.zstd_decompressor = decompressor
        if expected_raw_bytes is None:
            return decompressor.decompress(payload)
        return decompressor.decompress(payload, max_output_size=expected_raw_bytes)
    except zstandard.ZstdError as exc:
        raise CompressionError("invalid zstd payload") from exc


class ChunkCompressor:
    def __init__(self, codec: str, level: int, workers: int = 1) -> None:
        self.codec, self.level = validate_compression(codec, level)
        if workers <= 0:
            raise ValueError("compression workers must be positive")
        self.workers = int(workers)
        self.label = f"{self.codec}-{self.level}"
        self._executor = (
            concurrent.futures.ThreadPoolExecutor(
                max_workers=self.workers,
                thread_name_prefix="trace-compress",
            )
            if self.workers > 1
            else None
        )

    def compress_batch(self, chunks: Sequence[bytes]) -> list[bytes]:
        if not chunks:
            return []
        if self._executor is None:
            return [_compress_validated(chunk, self.codec, self.level) for chunk in chunks]
        return list(
            self._executor.map(
                _compress_validated,
                chunks,
                itertools.repeat(self.codec),
                itertools.repeat(self.level),
            )
        )

    def close(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=True, cancel_futures=True)
            self._executor = None

    def __enter__(self) -> ChunkCompressor:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close()
