FROM rust:1.91-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked --bin chiptrace

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin chiptrace

COPY --from=builder /src/target/release/chiptrace /usr/local/bin/chiptrace

USER 10001:10001
HEALTHCHECK --interval=20s --timeout=5s --retries=5 --start-period=10s \
  CMD ["chiptrace", "probe"]
ENTRYPOINT ["chiptrace"]
CMD ["--help"]
