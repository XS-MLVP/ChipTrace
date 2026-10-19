# Keep the production platform base identical to the image used by the
# managed-route CI contract.  A floating Node tag can change the runtime
# between two GitHub runs and turn an otherwise valid image into a startup
# failure.  The digest has been verified to provide Node v22.23.3.
ARG CHIPTRACE_PLATFORM_BASE=node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392
FROM rust:1.91-bookworm AS builder

WORKDIR /src
ARG CHIPTRACE_REVISION=unknown
ENV CHIPTRACE_BUILD_REVISION=${CHIPTRACE_REVISION}
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY schemas ./schemas
COPY integrations/codex/managed-models.json ./integrations/codex/managed-models.json
ARG CHIPTRACE_CARGO_REGISTRY_INDEX=""
ARG CHIPTRACE_CARGO_OFFLINE=false
RUN --mount=type=cache,id=chiptrace-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=chiptrace-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=chiptrace-cargo-target,target=/src/target,sharing=locked \
    find crates schemas integrations/codex/managed-models.json -type f -exec touch {} + \
    && if [ "$CHIPTRACE_CARGO_OFFLINE" = true ]; then \
      cargo build --release --locked --offline --bin chiptrace; \
    elif [ -n "$CHIPTRACE_CARGO_REGISTRY_INDEX" ]; then \
      CARGO_REGISTRIES_CRATES_IO_INDEX="$CHIPTRACE_CARGO_REGISTRY_INDEX" \
        cargo build --release --locked --bin chiptrace; \
    else \
      cargo build --release --locked --bin chiptrace; \
    fi \
    && install -D -m 0755 /src/target/release/chiptrace /out/chiptrace

FROM ${CHIPTRACE_PLATFORM_BASE} AS platform

ARG CHIPTRACE_VERSION=0.6.0
ARG CHIPTRACE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/XS-MLVP/ChipTrace" \
      org.opencontainers.image.version="${CHIPTRACE_VERSION}" \
      org.opencontainers.image.revision="${CHIPTRACE_REVISION}"

COPY --from=builder /out/chiptrace /usr/local/bin/chiptrace
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY integrations/cloud-platform/plugin.js integrations/cloud-platform/server.js integrations/cloud-platform/client.js /opt/chiptrace/
RUN test "$(node --version)" = "v22.23.3" \
    && mkdir -p /data/platform /data/capture /data/objects \
    && chown -R 10001:10001 /data /opt/chiptrace
ENV CHIPTRACE_BIN=/usr/local/bin/chiptrace \
    CHIPTRACE_BUILD_REVISION=${CHIPTRACE_REVISION} \
    CHIPTRACE_PLATFORM_ROOT=/data/platform \
    CHIPTRACE_CAPTURE_ROOT=/data/capture \
    CHIPTRACE_OBJECT_ROOT=/data/objects \
    CHIPTRACE_PLATFORM_HOST=0.0.0.0 \
    CHIPTRACE_PLATFORM_PORT=18086
USER 10001:10001
WORKDIR /opt/chiptrace
EXPOSE 18086
ENTRYPOINT ["node"]
CMD ["/opt/chiptrace/server.js"]

FROM debian:bookworm-slim AS runtime

ARG CHIPTRACE_VERSION=0.6.0
ARG CHIPTRACE_REVISION=unknown

LABEL org.opencontainers.image.source="https://github.com/XS-MLVP/ChipTrace" \
      org.opencontainers.image.version="${CHIPTRACE_VERSION}" \
      org.opencontainers.image.revision="${CHIPTRACE_REVISION}"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN install -d -m 1777 /tmp

COPY --from=builder /out/chiptrace /usr/local/bin/chiptrace

USER 10001:10001
ENTRYPOINT ["chiptrace"]
CMD ["--help"]
