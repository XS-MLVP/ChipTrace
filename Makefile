.PHONY: check test gateway-test self-test m0-test build benchmark benchmark-store benchmark-http benchmark-compression

CHIPTRACE_VERSION ?= 0.5.1
CHIPTRACE_REVISION ?= $(shell git rev-parse HEAD)

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

test:
	cargo test --workspace --all-targets --locked
	$(MAKE) gateway-test

gateway-test:
	node --test integrations/openai-gateway/durable-outbox.test.js

self-test:
	cargo run --locked --bin chiptrace -- self-test

m0-test:
	CHIPTRACE_VERSION=$(CHIPTRACE_VERSION) CHIPTRACE_REVISION=$(CHIPTRACE_REVISION) \
		docker compose -f deploy/docker-compose.yml run --rm --build m0

build:
	cargo build --release --locked --bin chiptrace

benchmark:
	$(MAKE) benchmark-store
	$(MAKE) benchmark-http
	$(MAKE) benchmark-compression

benchmark-store:
	cargo run --release --locked --bin chiptrace -- benchmark-store

benchmark-http:
	cargo run --release --locked --bin chiptrace -- benchmark-http

benchmark-compression:
	cargo run --release --locked --bin chiptrace -- benchmark-compression
