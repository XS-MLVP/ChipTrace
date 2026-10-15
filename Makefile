.PHONY: check test gateway-test gateway-host-test codex-config-test managed-route-test native-context-test native-canary-gate-test native-canary-evidence-test runtime-health-gate-test platform-test self-test cloud-test m0-test build benchmark benchmark-store benchmark-http benchmark-compression

CHIPTRACE_VERSION ?= 0.6.0
CHIPTRACE_REVISION ?= $(shell git rev-parse HEAD)

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

test:
	cargo test --workspace --all-targets --locked
	$(MAKE) gateway-test
	$(MAKE) codex-config-test

gateway-test:
	node --test integrations/openai-gateway/durable-outbox.test.js

gateway-host-test:
	node --test integrations/openai-gateway/host-health.test.js

codex-config-test:
	node --test integrations/codex/config-contract.test.js
	node --test scripts/ci/upstream-context.test.js

managed-route-test:
	node --test integrations/codex/managed-route.test.js

native-context-test:
	cargo build --locked --bin chiptrace
	node --test integrations/codex/native-context.test.js

native-canary-gate-test:
	node --test scripts/ci/native-canary-gate.test.js

native-canary-evidence-test:
	node --test scripts/ci/native-canary-evidence.test.js

runtime-health-gate-test:
	node --test scripts/ci/runtime-health-gate.test.js

platform-test:
	cargo build --locked --bin chiptrace
	node --test integrations/cloud-platform/platform.test.js integrations/cloud-platform/storage-oss.test.js

self-test:
	cargo run --locked --bin chiptrace -- self-test

cloud-test:
	$(MAKE) check
	$(MAKE) test
	$(MAKE) self-test
	$(MAKE) native-context-test
	$(MAKE) native-canary-gate-test
	$(MAKE) native-canary-evidence-test
	$(MAKE) runtime-health-gate-test
	$(MAKE) platform-test

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
