.PHONY: check test gateway-test gateway-receipt-test gateway-host-test gateway-source-test failed-outbox-replay-test codex-config-test claude-config-test codex-route-preflight-test managed-route-test protocol-collection-test protocol-sandbox-contract-test native-context-test native-canary-gate-test native-canary-evidence-test stock-release-gate-test producer-support-gate-test producer-report-gate-test provider-response-gate-test live-preflight-contract-test action-pin-gate-test runtime-health-gate-test quality-baseline-test quality-reason-contract-test platform-health-gate-test relay-quality-seed-test deployment-smoke-contract-test audit-memory-test turn-memory-test platform-test deployment-config-test gateway-preflight-test maas-contract-test self-test cloud-test m0-test build benchmark benchmark-store benchmark-http benchmark-compression

CHIPTRACE_VERSION ?= 0.6.0
CHIPTRACE_REVISION ?= $(shell git rev-parse HEAD)

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

test:
	cargo test --workspace --all-targets --locked
	$(MAKE) gateway-test
	$(MAKE) codex-config-test
	$(MAKE) maas-contract-test

maas-contract-test:
	cargo test -p chiptrace maas_export --lib --locked

gateway-test:
	node --test integrations/openai-gateway/durable-outbox.test.js

gateway-receipt-test:
	cargo build --locked --bin chiptrace
	node --test integrations/openai-gateway/relay-receipt.test.js

gateway-host-test:
	node --test integrations/openai-gateway/host-health.test.js

gateway-source-test:
	node --test integrations/openai-gateway/server-capture.test.js integrations/openai-gateway/server-identity.test.js integrations/openai-gateway/server-drop-health.test.js

failed-outbox-replay-test:
	node --test scripts/ops/replay-failed-outbox.test.js

codex-config-test:
	cargo build --locked --bin chiptrace
	node --test integrations/codex/config-contract.test.js integrations/codex/hook-ack.test.js
	node --test integrations/codex/install-patched-codex.test.js
	node --test scripts/ci/upstream-context.test.js scripts/ci/producer-source-cache.test.js scripts/ci/producer-command.test.js

claude-config-test:
	node --test integrations/claude-code/config-contract.test.js

codex-route-preflight-test:
	node --test scripts/deploy/codex-route-preflight.test.js

managed-route-test:
	node --test integrations/codex/managed-route.test.js

protocol-collection-test:
	node --test --test-concurrency=1 integrations/codex/protocol-collection.test.js integrations/codex/protocol-interruption.test.js integrations/codex/protocol-compaction.test.js integrations/codex/protocol-auto-compaction.test.js

protocol-sandbox-contract-test:
	node --test integrations/codex/protocol-fixture.test.js

native-context-test:
	cargo build --locked --bin chiptrace
	node --test integrations/codex/native-context.test.js integrations/codex/protocol-fixture.test.js

native-canary-gate-test:
	node --test scripts/ci/native-canary-gate.test.js

native-canary-evidence-test:
	node --test scripts/ci/native-canary-evidence.test.js

stock-release-gate-test:
	node --test scripts/ci/stock-release-gate.test.js

producer-support-gate-test:
	node --test scripts/ci/producer-support-gate.test.js

producer-report-gate-test:
	node --test scripts/ci/producer-report-gate.test.js

provider-response-gate-test:
	node --test scripts/ci/provider-response-gate.test.js

live-preflight-contract-test:
	node --test scripts/ci/live-preflight-contract.test.js

action-pin-gate-test:
	node --test scripts/ci/action-pin-gate.test.js

runtime-health-gate-test:
	node --test scripts/ci/runtime-health-gate.test.js

quality-baseline-test:
	node --test scripts/ci/quality-baseline.test.js

quality-reason-contract-test:
	node --test scripts/ci/quality-reason-contract.test.js

platform-health-gate-test:
	node --test scripts/ci/platform-health-gate.test.js

relay-quality-seed-test:
	node --test scripts/ci/relay-quality-seed.test.js

deployment-smoke-contract-test:
	node --test scripts/ci/deployment-smoke.test.js

audit-memory-test: build
	node scripts/ci/audit-memory-gate.js

turn-memory-test:
	node scripts/ci/turn-memory-gate.js

platform-test:
	cargo build --locked --bin chiptrace
	node --test integrations/cloud-platform/platform.test.js integrations/cloud-platform/server.test.js integrations/cloud-platform/storage-oss.test.js

deployment-config-test:
	node --test scripts/deploy/preflight.test.js
	$(MAKE) gateway-preflight-test

gateway-preflight-test:
	node --test scripts/deploy/gateway-preflight.test.js

self-test:
	cargo run --locked --bin chiptrace -- self-test

cloud-test:
	$(MAKE) check
	$(MAKE) test
	$(MAKE) failed-outbox-replay-test
	$(MAKE) gateway-receipt-test
	$(MAKE) self-test
	$(MAKE) claude-config-test
	$(MAKE) codex-route-preflight-test
	$(MAKE) native-context-test
	$(MAKE) native-canary-gate-test
	$(MAKE) native-canary-evidence-test
	$(MAKE) stock-release-gate-test
	$(MAKE) producer-support-gate-test
	$(MAKE) producer-report-gate-test
	$(MAKE) provider-response-gate-test
	$(MAKE) live-preflight-contract-test
	$(MAKE) action-pin-gate-test
	$(MAKE) runtime-health-gate-test
	$(MAKE) quality-baseline-test
	$(MAKE) quality-reason-contract-test
	$(MAKE) platform-health-gate-test
	$(MAKE) relay-quality-seed-test
	$(MAKE) deployment-smoke-contract-test
	$(MAKE) platform-test
	$(MAKE) deployment-config-test

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
