.PHONY: check test self-test build benchmark benchmark-store benchmark-http benchmark-compression

check:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

test:
	cargo test --workspace --all-targets --locked

self-test:
	cargo run --locked --bin chiptrace -- self-test

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
