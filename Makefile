.PHONY: fmt lint test build check e2e man release

fmt:
	cargo fmt --all

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all-targets --all-features

build:
	cargo build --all-targets

check: fmt lint test build

e2e:
	./scripts/run-e2e.sh

man:
	mkdir -p target/man
	pandoc --standalone --to man docs/man.md --output target/man/ssh-key-sync.1

release: man
	cargo build --release --all-targets
