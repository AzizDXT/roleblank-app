# RoleBlank OS — developer commands (Linux / macOS / CI).
#
# Windows developers use scripts/rb.ps1 instead, which wraps these same commands
# in a Linux container. That indirection exists because the Windows host enforces
# an Application Control policy that refuses to execute freshly compiled binaries
# (see docs/backend/00-reconnaissance.md §3) — it is an environment constraint,
# not a preference.
#
# Every recipe fails on the first error: make stops on a non-zero exit status, and
# multi-command recipes are chained with && rather than newlines so a failure in
# the middle cannot be silently ignored.

.PHONY: help dev db-up db-down db-reset db-provision migrate build release run \
        test test-security test-race lint fmt audit deny coverage load-test \
        backup-dev restore-dev verify-audit openapi-check ci clean

BACKEND      := backend
PG_CONTAINER := roleblank-postgres
PG_IMAGE     := postgres:18.4-alpine
PG_PORT      := 5440

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# --- database ---------------------------------------------------------------

db-up: ## start the development PostgreSQL 18 container (loopback only)
	@docker ps --filter "name=^/$(PG_CONTAINER)$$" --format '{{.Names}}' | grep -q . || \
	docker run -d --name $(PG_CONTAINER) --network roleblank_net \
	  -e POSTGRES_PASSWORD=dev_superuser_pw_local_only \
	  -e POSTGRES_USER=postgres -e POSTGRES_DB=postgres \
	  -e POSTGRES_INITDB_ARGS=--data-checksums \
	  -v roleblank_pgdata:/var/lib/postgresql \
	  -p 127.0.0.1:$(PG_PORT):5432 \
	  --health-cmd "pg_isready -U postgres" --health-interval 3s --health-retries 20 \
	  $(PG_IMAGE)
	@echo "waiting for postgres..." && \
	for i in $$(seq 1 40); do \
	  [ "$$(docker inspect -f '{{.State.Health.Status}}' $(PG_CONTAINER) 2>/dev/null)" = "healthy" ] && exit 0; \
	  sleep 1; \
	done; echo "postgres did not become healthy" >&2; exit 1

db-down: ## stop the development database
	docker rm -f $(PG_CONTAINER) 2>/dev/null || true

db-reset: db-down ## destroy the data volume and start clean
	docker volume rm roleblank_pgdata 2>/dev/null || true
	$(MAKE) db-up

db-provision: db-up ## create the migrator and runtime roles (idempotent)
	docker exec -i $(PG_CONTAINER) psql -v ON_ERROR_STOP=1 -U postgres -d postgres < ops/sql/provision_dev.sql

migrate: ## apply pending migrations as the migrator role
	cd $(BACKEND) && cargo run --bin roleblank-api -- migrate

# --- build and run ----------------------------------------------------------

build: ## debug build
	cd $(BACKEND) && cargo build --locked

release: ## optimised build
	cd $(BACKEND) && cargo build --release --locked

run: ## run the API in the foreground
	cd $(BACKEND) && cargo run --bin roleblank-api -- serve

# --- tests ------------------------------------------------------------------

test: ## unit + integration tests (requires db-provision)
	cd $(BACKEND) && cargo test --all-features

test-security: ## the adversarial suites only
	cd $(BACKEND) && cargo test --test security_suite -- --nocapture

test-race: ## the concurrency suites only
	cd $(BACKEND) && cargo test --test race_suite -- --nocapture --test-threads=1

# --- quality gates ----------------------------------------------------------

lint: ## formatting and clippy, warnings are errors
	cd $(BACKEND) && cargo fmt --all -- --check && \
	cargo clippy --all-targets --all-features -- -D warnings

fmt: ## apply formatting
	cd $(BACKEND) && cargo fmt --all

audit: ## known vulnerability scan
	cd $(BACKEND) && (cargo audit --version >/dev/null 2>&1 || cargo install cargo-audit --locked) && cargo audit

deny: ## licence, source and ban policy
	cd $(BACKEND) && (cargo deny --version >/dev/null 2>&1 || cargo install cargo-deny --locked) && \
	cargo deny --manifest-path Cargo.toml --config ../deny.toml check

coverage: ## line coverage summary
	cd $(BACKEND) && (cargo llvm-cov --version >/dev/null 2>&1 || cargo install cargo-llvm-cov --locked) && \
	rustup component add llvm-tools-preview && cargo llvm-cov --summary-only

openapi-check: ## fail if the router and api/openapi.yaml have drifted
	cd $(BACKEND) && cargo test --test openapi_contract

# --- operations -------------------------------------------------------------

verify-audit: ## verify the audit hash chain
	cd $(BACKEND) && cargo run --bin roleblank-api -- verify-audit

backup-dev: ## logical backup of the development database
	./scripts/backup_dev.sh

restore-dev: ## restore the most recent development backup (needs RB_CONFIRM_RESTORE=yes)
	./scripts/restore_dev.sh

load-test: ## run the load-test scenarios (needs RB_LOAD_TEST_TOKEN)
	./scripts/load_test.sh

# --- aggregate --------------------------------------------------------------

ci: lint build test audit deny openapi-check ## everything CI runs

clean:
	cd $(BACKEND) && cargo clean
