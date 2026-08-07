# syntax=docker/dockerfile:1
# =============================================================================
# RoleBlank OS — backend production image
# =============================================================================
# Build context is the `backend/` directory (see docker-compose.dev.yml).
#
# Two stages, deliberately:
#   builder  — carries the Rust toolchain, the full source tree and the whole
#              ~256-crate dependency graph. None of that may reach production:
#              a compiler in a runtime image is an attacker's toolbox.
#   runtime  — a bare debian-slim with exactly one binary, the migrations, and
#              the CA bundle. Nothing else.
#
# WHY debian-slim and not alpine/distroless:
#   - The build uses the default glibc target; alpine would need musl and a
#     different toolchain, and Argon2id/ring behave differently under musl's
#     allocator. Keeping builder and runtime on the same libc removes a whole
#     class of "works in CI, segfaults in prod" problems.
#   - distroless would work, but it makes incident-time debugging (exec a shell)
#     impossible without rebuilding. debian-slim is the pragmatic middle.
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: builder
# -----------------------------------------------------------------------------
# `rust:1-bookworm` is pinned to the same Debian release as the runtime stage so
# the produced binary links against the glibc that will actually be present at
# run time. It is also the image already used by scripts/rb.ps1, so local builds
# and image builds use one identical toolchain (rustc 1.97.1).
FROM rust:1-bookworm AS builder

WORKDIR /build

# --- Dependency layer --------------------------------------------------------
# Only the manifests are copied first. Docker caches this layer on the hash of
# Cargo.toml + Cargo.lock alone, so editing application source does NOT
# invalidate the (slow) dependency compile. This is the single biggest build-time
# win available and it is why the dummy main.rs below exists.
COPY Cargo.toml Cargo.lock ./

# Placeholders satisfying BOTH declared targets in Cargo.toml — the `[lib]` at
# src/lib.rs and the `[[bin]]` at src/main.rs. Cargo refuses to resolve a manifest
# whose declared target file is missing, so dependencies cannot be compiled
# without *some* source at each path. Omitting the lib placeholder fails with
# `couldn't read src/lib.rs`.
RUN mkdir -p src \
    && echo '// dependency-cache placeholder — never shipped' > src/lib.rs \
    && echo 'fn main() { panic!("dependency-cache placeholder — never shipped"); }' > src/main.rs

# Compile the dependency graph in release mode. `--locked` fails the build if
# Cargo.lock would need to change: a container build must never silently resolve
# a different (possibly yanked or newly-vulnerable) dependency version than the
# one CI audited.
RUN cargo build --release --locked --bin roleblank-api

# --- Application layer -------------------------------------------------------
# Real sources land only now, after the dependency layer is cached.
#
# The placeholders are removed first: `COPY src ./src` merges into the existing
# directory, and a stale placeholder that the real tree does not overwrite would
# be compiled instead of the genuine file.
RUN rm -rf src
COPY src ./src
COPY migrations ./migrations

# Cargo's change detection is mtime-based. COPY sets a fresh mtime on src/, but
# the stale placeholder artefacts must still be removed explicitly: otherwise a
# fingerprint collision can leave the placeholder binary in place. Deleting the
# crate's own artefacts (not the whole target/) forces a rebuild of just this
# crate while every dependency stays cached.
# BOTH targets' artefacts must go: the crate is a library plus a thin binary, and
# the dependency layer compiled a placeholder for each. Deleting only the binary's
# artefacts leaves the placeholder *library* cached, and the real `main.rs` then
# fails with `unresolved import roleblank_backend::cli` — the library it links
# against is the empty stub.
RUN rm -f target/release/roleblank-api \
          target/release/deps/roleblank_api* \
          target/release/deps/roleblank_backend* \
          target/release/deps/libroleblank_backend* \
          target/release/libroleblank_backend* \
    && cargo build --release --locked --bin roleblank-api \
    # Fail loudly here rather than at container start if the binary is missing.
    && test -x target/release/roleblank-api

# -----------------------------------------------------------------------------
# Stage 2: runtime
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# ca-certificates is the ONLY package installed. It is required because the
# application connects to PostgreSQL over rustls and rustls has no built-in trust
# store — without the system CA bundle every TLS handshake to a managed database
# fails at certificate verification. Everything else (curl, wget, psql, shells
# beyond the base image's own) is deliberately absent to keep the attack surface
# and the CVE surface minimal.
#
# The apt lists are removed in the same RUN so the package index never becomes a
# layer in the final image.
RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Fixed, high, non-overlapping uid/gid. Fixed (rather than auto-assigned) so that
# file ownership is stable and predictable when a volume is mounted from a host
# or another image; high (10001) so it cannot collide with a distro system
# account; non-root because a compromised process must not be uid 0 — this is
# what makes `--read-only`, `--cap-drop=ALL` and a non-privileged runtime
# actually meaningful.
RUN groupadd --system --gid 10001 roleblank \
    && useradd --system --uid 10001 --gid 10001 \
       --home-dir /app --no-create-home --shell /usr/sbin/nologin roleblank

WORKDIR /app

# The binary is the only artefact taken from the builder besides the migrations.
# No source, no Cargo.lock, no toolchain, no build cache — nothing that would let
# an intruder rebuild or read the code, and nothing that could carry a secret
# baked in at build time (this image is built with no build-args and no secrets).
COPY --from=builder --chown=root:root --chmod=0755 \
     /build/target/release/roleblank-api /usr/local/bin/roleblank-api

# Migrations ship with the image so that `roleblank-api migrate` can be run as a
# one-shot job from the exact same immutable artefact that will serve traffic —
# the migration set and the code that depends on it can then never drift apart.
# Owned by root and readable-only by the app user: the runtime must never be able
# to rewrite its own migration files.
COPY --from=builder --chown=root:root /build/migrations /app/migrations

USER roleblank

# Documentation only (EXPOSE publishes nothing). The application's in-container
# listen port is 8080; the host mapping is the orchestrator's concern.
EXPOSE 8080

# --- Deliberately NO HEALTHCHECK ---------------------------------------------
# This image contains no curl, no wget and no shell-based HTTP client, by design
# (see the ca-certificates comment above). A Docker HEALTHCHECK would therefore
# require adding one of those tools back purely to satisfy a directive — trading
# a permanently larger attack surface for a probe the orchestrator can already
# perform better from the outside.
#
# The orchestrator (compose, Kubernetes, ECS, …) MUST instead probe over HTTP:
#     liveness :  GET /health/live
#     readiness:  GET /health/ready
# Do not "fix" this by installing curl.
# -----------------------------------------------------------------------------

# ENTRYPOINT is the binary and CMD is only the subcommand, so operators can run
# the other subcommands against the identical image without overriding the
# entrypoint:   docker run <image> migrate | verify-audit | check-config
ENTRYPOINT ["/usr/local/bin/roleblank-api"]
CMD ["serve"]
