# syntax=docker/dockerfile:1
#
# Multi-stage build for Portal (the HOLDFAST apex launcher/dashboard).
#   - builder: rust:1.96-slim (Debian trixie; ships gcc for the `ring` C build).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates.
#
# Like keyward/beacon, Portal links NO OpenSSL: the Beacon fetch uses rustls + `ring`, so
# the binary depends only on glibc — no libssl in either stage. The container HEALTHCHECK
# uses the built-in `portal healthcheck` subcommand, so no extra HTTP tool is needed.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Cache the dependency graph first: build a throwaway lib/bin against the real manifest so
# `cargo build` only recompiles our crate when src/ changes, not the whole tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --bin portal \
    && rm -rf src

# Now build the real binary. Templates + static assets are embedded via include_str!, so
# they must be present at compile time.
COPY src ./src
COPY static ./static
COPY templates ./templates
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin portal \
    && strip target/release/portal

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home portal
COPY --from=builder /build/target/release/portal /usr/local/bin/portal

USER portal
# Default in-container bind + internal backend URLs; overridable at runtime. The dashboard
# fetches all three concurrently (resilient: any unreachable backend degrades to "—"/unknown).
ENV BIND_ADDR=0.0.0.0:8600
ENV BEACON_URL=http://beacon:8400
ENV VITALS_URL=http://vitals:8300
ENV WATCHTOWER_URL=http://watchtower:8500
EXPOSE 8600

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["portal", "healthcheck"]

ENTRYPOINT ["portal"]
