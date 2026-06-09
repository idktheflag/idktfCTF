# ── Stage 1: Builder ──────────────────────────────────────────────────────────
# We compile in a full Rust image, then copy only the binary into a minimal
# runtime image. This is called a "multi-stage build" — it's how you keep
# Docker images small. The builder stage ends up ~1.5 GB; the final image ~100 MB.
FROM rust:1.78-slim AS builder

WORKDIR /app

# ── Dependency caching trick ──────────────────────────────────────────────────
# Docker builds layer by layer and caches each layer. If we COPY source first,
# any source change invalidates the cache and re-downloads all crates (slow).
#
# Instead:
#   1. Copy only Cargo.toml and Cargo.lock (the dependency manifest).
#   2. Create a fake src/main.rs so `cargo build` has something to compile.
#   3. Build — this downloads and compiles all dependencies.
#   4. THEN copy real source and rebuild — only our code recompiles, not deps.
#
# This makes iterative rebuilds much faster in CI.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release
# Remove the fake binary so it doesn't interfere with the real build.
RUN rm -f target/release/idktfCTF

# ── Copy real source and build ────────────────────────────────────────────────
COPY src ./src
COPY migrations ./migrations
# `touch` updates the file timestamp — Cargo uses timestamps to decide what
# needs recompiling. Without this, Cargo might skip main.rs since it wasn't
# "changed" (we already built a main.rs above).
RUN touch src/main.rs
RUN cargo build --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# debian:bookworm-slim is ~80 MB — much smaller than the Rust toolchain image.
# We need libssl for reqwest (TLS) and ca-certificates for HTTPS connections.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Keeping the image clean: rm removes the apt cache so it doesn't bloat the layer.

# Copy only the compiled binary from the builder stage.
COPY --from=builder /app/target/release/idktfCTF /usr/local/bin/idktfCTF

# The server reads config from env vars at startup (DATABASE_URL, JWT_SECRET, etc.)
# These are injected by Kubernetes Secrets — not baked into the image.
EXPOSE 3000

CMD ["idktfCTF"]
