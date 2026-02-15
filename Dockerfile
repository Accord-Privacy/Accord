# Multi-stage Docker build for Accord relay server
# Stage 1: Rust builder
FROM rust:1.86-slim AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY core/Cargo.toml ./core/
COPY server/Cargo.toml ./server/

# Create dummy source files to build dependencies
RUN mkdir -p core/src server/src && \
    echo "fn main() {}" > core/src/lib.rs && \
    echo "fn main() {}" > server/src/main.rs

# Build dependencies (cached layer)
RUN cargo build --release -p accord-server

# Remove dummy files
RUN rm -rf core/src server/src

# Copy actual source code
COPY core/ ./core/
COPY server/ ./server/

# Build the actual server
RUN cargo build --release -p accord-server

# Stage 2: Runtime image
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd -r accord && useradd -r -g accord accord

# Create app and data directories
RUN mkdir -p /data && chown accord:accord /data

# Copy binary from builder stage
COPY --from=builder /app/target/release/accord-server /usr/local/bin/accord-server

# Switch to non-root user
USER accord

# Expose port 8080
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD test -f /proc/1/cmdline || exit 1

# Run the server
CMD ["accord-server"]