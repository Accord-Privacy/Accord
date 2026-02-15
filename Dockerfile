# Multi-stage Docker build for Accord server
# Optimized for security and small image size

# Build stage
FROM rust:1.86-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY core/Cargo.toml ./core/
COPY server/Cargo.toml ./server/

# Create dummy source files to cache dependencies
RUN mkdir -p core/src server/src && \
    echo "fn main() {}" > core/src/lib.rs && \
    echo "fn main() {}" > server/src/main.rs

# Build dependencies (cached layer)
RUN cargo build --release --bin accord-server

# Remove dummy files
RUN rm -rf core/src server/src

# Copy actual source code
COPY core/ ./core/
COPY server/ ./server/

# Build application with security-focused profile
RUN cargo build --profile secure --bin accord-server

# Runtime stage
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get autoremove -y \
    && apt-get clean

# Create non-root user
RUN groupadd -r accord && useradd -r -g accord accord

# Create app directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/target/secure/accord-server /usr/local/bin/accord-server

# Create data directory
RUN mkdir -p /app/data && chown accord:accord /app/data

# Switch to non-root user
USER accord

# Expose port (default 8443 for HTTPS)
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f https://localhost:8443/health || exit 1

# Run the application
CMD ["accord-server"]