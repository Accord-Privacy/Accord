# ── Stage 1: Build ──────────────────────────────────────────────
FROM rust:1.93-bookworm AS builder

WORKDIR /src
COPY . .

RUN cargo build --release -p accord-server \
    && strip target/release/accord-server

# ── Stage 2: Runtime ────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r accord && useradd -r -g accord -m accord

COPY --from=builder /src/target/release/accord-server /usr/local/bin/accord-server

RUN mkdir -p /data && chown accord:accord /data
VOLUME /data
WORKDIR /data

USER accord

EXPOSE 8080 9443

ENTRYPOINT ["accord-server"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--database", "/data/accord.db"]
