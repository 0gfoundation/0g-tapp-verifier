# Build
FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# The AS proto is shared with the trustee stack next door, so the build context
# must be the repo root: docker build -f scan/Dockerfile .
COPY scan/Cargo.toml scan/build.rs ./scan/
COPY scan/src ./scan/src
COPY scan/proto ./scan/proto
COPY tdx-boot-chain/attestation.proto ./tdx-boot-chain/
WORKDIR /src/scan
RUN cargo build --release --locked || cargo build --release

# Run
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/scan/target/release/tappscan /usr/local/bin/tappscan
# Caches live here; mount a volume so a restart does not re-scan the chain and
# re-attest every node.
WORKDIR /var/lib/tappscan
ENV TAPPSCAN_CACHE=/var/lib/tappscan/chain.json \
    TAPPSCAN_STATUS=/var/lib/tappscan/status.json \
    TAPPSCAN_BIND=0.0.0.0:8088 \
    RUST_LOG=tappscan=info
EXPOSE 8088
ENTRYPOINT ["tappscan"]
CMD ["serve"]
