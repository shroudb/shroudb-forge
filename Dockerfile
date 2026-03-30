# Cross-compilation images — selected by TARGETARCH (set automatically by buildx)
ARG TARGETARCH=amd64
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:x86_64-musl AS cross-amd64
FROM --platform=$BUILDPLATFORM messense/rust-musl-cross:aarch64-musl AS cross-arm64
FROM cross-${TARGETARCH} AS builder

WORKDIR /build
COPY . .

ARG TARGETARCH
RUN --mount=type=secret,id=registry_token \
    mkdir -p /root/.cargo && \
    printf '[source.crates-io]\nreplace-with = "shroudb-cratesio"\n\n[source.shroudb-cratesio]\nregistry = "sparse+https://crates.shroudb.dev/api/v1/cratesio/"\n\n[registries.shroudb-cratesio]\nindex = "sparse+https://crates.shroudb.dev/api/v1/cratesio/"\ncredential-provider = ["cargo:token"]\n\n[registries.shroudb]\nindex = "sparse+https://crates.shroudb.dev/api/v1/crates/"\ncredential-provider = ["cargo:token"]\n' > /root/.cargo/config.toml && \
    RUST_TARGET=$(if [ "$TARGETARCH" = "arm64" ]; then echo "aarch64-unknown-linux-musl"; else echo "x86_64-unknown-linux-musl"; fi) && \
    CARGO_REGISTRIES_SHROUDB_CRATESIO_TOKEN="$(cat /run/secrets/registry_token)" \
    CARGO_REGISTRIES_SHROUDB_TOKEN="$(cat /run/secrets/registry_token)" \
    cargo build --release --target "$RUST_TARGET" -p shroudb-forge-server -p shroudb-forge-cli && \
    mkdir -p /out && \
    cp "target/$RUST_TARGET/release/shroudb-forge" /out/ && \
    cp "target/$RUST_TARGET/release/shroudb-forge-cli" /out/

# --- shroudb-forge: internal certificate authority engine ---
FROM alpine:3.21 AS shroudb-forge
RUN adduser -D -u 65532 shroudb && \
    mkdir /data && chown shroudb:shroudb /data
LABEL org.opencontainers.image.title="ShrouDB Forge" \
      org.opencontainers.image.description="Internal certificate authority with CA lifecycle management" \
      org.opencontainers.image.vendor="ShrouDB" \
      org.opencontainers.image.url="https://github.com/shroudb/shroudb-forge" \
      org.opencontainers.image.source="https://github.com/shroudb/shroudb-forge" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /out/shroudb-forge /shroudb-forge
VOLUME /data
WORKDIR /data
USER shroudb
EXPOSE 6699 6700
ENTRYPOINT ["/shroudb-forge"]

# --- shroudb-forge-cli: CLI tool ---
FROM alpine:3.21 AS shroudb-forge-cli
RUN adduser -D -u 65532 shroudb
LABEL org.opencontainers.image.title="ShrouDB Forge CLI" \
      org.opencontainers.image.description="CLI tool for the Forge internal certificate authority" \
      org.opencontainers.image.vendor="ShrouDB" \
      org.opencontainers.image.url="https://github.com/shroudb/shroudb-forge" \
      org.opencontainers.image.source="https://github.com/shroudb/shroudb-forge" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=builder /out/shroudb-forge-cli /shroudb-forge-cli
USER shroudb
ENTRYPOINT ["/shroudb-forge-cli"]
