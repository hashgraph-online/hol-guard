FROM rust:1.88.0-slim-bookworm AS builder
WORKDIR /src
COPY ci/gauntlet-rs /src/ci/gauntlet-rs
COPY ci/gauntlet/control_plane/static /src/ci/gauntlet/control_plane/static
RUN cargo build --release --locked --manifest-path /src/ci/gauntlet-rs/Cargo.toml -p gauntlet-dashboard --bin gauntlet-dashboard

FROM debian:bookworm-slim
COPY --from=builder /src/ci/gauntlet-rs/target/release/gauntlet-dashboard /usr/local/bin/gauntlet-dashboard
USER 65532:65532
EXPOSE 8787
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s CMD ["/usr/local/bin/gauntlet-dashboard", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/gauntlet-dashboard", "--state", "/state", "--bind", "0.0.0.0", "--port", "8787"]
