# Use the same pinned Ubuntu 26.04 LTS base for compilation and execution.
FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db AS base

FROM base AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates rustup \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
RUN rustup toolchain install 1.90.0 --profile minimal \
    && rustup default 1.90.0
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN cargo test --locked --release && cargo build --locked --release

FROM base AS runtime
RUN groupadd --gid 10001 worker \
    && useradd --uid 10001 --gid 10001 --create-home worker
COPY --from=build /src/target/release/wifi-cap2hashcat /usr/local/bin/wifi-cap2hashcat
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/local/share/wifi-cap2hashcat/
COPY third_party/rust/ /usr/local/share/wifi-cap2hashcat/third_party/rust/
USER 10001:10001
WORKDIR /home/worker
ENTRYPOINT ["/usr/local/bin/wifi-cap2hashcat"]
CMD ["--help"]
