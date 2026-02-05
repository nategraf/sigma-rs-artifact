FROM ubuntu:24.04
RUN apt update && apt install -y build-essential rustup python3-pip libssl-dev pkg-config git curl make iproute2

# rdsys (one of the dependencies for the Lox benchmarks) is written in Go
RUN curl -OL https://golang.org/dl/go1.25.6.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.25.6.linux-amd64.tar.gz \
    && rm go1.25.6.linux-amd64.tar.gz

# Set up Go environment
ENV PATH=$PATH:/usr/local/go/bin

# Verify installation
RUN go version

# Install a recent Rust compiler
RUN install -D /usr/bin/rustup /root/.cargo/bin/rustup && /root/.cargo/bin/rustup install 1.92.0

COPY . /root/sigma-rs-artifact/

# Build all the tests, binaries, benchmarks
WORKDIR /root/sigma-rs-artifact/spongefish
RUN cargo build --release --all-targets
RUN cargo build --release --all-targets -p spongefish
WORKDIR /root/sigma-rs-artifact/sigma-proofs
RUN cargo build --release --all-targets
WORKDIR /root/sigma-rs-artifact/sigma-compiler
RUN cargo build --release --all-targets
WORKDIR /root/sigma-rs-artifact/sigma-compiler/sigma-compiler-core
RUN cargo build --release --all-targets
WORKDIR /root/sigma-rs-artifact/sigma-compiler/sigma-compiler-derive
RUN cargo build --release --all-targets
WORKDIR /root/sigma-rs-artifact/cmz
RUN cargo build --release --all-targets
WORKDIR /root/sigma-rs-artifact/cmz/cmz-core
RUN cargo build --release --all-targets
WORKDIR /root/sigma-rs-artifact/cmz/cmz-derive
RUN cargo build --release --all-targets
WORKDIR /root/sigma-rs-artifact/application-ooni
RUN cargo build --release --all-targets
RUN cargo build --release --all-targets -p ooniauth-core
WORKDIR /root/sigma-rs-artifact/application-lox/crates/lox-extensions
RUN cargo build --release --features=bridgeauth,test --all-targets
WORKDIR /root/sigma-rs-artifact/application-lox-zkp/crates/lox-library
RUN cargo build --release --features=bridgeauth --all-targets

# Build the wasm testing environment
WORKDIR /root/sigma-rs-artifact
RUN git clone https://gitlab.torproject.org/tpo/anti-censorship/rdsys.git
WORKDIR /root/sigma-rs-artifact/rdsys
RUN make build
RUN make descriptors
WORKDIR /root/sigma-rs-artifact/application-lox/crates/lox-wasm
RUN cargo install wasm-pack
RUN /root/.cargo/bin/wasm-pack build --release --target web
WORKDIR /root/sigma-rs-artifact/application-lox-zkp/crates/lox-wasm
RUN /root/.cargo/bin/wasm-pack build --release --target web

WORKDIR /root/sigma-rs-artifact/
