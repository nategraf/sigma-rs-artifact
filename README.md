# Code artifact for `sigma-rs`

This repository contains the code artifact for `sigma-rs`, a Rust
software stack for implementing protocols based on keyed-verification
anonymous credentials (KVAC).

## Artifact structure

The directories in this repository are as follows:

  - [`Scripts`](Scripts/)
    : Useful scripts for building a docker image for this artifact, and running tests therein
  - [`application-lox-zkp`](application-lox-zkp/)
    : A fork of [the Tor Project's Lox code repository](https://gitlab.torproject.org/tpo/anti-censorship/lox), which uses de Valence's [zkp crate](https://github.com/dalek-cryptography/zkp) to implement its zero-knowledge proofs; we added code to perform benchmarks to compare the zkp-based implementation to our own.  The main subdirectory containing the zkp-based Lox implementation is [`application-lox-zkp/crates/lox-library`](application-lox-zkp/crates/lox-library/).
  - [`application-lox`](application-lox/)
    : Another fork of [the Tor Project's Lox code repository](https://gitlab.torproject.org/tpo/anti-censorship/lox), which uses our `sigma-rs` software stack to re-implement the Lox protocols.  Our re-implementation is in the [`application-lox/crates/lox-extensions`](application-lox/crates/lox-extensions/) subdirectory.
  - [`application-ooni`](application-ooni/)
    : Our implementation of anonymous credential protocols for [OONI](https://ooni.org/), the Open Observatory for Network Interference.  The main implementation is in the [`application-ooni/ooniauth-core`](application-ooni/ooniauth-core/) subdirectory.
  - [`cmz`](cmz/), [`sigma-compiler`](sigma-compiler/), [`sigma-proofs`](sigma-proofs/), [`spongefish`](spongefish/)
    : The constituent crates in our `sigma-rs` software stack

## Building the artifact

You will need `docker` installed on your host system.

After downloading or cloning this repository, build a docker image with:
```bash
  ./Scripts/build-docker
```

On a recentish laptop, this image should take around 10 minutes to build.  The resulting image is about 8 GB.

## Start the docker

Start the docker with:

```bash
  docker run --expose=8000 -it sigma-rs bash
```

**All of the remaining commands below should be run _within_ the docker.**

## Running the unit tests

To ensure everything has built properly, you should run the unit tests within the docker with:

```bash
  Scripts/run_all_tests
```

This should take less than 10 seconds to run.

## Running the Lox native client / native server benchmarks

To run the Lox native client / native server benchmarks (the "native" columns in Table 2 of the paper):

  - zkp version: `(cd application-lox-zkp/crates/lox-library/; ./run_test.sh)`  
    The results will be placed in the `application-lox-zkp/crates/lox-library/parsed_results/` directory
  - `sigma-rs` version: `(cd application-lox/crates/lox-extensions/; ./run_test.sh)`  
    The results will be placed in the `application-lox/crates/lox-extensions/parsed_results/` directory

Each run should take less than 30 seconds.

## Running the Lox wasm client / native server benchmarks

To run the Lox wasm client / native server benchmarks (the "wasm" columns in Table 2), 
follow the instructions in [`application-lox/crates/lox-extensions/TESTING.md`](application-lox/crates/lox-extensions/TESTING.md).  For now, you will have to manually adapt the instructions to a docker environment (more automation coming soon!).

## Running the OONI native benchmarks

To run the OONI native benchmarks (the "native" columns in Table 3):

```bash
(cd application-ooni && \
    cargo bench -p ooniauth-core && \
    python3 scripts/criterion_extract.py )
```

This benchmark should take under 2 minutes to run.

## Running the OONI iOS benchmarks

To run the OONI iOS benchmarks (the "iOS" column in Table 3), see the instructions in [`application-ooni/ios/README.md`](application-ooni/ios/README.md).

## Using `sigma-rs` in your own code

For instructions on using the `sigma-rs` stack to implement your own
KVAC protocols, see [`cmz/README.md`](cmz/README.md).
