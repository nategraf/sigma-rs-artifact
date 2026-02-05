# Lox: A privacy preserving bridge distribution system

Lox is a privacy preserving, reputation-based bridge distribution system that is being integrated into Tor. This integration has multiple pieces that are divided into crates within this workspace.

## Current status

#### lox-library

The protocols in the Lox-library are consistent with the Lox system described
in [Tulloch and Goldberg](https://petsymposium.org/popets/2023/popets-2023-0029.php) (and in greater detail [here](https://uwspace.uwaterloo.ca/handle/10012/18333)).

Some changes have been made to integrate the existing Lox protocols with Tor's
bridge distributor [rdsys](https://gitlab.torproject.org/tpo/anti-censorship/rdsys),
but so far, these have not affected the Lox protocols themselves.

These changes are necessary to keep the consistentcy of bridges in buckets that Lox requires while working with the reality of h how rdsys/Tor currently receives and distributes information about bridges. The changes to Lox are:
1. Add a `uid_fingerprint` field to the BridgeLine which helps with bridge lookup and
   corresponds (roughly) to the unique fingerprint rdsys gives to each bridge
   (made up of a hash of the IP and pluggable transport type)
2. Allow for the details of a bridge to be updated. This has been added to
   [`crates/lox-library/src/lib.rs`](https://gitlab.torproject.org/tpo/anti-censorship/lox-rs/-/blob/main/crates/lox-library/src/lib.rs) and accounts for the fact that some details
   of an existing bridge (i.e., that has a matching fingerprint) may be updated
   from time to time.
3. Allow for a bridge to be replaced. This has also been added to
   [`crates/lox-library/src/lib.rs`](https://gitlab.torproject.org/tpo/anti-censorship/lox-rs/-/blob/main/crates/lox-library/src/lib.rs)
   and accounts for the fact that Tor currently does not have a robust way of
   [knowing that a bridge is blocked](https://gitlab.torproject.org/tpo/anti-censorship/censorship-analysis/-/issues/40035), but does have some tests (namely,
   [bridgestrap](https://gitlab.torproject.org/tpo/anti-censorship/bridgestrap) and [onbasca](https://gitlab.torproject.org/tpo/network-health/onbasca)) to know if a
   bridge should not be distributed. Since we do not know if the results of
   these tests indicate a blocking event, we are allowing for bridges that
   rdsys marks as `gone` to be updated without penalty in the Lox library.
4. The vectors within `bridge_table.rs` have been refactored into HashMaps that use a unique `u32` for lookup. This will be backed by some kind of persistent storage prior to deployment.


#### lox-distributor

The `lox-distributor` acts as an intermediary between `rdsys`, the `lox-library`'s server protocols and
client requests from `lox-wasm` integrated into Tor browser. 

Currently, it receives resources from `rdsys` through the
[`rdsys-backend-api`](https://gitlab.torproject.org/onyinyang/lox-rs/-/tree/main/crates/rdsys-backend-api), parses them into `new`, `changed`, or `gone` resources (i.e., BridgeLines) that can then be added, updated or replaced in the Lox `bridge_table`.

The `lox-distributor` also handles client requests from the Tor browser for Lox
credentials and all related functionality.

#### lox-wasm

The `lox-wasm` library implements the client side of the `lox-library` with
[`wasm-bindgen`](https://rustwasm.github.io/wasm-bindgen/) to facilitate it's
integration into Tor browser.

#### lox-utils

`lox-utils` is a set of functions that don't really belong to one specific lox
project but are useful across several projects within this Lox workspace.

#### rdsys-backend-api

The `rdsys-backend-api` polls rdsys and translates resources received from rdsys into the proper format expected by the `lox-distributor`. Next up for the `rdsys-backend-api`:

Since Lox requires bridge persistence more than other bridge distributors the `rdsys-backend-api` requires additional logic to determine which `gone` resources should be handed out to the `lox-distributor`. This likely means: `gone` resources that have been failing tests, and are thus `gone` for x length of time, since we will not want a resource that is down temporarily to be completely removed from whatever bucket it has been placed in.

## Building the various parts of Lox


## Roadmap

Please see our plans for this workspace in the [wiki](https://gitlab.torproject.org/tpo/anti-censorship/lox-rs/-/wikis/Lox-Roadmap).
