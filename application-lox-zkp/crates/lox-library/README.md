# Lox

Lox is a reputation-based bridge distribution system that provides privacy protection to users and their social graph and is open to all users.

The protocols in the Lox-library are consistent with the Lox system described
in [Tulloch and Goldberg](https://petsymposium.org/popets/2023/popets-2023-0029.php) (and in greater detail [here](https://uwspace.uwaterloo.ca/handle/10012/18333)). However, this implementation may diverge from the theory over time as the system is deployed and its limitations are better illuminated. The [original version of this library](https://git-crysp.uwaterloo.ca/iang/lox) will remain a more precise implementation of the theory.

Lox is written in rust and requires `cargo` to test. [Install Rust](https://www.rust-lang.org/tools/install). We used Rust version 1.65.0.

## Notable Changes from the original repository

Some changes have been made to integrate the existing Lox protocols with Tor's
bridge distributor [rdsys](https://gitlab.torproject.org/tpo/anti-censorship/rdsys),
but so far, these have not affected the Lox protocols themselves.

These changes are necessary to keep the consistentcy of bridges in buckets that Lox requires while working with the reality of how rdsys/Tor currently receives and distributes information about bridges. The changes to Lox are:
1. Add a `uid_fingerprint` field to the BridgeLine which helps with bridge lookup and
   corresponds (roughly) to the unique fingerprint rdsys gives to each bridge
   (made up of a hash of the IP and pluggable transport type)
2. Allow for the details of a bridge to be updated. This has been added to
   [`crates/lox-library/src/lib.rs`](https://gitlab.torproject.org/tpo/anti-censorship/lox-rs/-/blob/main/crates/lox-library/src/lib.rs) and accounts for the fact that some details
   of an existing bridge (i.e., that has a matching fingerprint) may be updated
   from time to time.
3. Allow for a bridge to be replaced without penalty. This has also been added to
   [`crates/lox-library/src/lib.rs`](https://gitlab.torproject.org/tpo/anti-censorship/lox-rs/-/blob/main/crates/lox-library/src/lib.rs)
   and accounts for the fact that Tor currently does not have a robust way of
   [knowing that a bridge is blocked](https://gitlab.torproject.org/tpo/anti-censorship/censorship-analysis/-/issues/40035), but does have some tests (namely,
   [bridgestrap](https://gitlab.torproject.org/tpo/anti-censorship/bridgestrap) and [onbasca](https://gitlab.torproject.org/tpo/network-health/onbasca)) that help to determine if a
   bridge should not be distributed. Since we do not know if the results of
   these tests indicate a blocking event, we are allowing for bridges that
   rdsys marks as unsuitable for distribution to be updated without penalty in the Lox library.
4. The vectors within `bridge_table.rs` have been refactored into HashMaps that use a unique `u32` for lookup. This has led to a
number of changes around how bridges are inserted/removed from the bridge table but does not impact the overall functionality of the Lox system.
5. The `DupFilter` has been changed from a `HashMap` to a `HashSet`, primarily because this is easier to Serialize/Deserialize when storing the state of the Lox system to recover from failure or to be able to roll back to a previous state.
6. The [`dalek-cryptography`](https://dalek.rs/) libraries have been updated to their most recent versions and the `zkp` library has been forked (until/unless this is fixed in one of the existing upstream repos) to fix a bug that appears when a public attribute is set to 0 (previously impacting only the blockage migration protocol when a user's invitations are set to 0 after migrating). The fork of `zkp` also includes similar updates to `dalek-cryptography` dependencies and some others such as `rand`.
7. Many tests that were used to create the Lox paper/thesis and measure the performance of the system were removed from this repository as they are unnecessary in a deployment scenario. They are still available in the [original repository](https://git-crysp.uwaterloo.ca/iang/lox).

### Other important Notes

As with the original implementation, this implementation is coded such that the reachability certificate expires at 00:00 UTC. Therefore, if an unlucky user requests a reachability certificate just before the 00:00 UTC and tries to use it just after, the request will fail. If the bucket is still reachable, a user can simply request a new reachability token if their request fails for this reason (a new certificate should be available prior to the outdated certificate expiring).
