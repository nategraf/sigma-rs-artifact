# lox-extensions

Lox is a reputation-based bridge distribution system that provides privacy protection to users and their social graph while remaining open to all users. It is described in [Tulloch and Goldberg](https://petsymposium.org/popets/2023/popets-2023-0029.php) (and in greater detail [here](https://uwspace.uwaterloo.ca/handle/10012/18333)). It is currently being maintained by the [Tor Project](https://www.torproject.org/download/)'s [Anti-censorship team](https://gitlab.torproject.org/tpo/anti-censorship/team).

`lox-extensions` is a rust crate that is a re-implementation and replacement of the [`lox-library`](https://crates.io/crates/lox-library) crate, depending on a different set of cryptographic libraries to implement Lox's anonymous credential based reputation system. `lox-extensions` uses the following `sigma-rs` crates: 

- [`cmz`](https://crates.io/crates/cmz) ([`-core`](https://crates.io/crates/cmz-core) and [`-derive`](https://crates.io/crates/cmz-derive)) together facilitate the creation of the Lox system as a series of [10 protocols](src/proto/) described in compact statements using [5 µCMZ credentials](src/lox_creds.rs). The output of our protocols are fed to the `sigma-compiler` crates.

- [`sigma-compiler`](https://crates.io/crates/sigma-compiler) ([`-derive`](https://crates.io/crates/sigma-compiler-derive)) automatically generate the code for sigma zero-knowledge proof protocols from the more complex statements described at the `cmz` layer. These are given to the `sigma-compiler` layer and compiled into statements about linear combinations of points, that can be consumed by the `sigma-proofs` API.

- [`sigma-proofs`](https://crates.io/crates/sigma-proofs) perform zero-knowledge proofs based on the input from the `sigma-compiler`.

Building and testing this crate, requires `cargo`. You can get `cargo` by [installing Rust](https://www.rust-lang.org/tools/install). We used Rust version 1.89.

All Lox tests can be run with `cargo test --features bridgeauth`

## Notable Changes to adapt Lox for Tor

Some changes have been made to integrate the existing Lox protocols with Tor's bridge distributor [rdsys](https://gitlab.torproject.org/tpo/anti-censorship/rdsys), but so far, no changes have been made to alter the functionality of the Lox protocols themselves.

These changes are necessary to keep the consistentcy of bridges in buckets that Lox requires while working with the reality of how rdsys/Tor currently receives and distributes information about bridges. The changes to Lox are:
1. Add a `uid_fingerprint` field to the [`BridgeLine`](src/bridge_table.rs?ref_type=heads#L51) struct which helps with bridge lookup and corresponds (roughly) to the unique fingerprint rdsys gives to each bridge (made up of a hash of the IP and pluggable transport type)
2. Allow for the details of a bridge to be updated. This has been added to
   [`src/lib.rs`](src/lib.rs?ref_type=heads#L557) and accounts for the fact that some details of an existing bridge (i.e., that has a matching fingerprint) may be updated from time to time.
3. Allow for a bridge to be replaced without penalty. This has also been added to [`src/lib.rs`](src/lib.rs?ref_type=heads#L668) and accounts for the fact that Tor currently does not have a robust way of
   [knowing that a bridge is blocked](https://gitlab.torproject.org/tpo/anti-censorship/censorship-analysis/-/issues/40035), but does have some tests (namely,
   [bridgestrap](https://gitlab.torproject.org/tpo/anti-censorship/bridgestrap) and [onbasca](https://gitlab.torproject.org/tpo/network-health/onbasca)) that help to determine if a bridge should not be distributed. Since we do not know if the results of these tests indicate a blocking event, we are allowing for bridges that rdsys marks as unsuitable for distribution to be updated without penalty in the Lox library.
4. The vectors within `bridge_table.rs` have been refactored into HashMaps that use a unique `u32` for lookup. This has led to a
number of changes around how bridges are inserted/removed from the bridge table but does not impact the overall functionality of the Lox system.
5. The `DupFilter` has been changed from a `HashMap` to a `HashSet`, primarily because this is easier to Serialize/Deserialize when storing the state of the Lox system to recover from failure or to be able to roll back to a previous state.
6. The [`dalek-cryptography`](https://dalek.rs/) libraries have been updated to their most recent versions and the `zkp` library ~~has been forked (until/unless this is fixed in one of the existing upstream repos) to fix a bug that appears when a public attribute is set to 0 (previously impacting only the blockage migration protocol when a user's invitations are set to 0 after migrating). The fork of `zkp` also includes similar updates to `dalek-cryptography` dependencies and some others such as `rand`.~~ has been replaced by the [`sigma-rs`](https://github.com/sigma-rs) libraries.
This allows us to express protocols using the `cmz` library and prove things expressed in statements with the `sigma-proofs` library. All of the public/private key pairs are of type `CMZPubKey` and `CMZPrivKey` and our credentials are expressed using the cmz credential macro.
7. Many tests that were used to create the Lox paper/thesis and measure the performance of the system were removed from this repository as they are unnecessary in a deployment scenario. They are still available in the [original repository](https://git-crysp.uwaterloo.ca/iang/lox).
8. Key rotation protocols were added to allow users to anonymously update existing [Lox](src/proto/update_cred.rs) and [Invitation](src/proto/update_invite.rs) credentials to use new keys.

### Other important Notes

As with the original implementation, this implementation is coded such that the reachability certificate expires at 00:00 UTC. Therefore, if an unlucky user requests a reachability certificate just before 00:00 UTC and tries to use it just after, the request will fail. If the bucket is still reachable, a user can simply request a new reachability token if their request fails for this reason (a new certificate should be available prior to the outdated certificate expiring).

##### Note on the abandonment of `lox-library`:
It was initially unclear how fundamentally the lox code base would need to change to fit as an extension of the generic anonymous credential stack that we envisioned with `sigma-rs`. As such, development of `lox-extension` started as a complete rewrite of each of the Lox protocols with the relatively minor changes to the Lox authority and other elements of the system coming later. To reflect the development process, and the reframing of Lox as an extension, or layer, of a more generic anonymous credentials stack, and to mitigate the many breaking changes involved, creating a new `lox-extension` crate seemed most appropriate.

##### Note on future changes:
In terms of functionality, the initial version of this crate is fundamentally unchanged from the `lox-library` which is consistent with the Lox system described
in [Tulloch and Goldberg](https://petsymposium.org/popets/2023/popets-2023-0029.php). However, this implementation may diverge from the theory over time as the system is deployed and its limitations as a censorship circumvention tool are better illuminated.

