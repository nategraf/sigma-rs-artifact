# Changelog

Entries are listed in reverse chronological order.


## 0.2.0

* Update Rust crate lazy_static to 1.4.0
* Update Rust crate ed25519-dalek to 2.1.1
* Update Rust crate curve25519-dalek to 4.1.2
* Update Rust crate chrono to 0.4.38
* Update Rust crate bincode to 1.3.3
* Update thiserror to 1.0.59
* Update Rust crate serde to 1.0.195
* Update time to 0.3.36
* Update Rust crate serde_with to 3.0.0
* Update Rust crate thiserror to 1.0.69
* Add bridgeauth feature to lox library
* Remove unused dependency statistical, prometheus, hexfmt
* Add additional protocols update_cred and update_invite to handle key rotation
* Make lox's bridgetable private with required getters
* Fix syncing issue that replaced not working spare bridges instead of removing them
* Add more descriptive errors for proto functions
* Fix bug in bridge_replace fn, test
* Fix length of bridge bytes and rdsys request interval
* Respond with error when open invitation buckets are empty
* Add refactors and additional tests for added functions


## 0.1.0

* Add db to store lox-context
* Update serde to 1.0.193
* Update serde_with to 3.4.0
* Update thiserror to 1.0.50
* Update time to 0.3.30
* Update rand to 0.8.0
* Update sha1 to 0.10
* Update aes-gcm to 0.10
* Update base64 to 0.21.4
* Update subtle to 2.5
* Update curve25519-dalek to 4, pointing to dalek-cryptography instead of zkcrypto
* Update ed25519-dalek to 2, pointing to dalek-cryptography instead of zkcrypto
* Change zkp dependency to lox-zkp 0.8.0
* Add/Adjust constants BRIDGE_BYTES, MAX_DAILY_BRIDGES, EXPIRY_DATE
* Change bridge_unreachable function to bridge_blocked
* Fixed bug in blockage-migration due to bug in zkp crate, removed in lox-zkp
* Add functionality required to sync bridges from rdsys with the lox bridge table
* Limit the number of open invites that are distributed each day
* Convert bridge table structures from Vectors to HashMaps
* Add logic to clean up unused buckets and find next bucket key
* Add Tor MIT license
* Add function to replace bridges that are determined to be down/not working rather than blocked
* Make Issuer Keys, BridgeDB, BridgeAuth (de)serializeabe

## Pre 0.1.0

* Original release, created for Lox: Protecting the Social Graph in Bridge Distribution
 Paper: https://petsymposium.org/popets/2023/popets-2023-0029.php
 Original Repo: https://git-crysp.uwaterloo.ca/iang/lox
