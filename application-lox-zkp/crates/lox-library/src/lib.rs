/*! Implementation of a new style of bridge authority for Tor that
allows users to invite other users, while protecting the social graph
from the bridge authority itself.

We use CMZ14 credentials (GGM version, which is more efficient, but
makes a stronger security assumption): "Algebraic MACs and
Keyed-Verification Anonymous Credentials" (Chase, Meiklejohn, and
Zaverucha, CCS 2014)

The notation follows that of the paper "Hyphae: Social Secret Sharing"
(Lovecruft and de Valence, 2017), Section 4. */

// We really want points to be capital letters and scalars to be
// lowercase letters
#![allow(non_snake_case)]

#[macro_use]
extern crate lox_zkp;

pub mod bridge_table;
pub mod cred;
pub mod dumper;
pub mod dup_filter;
pub mod migration_table;
pub mod mock_auth;

#[cfg(feature = "bridgeauth")]
use chrono::{DateTime, Duration, Utc};
use sha2::Sha512;

use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
#[cfg(test)]
use curve25519_dalek::traits::IsIdentity;
#[allow(unused_imports)]
use rand::rngs::OsRng;
#[allow(unused_imports)]
use rand::Rng;
#[cfg(feature = "bridgeauth")]
use std::collections::HashMap;
#[cfg(feature = "bridgeauth")]
use std::convert::TryFrom;
use std::convert::TryInto;

#[cfg(feature = "bridgeauth")]
use ed25519_dalek::{Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey};
use subtle::ConstantTimeEq;

#[cfg(feature = "bridgeauth")]
use std::collections::HashSet;

#[cfg(feature = "bridgeauth")]
use bridge_table::{
    BridgeLine, BridgeTable, EncryptedBucket, MAX_BRIDGES_PER_BUCKET, MIN_BUCKET_REACHABILITY,
};
#[cfg(feature = "bridgeauth")]
use migration_table::{MigrationTable, MigrationType};

use lazy_static::lazy_static;

use serde::{Deserialize, Serialize};
#[cfg(feature = "bridgeauth")]
use thiserror::Error;

lazy_static! {
    pub static ref CMZ_A: RistrettoPoint =
        RistrettoPoint::hash_from_bytes::<Sha512>(b"CMZ Generator A");
    pub static ref CMZ_B: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;
    pub static ref CMZ_A_TABLE: RistrettoBasepointTable = RistrettoBasepointTable::create(&CMZ_A);
    pub static ref CMZ_B_TABLE: RistrettoBasepointTable =
        dalek_constants::RISTRETTO_BASEPOINT_TABLE.clone();
}

// EXPIRY_DATE is set to EXPIRY_DATE days for open-entry and blocked buckets in order to match
// the expiry date for Lox credentials.This particular value (EXPIRY_DATE) is chosen because
// values that are 2^k − 1 make range proofs more efficient, but this can be changed to any value
pub const EXPIRY_DATE: u32 = 511;

/// ReplaceSuccess sends a signal to the lox-distributor to inform
/// whether or not a bridge was successfully replaced
#[derive(PartialEq, Eq)]
#[cfg(feature = "bridgeauth")]
pub enum ReplaceSuccess {
    NotFound = 0,
    NotReplaced = 1,
    Replaced = 2,
    Removed = 3,
}

/// This error is thrown if the number of buckets/keys in the bridge table
/// exceeds u32 MAX.It is unlikely this error will ever occur.
#[derive(Error, Debug)]
#[cfg(feature = "bridgeauth")]
pub enum NoAvailableIDError {
    #[error("Find key exhausted with no available index found!")]
    ExhaustedIndexer,
}

/// This error is thrown after the MAX_DAILY_BRIDGES threshold for bridges
/// distributed in a day has been reached
#[derive(Error, Debug)]
#[cfg(feature = "bridgeauth")]
pub enum OpenInvitationError {
    #[error("The maximum number of bridges has already been distributed today, please try again tomorrow!")]
    ExceededMaxBridges,

    #[error("There are no bridges available for open invitations.")]
    NoBridgesAvailable,
}

#[derive(Error, Debug)]
#[cfg(feature = "bridgeauth")]
pub enum BridgeTableError {
    #[error("The bucket corresponding to key {0} was not in the bridge table")]
    MissingBucket(u32),
}

/// Private Key of the Issuer
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IssuerPrivKey {
    x0tilde: Scalar,
    x: Vec<Scalar>,
}

impl IssuerPrivKey {
    /// Create an IssuerPrivKey for credentials with the given number of
    /// attributes.
    pub fn new(n: u16) -> IssuerPrivKey {
        let mut rng = rand::rngs::OsRng;
        let x0tilde = Scalar::random(&mut rng);
        let mut x: Vec<Scalar> = Vec::with_capacity((n + 1) as usize);

        // Set x to a vector of n+1 random Scalars
        x.resize_with((n + 1) as usize, || Scalar::random(&mut rng));

        IssuerPrivKey { x0tilde, x }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IssuerPubKey {
    X: Vec<RistrettoPoint>,
}

/// Public Key of the Issuer
impl IssuerPubKey {
    /// Create an IssuerPubKey from the corresponding IssuerPrivKey
    pub fn new(privkey: &IssuerPrivKey) -> IssuerPubKey {
        let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;
        let Btable: &RistrettoBasepointTable = &CMZ_B_TABLE;
        let n_plus_one = privkey.x.len();
        let mut X: Vec<RistrettoPoint> = Vec::with_capacity(n_plus_one);

        // The first element is a special case; it is
        // X[0] = x0tilde*A + x[0]*B
        X.push(&privkey.x0tilde * Atable + &privkey.x[0] * Btable);

        // The other elements (1 through n) are X[i] = x[i]*A
        X.extend(privkey.x.iter().skip(1).map(|xi| xi * Atable));

        IssuerPubKey { X }
    }
}

/// Number of times a given invitation is ditributed
pub const OPENINV_K: u32 = 10;
/// TODO: Decide on maximum daily number of invitations to be distributed
pub const MAX_DAILY_BRIDGES: u32 = 100;
/// The BridgeDb. This will typically be a singleton object. The
/// BridgeDb's role is simply to issue signed "open invitations" to
/// people who are not yet part of the system.
#[derive(Debug, Serialize, Deserialize)]
#[cfg(feature = "bridgeauth")]
pub struct BridgeDb {
    /// The keypair for signing open invitations
    keypair: SigningKey,
    /// The public key for verifying open invitations
    pub pubkey: VerifyingKey,
    /// The set of open-invitation buckets
    openinv_buckets: HashSet<u32>,
    /// The set of open invitation buckets that have been distributed
    distributed_buckets: Vec<u32>,
    #[serde(skip)]
    today: DateTime<Utc>,
    pub current_k: u32,
    pub daily_bridges_distributed: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(feature = "bridgeauth")]
pub struct OldKeyStore {
    /// Most recently outdated lox secret and private keys for verifying update_cred credentials
    priv_key: IssuerPrivKey,
    /// The public key for verifying update_cred credentials
    pub pub_key: IssuerPubKey,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[cfg(feature = "bridgeauth")]
pub struct OldKeys {
    /// Most recently outdated lox secret and private keys for verifying update_cred credentials
    lox_keys: Vec<OldKeyStore>,
    /// Most recently outdated open_invitation VerifyingKey for verifying update_openinv tokens
    bridgedb_key: Vec<VerifyingKey>,
    /// Most recently outdated invitation secret and private keys for verifying update_inv credentials
    invitation_keys: Vec<OldKeyStore>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[cfg(feature = "bridgeauth")]
pub struct OldFilters {
    /// Most recently outdated lox id filter
    lox_filter: Vec<dup_filter::DupFilter<Scalar>>,
    /// Most recently outdated open invitation filter
    openinv_filter: Vec<dup_filter::DupFilter<Scalar>>,
    /// Most recently outdated invitation filter
    invitation_filter: Vec<dup_filter::DupFilter<Scalar>>,
}

/// An open invitation is a [u8; OPENINV_LENGTH] where the first 32
/// bytes are the serialization of a random Scalar (the invitation id),
/// the next 4 bytes are a little-endian bucket number, and the last
/// SIGNATURE_LENGTH bytes are the signature on the first 36 bytes.
pub const OPENINV_LENGTH: usize = 32 // the length of the random
                                     // invitation id (a Scalar)
    + 4 // the length of the u32 for the bucket number
    + ed25519_dalek::SIGNATURE_LENGTH; // the length of the signature

#[cfg(feature = "bridgeauth")]
impl BridgeDb {
    /// Create the BridgeDb.
    pub fn new() -> Self {
        let mut csprng = OsRng {};
        let keypair = SigningKey::generate(&mut csprng);
        let pubkey = keypair.verifying_key();
        Self {
            keypair,
            pubkey,
            openinv_buckets: Default::default(),
            distributed_buckets: Default::default(),
            today: Utc::now(),
            current_k: 0,
            daily_bridges_distributed: 0,
        }
    }

    pub fn openinv_length(&mut self) -> usize {
        self.openinv_buckets.len()
    }

    /// Rotate Open Invitation keys
    pub fn rotate_open_inv_keys(&mut self) -> VerifyingKey {
        let mut csprng = OsRng {};
        self.keypair = SigningKey::generate(&mut csprng);
        self.pubkey = self.keypair.verifying_key();
        self.pubkey
    }

    /// Insert an open-invitation bucket into the set
    pub fn insert_openinv(&mut self, bucket: u32) {
        self.openinv_buckets.insert(bucket);
    }

    /// Remove an open-invitation bucket from the set
    pub fn remove_openinv(&mut self, bucket: &u32) {
        self.openinv_buckets.remove(bucket);
    }

    /// Remove open invitation and/or otherwise distributed buckets that have
    /// become blocked or are expired to free up the index for a new bucket
    pub fn remove_blocked_or_expired_buckets(&mut self, bucket: &u32) {
        if self.openinv_buckets.contains(bucket) {
            println!("Removing a bucket that has not been distributed yet!");
            self.openinv_buckets.remove(bucket);
        } else if self.distributed_buckets.contains(bucket) {
            self.distributed_buckets.retain(|&x| x != *bucket);
        }
    }

    /// Mark a bucket as distributed
    pub fn mark_distributed(&mut self, bucket: u32) {
        self.distributed_buckets.push(bucket);
    }

    /// Produce an open invitation such that the next k users, where k is <
    /// OPENINV_K, will receive the same open invitation bucket
    /// chosen randomly from the set of open-invitation buckets.
    pub fn invite(&mut self) -> Result<[u8; OPENINV_LENGTH], OpenInvitationError> {
        let mut res: [u8; OPENINV_LENGTH] = [0; OPENINV_LENGTH];
        let mut rng = rand::rngs::OsRng;
        // Choose a random invitation id (a Scalar) and serialize it
        let id = Scalar::random(&mut rng);
        res[0..32].copy_from_slice(&id.to_bytes());
        let bucket_num: u32;
        if Utc::now() >= (self.today + Duration::days(1)) {
            self.today = Utc::now();
            self.daily_bridges_distributed = 0;
        }
        if self.daily_bridges_distributed < MAX_DAILY_BRIDGES {
            if self.current_k < OPENINV_K && !self.distributed_buckets.is_empty() {
                bucket_num = *self.distributed_buckets.last().unwrap();
                self.current_k += 1;
            } else {
                if self.openinv_buckets.is_empty() {
                    return Err(OpenInvitationError::NoBridgesAvailable);
                }
                // Choose a random bucket number (from the set of open
                // invitation buckets) and serialize it
                let openinv_vec: Vec<&u32> = self.openinv_buckets.iter().collect();
                bucket_num = *openinv_vec[rng.gen_range(0..openinv_vec.len())];
                self.mark_distributed(bucket_num);
                self.remove_openinv(&bucket_num);
                self.current_k = 1;
                self.daily_bridges_distributed += 1;
            }
            res[32..(32 + 4)].copy_from_slice(&bucket_num.to_le_bytes());
            // Sign the first 36 bytes and serialize it
            let sig = self.keypair.sign(&res[0..(32 + 4)]);
            res[(32 + 4)..].copy_from_slice(&sig.to_bytes());
            Ok(res)
        } else {
            Err(OpenInvitationError::ExceededMaxBridges)
        }
    }

    /// Verify an open invitation. Returns the invitation id and the
    /// bucket number if the signature checked out. It is up to the
    /// caller to then check that the invitation id has not been used
    /// before.
    pub fn verify(
        invitation: [u8; OPENINV_LENGTH],
        pubkey: VerifyingKey,
    ) -> Result<(Scalar, u32), SignatureError> {
        // Pull out the signature and verify it
        let sig = Signature::try_from(&invitation[(32 + 4)..])?;
        pubkey.verify(&invitation[0..(32 + 4)], &sig)?;
        // The signature passed. Pull out the bucket number and then
        // the invitation id
        let bucket = u32::from_le_bytes(invitation[32..(32 + 4)].try_into().unwrap());
        let s = Scalar::from_canonical_bytes(invitation[0..32].try_into().unwrap());
        if s.is_some().into() {
            Ok((s.unwrap(), bucket))
        } else {
            // It should never happen that there's a valid signature on
            // an invalid serialization of a Scalar, but check anyway.
            Err(SignatureError::new())
        }
    }
}

#[cfg(feature = "bridgeauth")]
impl Default for BridgeDb {
    fn default() -> Self {
        Self::new()
    }
}

/// The bridge authority. This will typically be a singleton object.
#[cfg(feature = "bridgeauth")]
#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeAuth {
    /// The private key for the main Lox credential
    lox_priv: IssuerPrivKey,
    /// The public key for the main Lox credential
    pub lox_pub: IssuerPubKey,
    /// The private key for migration credentials
    migration_priv: IssuerPrivKey,
    /// The public key for migration credentials
    pub migration_pub: IssuerPubKey,
    /// The private key for migration key credentials
    migrationkey_priv: IssuerPrivKey,
    /// The public key for migration key credentials
    pub migrationkey_pub: IssuerPubKey,
    /// The private key for bucket reachability credentials
    reachability_priv: IssuerPrivKey,
    /// The public key for bucket reachability credentials
    pub reachability_pub: IssuerPubKey,
    /// The private key for invitation credentials
    invitation_priv: IssuerPrivKey,
    /// The public key for invitation credentials
    pub invitation_pub: IssuerPubKey,

    /// The public key of the BridgeDb issuing open invitations
    pub bridgedb_pub: VerifyingKey,

    /// The bridge table
    bridge_table: BridgeTable,

    /// The migration tables
    trustup_migration_table: MigrationTable,
    blockage_migration_table: MigrationTable,

    /// Duplicate filter for open invitations
    bridgedb_pub_filter: dup_filter::DupFilter<Scalar>,
    /// Duplicate filter for Lox credential ids
    id_filter: dup_filter::DupFilter<Scalar>,
    /// Duplicate filter for Invitation credential ids
    inv_id_filter: dup_filter::DupFilter<Scalar>,
    /// Duplicate filter for trust promotions (from untrusted level 0 to
    /// trusted level 1)
    trust_promotion_filter: dup_filter::DupFilter<Scalar>,
    // Outdated Lox Keys to be populated with the old Lox private and public keys
    // after a key rotation
    old_keys: OldKeys,
    old_filters: OldFilters,

    /// For testing only: offset of the true time to the simulated time
    #[serde(skip)]
    time_offset: time::Duration,
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    pub fn new(bridgedb_pub: VerifyingKey) -> Self {
        // Create the private and public keys for each of the types of
        // credential, each with the appropriate number of attributes
        let lox_priv = IssuerPrivKey::new(6);
        let lox_pub = IssuerPubKey::new(&lox_priv);
        let migration_priv = IssuerPrivKey::new(4);
        let migration_pub = IssuerPubKey::new(&migration_priv);
        let migrationkey_priv = IssuerPrivKey::new(2);
        let migrationkey_pub = IssuerPubKey::new(&migrationkey_priv);
        let reachability_priv = IssuerPrivKey::new(2);
        let reachability_pub = IssuerPubKey::new(&reachability_priv);
        let invitation_priv = IssuerPrivKey::new(4);
        let invitation_pub = IssuerPubKey::new(&invitation_priv);
        Self {
            lox_priv,
            lox_pub,
            migration_priv,
            migration_pub,
            migrationkey_priv,
            migrationkey_pub,
            reachability_priv,
            reachability_pub,
            invitation_priv,
            invitation_pub,
            bridgedb_pub,
            bridge_table: Default::default(),
            trustup_migration_table: MigrationTable::new(MigrationType::TrustUpgrade),
            blockage_migration_table: MigrationTable::new(MigrationType::Blockage),
            bridgedb_pub_filter: Default::default(),
            id_filter: Default::default(),
            inv_id_filter: Default::default(),
            trust_promotion_filter: Default::default(),
            time_offset: time::Duration::ZERO,
            old_keys: Default::default(),
            old_filters: Default::default(),
        }
    }

    pub fn rotate_lox_keys(&mut self) {
        let updated_lox_priv = IssuerPrivKey::new(6);
        let updated_lox_pub = IssuerPubKey::new(&updated_lox_priv);
        // Store the old keys until the next key rotation (this should happen no more than 511 days after the
        // last rotation to ensure that all credentials issued with the old key can be updated
        self.old_keys.lox_keys.push(OldKeyStore {
            priv_key: self.lox_priv.clone(),
            pub_key: self.lox_pub.clone(),
        });
        // Move the old lox id filter to the old_lox_id_filter
        self.old_filters.lox_filter.push(self.id_filter.clone());
        // TODO: Commit to the new keys and post the commitment somewhere public that can be verified
        // by users, ideally
        self.lox_priv = updated_lox_priv;
        self.lox_pub = updated_lox_pub;
        self.id_filter = Default::default();
    }

    pub fn rotate_invitation_keys(&mut self) {
        let updated_invitation_priv = IssuerPrivKey::new(4);
        let updated_invitation_pub = IssuerPubKey::new(&updated_invitation_priv);
        // Store the old keys until the next key rotation (this should happen no more than 511 days after the
        // last rotation to ensure that all credentials issued with the old key can be updated
        self.old_keys.invitation_keys.push(OldKeyStore {
            priv_key: self.invitation_priv.clone(),
            pub_key: self.invitation_pub.clone(),
        });
        // Move the old invitation id filter to the old_invitation_id_filter
        self.old_filters
            .invitation_filter
            .push(self.inv_id_filter.clone());
        // TODO: Commit to the new keys and post the commitment somewhere public that can be verified
        // by users, ideally
        self.invitation_priv = updated_invitation_priv;
        self.invitation_pub = updated_invitation_pub;
        self.inv_id_filter = Default::default();
    }

    pub fn rotate_bridgedb_keys(&mut self, new_bridgedb_pub: VerifyingKey) {
        // Store the old verifying key until the next key rotation (this should happen no more often than the
        // we would reasonably expect a user to redeem an open invitation token to ensure that all invitations
        // issued with the old key can be updated)
        self.old_keys.bridgedb_key.push(self.bridgedb_pub);
        // Move the old lox id filter to the old_lox_id_filter
        self.old_filters
            .openinv_filter
            .push(self.bridgedb_pub_filter.clone());
        // TODO: Commit to the new keys and post the commitment somewhere public that can be verified
        // by users, ideally
        self.bridgedb_pub = new_bridgedb_pub;
        self.bridgedb_pub_filter = Default::default();
    }

    pub fn is_empty(&self) -> bool {
        self.bridge_table.buckets.is_empty()
    }

    pub fn reachable_length(&self) -> usize {
        self.bridge_table.reachable.len()
    }

    pub fn unallocated_length(&self) -> usize {
        self.bridge_table.unallocated_bridges.len()
    }

    pub fn spares_length(&self) -> usize {
        self.bridge_table.spares.len()
    }

    pub fn openinv_length(&self, bdb: &mut BridgeDb) -> usize {
        bdb.openinv_length()
    }

    /// Insert a set of open invitation bridges.
    ///
    /// Each of the bridges will be given its own open invitation
    /// bucket, and the BridgeDb will be informed. A single bucket
    /// containing all of the bridges will also be created, with a trust
    /// upgrade migration from each of the single-bridge buckets.
    pub fn add_openinv_bridges(
        &mut self,
        bridges: [BridgeLine; MAX_BRIDGES_PER_BUCKET],
        bdb: &mut BridgeDb,
    ) -> Result<(), NoAvailableIDError> {
        let bindex = self.find_next_available_key(bdb)?;
        self.bridge_table.new_bucket(bindex, &bridges);
        let mut single = [BridgeLine::default(); MAX_BRIDGES_PER_BUCKET];
        for b in bridges.iter() {
            let sindex = self.find_next_available_key(bdb)?;
            single[0] = *b;
            self.bridge_table.new_bucket(sindex, &single);
            self.bridge_table.open_inv_keys.push((sindex, self.today()));
            bdb.insert_openinv(sindex);
            self.trustup_migration_table.table.insert(sindex, bindex);
        }
        Ok(())
    }

    /// Insert a hot spare bucket of bridges
    pub fn add_spare_bucket(
        &mut self,
        bucket: [BridgeLine; MAX_BRIDGES_PER_BUCKET],
        bdb: &mut BridgeDb,
    ) -> Result<(), NoAvailableIDError> {
        let index = self.find_next_available_key(bdb)?;
        self.bridge_table.new_bucket(index, &bucket);
        self.bridge_table.spares.insert(index);
        Ok(())
    }

    /// When syncing the Lox bridge table with rdsys, this function returns any bridges
    /// that are found in the Lox bridge table that are not found in the Vector
    /// of bridges received from rdsys through the Lox distributor.
    pub fn find_and_remove_unaccounted_for_bridges(
        &mut self,
        accounted_for_bridges: Vec<u64>,
    ) -> Vec<BridgeLine> {
        let mut unaccounted_for: Vec<BridgeLine> = Vec::new();
        for (k, _v) in self.bridge_table.reachable.clone() {
            if !accounted_for_bridges.contains(&k.uid_fingerprint) {
                unaccounted_for.push(k);
            }
        }
        unaccounted_for
    }

    /// Allocate single left over bridges to an open invitation bucket
    pub fn allocate_bridges(
        &mut self,
        distributor_bridges: &mut Vec<BridgeLine>,
        bdb: &mut BridgeDb,
    ) {
        while let Some(bridge) = distributor_bridges.pop() {
            self.bridge_table.unallocated_bridges.push(bridge);
        }
        while self.bridge_table.unallocated_bridges.len() >= MAX_BRIDGES_PER_BUCKET {
            let mut bucket = [BridgeLine::default(); MAX_BRIDGES_PER_BUCKET];
            for bridge in bucket.iter_mut() {
                *bridge = self.bridge_table.unallocated_bridges.pop().unwrap();
            }
            match self.add_openinv_bridges(bucket, bdb) {
                Ok(_) => continue,
                Err(e) => {
                    println!("Error: {e}");
                    for bridge in bucket {
                        self.bridge_table.unallocated_bridges.push(bridge);
                    }
                }
            }
        }
    }

    // Update the details of a bridge in the bridge table. This assumes that the IP and Port
    // of a given bridge remains the same and thus can be updated.
    // First we must retrieve the list of reachable bridges, then we must search for any matching our partial key
    // which will include the IP and Port. Finally we can replace the original bridge with the updated bridge.
    // Returns true if the bridge has successfully updated
    pub fn bridge_update(&mut self, bridge: &BridgeLine) -> bool {
        let mut res: bool = false; //default False to assume that update failed
        let reachable_bridges = self.bridge_table.reachable.clone();
        for reachable_bridge in reachable_bridges {
            if reachable_bridge.0.uid_fingerprint == bridge.uid_fingerprint {
                // Now we must remove the old bridge from the table and insert the new bridge in its place
                // i.e., in the same bucket and with the same permissions.
                let positions = self.bridge_table.reachable.get(&reachable_bridge.0);
                if let Some(v) = positions {
                    for (bucketnum, offset) in v.iter() {
                        let mut bridgelines = match self.bridge_table.buckets.get(bucketnum) {
                            Some(bridgelines) => *bridgelines,
                            None => return res,
                        };
                        assert!(bridgelines[*offset] == reachable_bridge.0);
                        bridgelines[*offset] = *bridge;
                        self.bridge_table.buckets.insert(*bucketnum, bridgelines);
                        if !self.bridge_table.buckets.contains_key(bucketnum) {
                            return res;
                        }
                    }
                    res = true;
                } else {
                    return res;
                }
                // We must also remove the old bridge from the reachable bridges table
                // and add the new bridge
                self.bridge_table.reachable.remove(&reachable_bridge.0);
                self.bridge_table
                    .reachable
                    .insert(*bridge, reachable_bridge.1);
                return res;
            }
        }
        // Also check the unallocated bridges just in case there is a bridge that should be updated there
        let unallocated_bridges = self.bridge_table.unallocated_bridges.clone();
        for (i, unallocated_bridge) in unallocated_bridges.iter().enumerate() {
            if unallocated_bridge.uid_fingerprint == bridge.uid_fingerprint {
                // Now we must remove the old bridge from the unallocated bridges and insert the new bridge
                // in its place
                self.bridge_table.unallocated_bridges.remove(i);
                self.bridge_table.unallocated_bridges.push(*bridge);
                res = true;
            }
        }
        // If this is returned, we assume that the bridge wasn't found in the bridge table
        // and therefore should be treated as a "new bridge"
        res
    }

    // Repurpose a bucket of spares into unallocated bridges
    pub fn dissolve_spare_bucket(&mut self, key: u32) -> Result<(), BridgeTableError> {
        self.bridge_table.spares.remove(&key);
        // Get the actual bridges from the spare bucket
        let spare_bucket = self
            .bridge_table
            .buckets
            .remove(&key)
            .ok_or(BridgeTableError::MissingBucket(key))?;
        for bridge in spare_bucket.iter() {
            self.bridge_table.unallocated_bridges.push(*bridge);
            // Mark bucket as unreachable while it is unallocated
            self.bridge_table.reachable.remove(bridge);
        }
        self.bridge_table.keys.remove(&key);
        self.bridge_table.recycleable_keys.push(key);
        Ok(())
    }

    // Removes an unallocated bridge and returns it if it was present
    pub fn remove_unallocated(&mut self, bridge: &BridgeLine) -> Option<BridgeLine> {
        match self
            .bridge_table
            .unallocated_bridges
            .iter()
            .position(|x| x == bridge)
        {
            Some(index) => Some(self.bridge_table.unallocated_bridges.swap_remove(index)),
            None => None,
        }
    }

    /// Attempt to remove a bridge that is failing tests and replace it with a bridge from
    /// available_bridge or from a spare bucket
    pub fn bridge_replace(
        &mut self,
        bridge: &BridgeLine,
        available_bridge: Option<BridgeLine>,
    ) -> ReplaceSuccess {
        let reachable_bridges = &self.bridge_table.reachable.clone();
        let Some(positions) = reachable_bridges.get(bridge) else {
            match self.remove_unallocated(bridge) {
                Some(_) => {
                    return ReplaceSuccess::Removed;
                }
                None => {
                    return ReplaceSuccess::NotFound;
                }
            }
        };
        // Check if the bridge is in a spare bucket first, if it is, dissolve the bucket
        if let Some(spare) = self
            .bridge_table
            .spares
            .iter()
            .find(|x| positions.iter().any(|(bucketnum, _)| &bucketnum == x))
            .cloned()
        {
            let Ok(_) = self.dissolve_spare_bucket(spare) else {
                return ReplaceSuccess::NotReplaced;
            };
            // Next Check if the bridge is in the unallocated bridges and remove the bridge if so
            // Bridges in spare buckets should have been moved to the unallocated bridges
            match self.remove_unallocated(bridge) {
                Some(_) => {
                    return ReplaceSuccess::Removed;
                }
                None => {
                    return ReplaceSuccess::NotFound;
                }
            }
        }
        // select replacement:
        //   - first try the given bridge
        //   - second try to pick one from the set of available bridges
        //   - third dissolve a spare bucket to create more available bridges
        let Some(replacement) = available_bridge.or_else(|| {
            self.bridge_table.unallocated_bridges.pop().or_else(|| {
                let spare = self
                    .bridge_table
                    .spares
                    .iter()
                    // in case bridge is a spare, avoid replacing it with itself
                    .find(|x| !positions.iter().any(|(bucketnum, _)| &bucketnum == x))
                    .cloned()?;
                let Ok(_) = self.dissolve_spare_bucket(spare) else {
                    return None;
                };
                self.bridge_table.unallocated_bridges.pop()
            })
        }) else {
            // If there are no available bridges that can be assigned here, the only thing
            // that can be done is return an indication that updating the gone bridge
            // didn't work.
            // In this case, we do not mark the bridge as unreachable or remove it from the
            // reachable bridges so that we can still find it when a new bridge does become available
            println!("No available bridges");
            return ReplaceSuccess::NotReplaced;
        };
        for (bucketnum, offset) in positions.iter() {
            let mut bridgelines = match self.bridge_table.buckets.get(bucketnum) {
                Some(bridgelines) => *bridgelines,
                None => return ReplaceSuccess::NotFound,
            };
            assert!(bridgelines[*offset] == *bridge);
            bridgelines[*offset] = replacement;
            self.bridge_table.buckets.insert(*bucketnum, bridgelines);
            // Remove the bridge from the reachable bridges and add new bridge
            self.bridge_table
                .reachable
                .insert(replacement, positions.clone());
            // Remove the bridge from the bucket
            self.bridge_table.reachable.remove(bridge);
        }
        ReplaceSuccess::Replaced
    }

    /// Mark a bridge as blocked
    ///
    /// This bridge will be removed from each of the buckets that
    /// contains it. If any of those are open-invitation buckets, the
    /// trust upgrade migration for that bucket will be removed and the
    /// BridgeDb will be informed to stop handing out that bridge. If
    /// any of those are trusted buckets where the number of reachable
    /// bridges has fallen below the threshold, a blockage migration
    /// from that bucket to a spare bucket will be added, and the spare
    /// bucket will be removed from the list of hot spares. In
    /// addition, if the blocked bucket was the _target_ of a blockage
    /// migration, change the target to the new (formerly spare) bucket.
    /// Returns true if sucessful, or false if it needed a hot spare but
    /// there was none available.
    pub fn bridge_blocked(&mut self, bridge: &BridgeLine, bdb: &mut BridgeDb) -> bool {
        let mut res: bool = true;
        if self.remove_unallocated(bridge).is_some() {
            return true;
        }
        if let Some(positions) = self.bridge_table.reachable.get(bridge) {
            for (bucketnum, offset) in positions.iter() {
                // Count how many bridges in this bucket are reachable
                let mut bucket = match self.bridge_table.buckets.get(bucketnum) {
                    Some(bridgelines) => *bridgelines,
                    None => return false, // This should not happen
                };
                // Remove the bridge from the bucket
                assert!(bucket[*offset] == *bridge);
                bucket[*offset] = BridgeLine::default();

                // If this is an open invitation bucket, there is only one bridge, remove bucket
                if bdb.openinv_buckets.contains(bucketnum)
                    || bdb.distributed_buckets.contains(bucketnum)
                {
                    bdb.remove_blocked_or_expired_buckets(bucketnum);
                    self.trustup_migration_table.table.remove(bucketnum);
                    continue;
                }

                // If this bucket still has an acceptable number of bridges, continue
                let numreachable = bucket
                    .iter()
                    .filter(|br| self.bridge_table.reachable.contains_key(br))
                    .count();
                if numreachable != MIN_BUCKET_REACHABILITY {
                    // No
                    continue;
                }

                // Remove any trust upgrade migrations to this bucket
                self.trustup_migration_table
                    .table
                    .retain(|_, &mut v| v != *bucketnum);

                // If there are no spares, delete blockage migrations leading to this bucket
                if self.bridge_table.spares.is_empty() {
                    res = false;
                    self.blockage_migration_table
                        .table
                        .retain(|_, &mut v| v != *bucketnum);
                    continue;
                }
                // Get the first spare and remove it from the spares
                // set.
                let spare = *self.bridge_table.spares.iter().next().unwrap();
                self.bridge_table.spares.remove(&spare);
                self.bridge_table
                    .blocked_keys
                    .push((*bucketnum, self.today()));
                // Add a blockage migration from this bucket to the spare
                self.blockage_migration_table
                    .table
                    .insert(*bucketnum, spare);
                // Change any blockage migrations with this bucket
                // as the destination to the spare
                for (_, v) in self.blockage_migration_table.table.iter_mut() {
                    if *v == *bucketnum {
                        *v = spare;
                    }
                }
            }
        }
        self.bridge_table.reachable.remove(bridge);

        res
    }

    // Since buckets are moved around in the bridge_table, finding a lookup key that
    // does not overwrite existing bridges could become an issue.We keep a list
    // of recycleable lookup keys from buckets that have been removed and prioritize
    // this list before increasing the counter
    fn find_next_available_key(&mut self, bdb: &mut BridgeDb) -> Result<u32, NoAvailableIDError> {
        self.clean_up_expired_buckets(bdb);
        if self.bridge_table.recycleable_keys.is_empty() {
            let mut test_index = 1;
            let mut test_counter = self.bridge_table.counter.wrapping_add(test_index);
            let mut i = 0;
            while self.bridge_table.buckets.contains_key(&test_counter) && i < 5000 {
                test_index += 1;
                test_counter = self.bridge_table.counter.wrapping_add(test_index);
                i += 1;
                if i == 5000 {
                    return Err(NoAvailableIDError::ExhaustedIndexer);
                }
            }
            self.bridge_table.counter = self.bridge_table.counter.wrapping_add(test_index);
            Ok(self.bridge_table.counter)
        } else {
            Ok(self.bridge_table.recycleable_keys.pop().unwrap())
        }
    }

    // This function looks for and removes buckets so their indexes can be reused
    // This should include buckets that have been blocked for a sufficiently long period
    // that we no longer want to allow migration to, or else, open-entry buckets that
    // have been unblocked long enough to become trusted and who's users' credentials
    // would have expired (after EXPIRY_DATE)
    pub fn clean_up_expired_buckets(&mut self, bdb: &mut BridgeDb) {
        // First check if there are any blocked indexes that are old enough to be replaced
        self.clean_up_blocked();
        // Next do the same for open_invitations buckets
        self.clean_up_open_entry(bdb);
    }

    /// Cleans up exipred blocked buckets
    fn clean_up_blocked(&mut self) {
        // If there are expired blockages, separate them from the fresh blockages
        #[allow(clippy::type_complexity)]
        let (expired, fresh): (Vec<(u32, u32)>, Vec<(u32, u32)>) = self
            .bridge_table
            .blocked_keys
            .iter()
            .partition(|&x| x.1 + EXPIRY_DATE < self.today());
        for item in expired {
            let key = item.0;
            // check each single bridge line and ensure none are still marked as reachable.
            // if any are still reachable, remove from reachable bridges.
            // When syncing resources, we will likely have to reallocate this bridge but if it hasn't already been
            // blocked, this might be fine?
            let bridgelines = self.bridge_table.buckets.get(&key).unwrap();
            for bridgeline in bridgelines {
                // If the bridge hasn't been set to default, assume it's still reachable
                if bridgeline.port > 0 {
                    // Move to unallocated bridges
                    self.bridge_table.unallocated_bridges.push(*bridgeline);
                    // Make sure bridge is removed from reachable bridges
                    self.bridge_table.reachable.remove(bridgeline);
                }
            }
            // Then remove the bucket and keys at the specified index
            self.bridge_table.buckets.remove(&key);
            self.bridge_table.keys.remove(&key);
            //and add them to the recyclable keys
            self.bridge_table.recycleable_keys.push(key);
            // Remove the expired blocked bucket from the blockage migration table,
            // assuming that anyone that has still not attempted to migrate from their
            // blocked bridge after the EXPIRY_DATE probably doesn't still need to migrate.
            self.blockage_migration_table.table.retain(|&k, _| k != key);
        }
        // Finally, update the blocked_keys vector to only include the fresh keys
        self.bridge_table.blocked_keys = fresh
    }

    /// Cleans up expired open invitation buckets
    fn clean_up_open_entry(&mut self, bdb: &mut BridgeDb) {
        // Separate exipred from fresh open invitation indexes
        #[allow(clippy::type_complexity)]
        let (expired, fresh): (Vec<(u32, u32)>, Vec<(u32, u32)>) = self
            .bridge_table
            .open_inv_keys
            .iter()
            .partition(|&x| x.1 + EXPIRY_DATE < self.today());
        for item in expired {
            let key = item.0;
            // We should check that the items were actually distributed before they are removed
            if !bdb.distributed_buckets.contains(&key) {
                // TODO: Add prometheus metric for this?
                println!("This bucket was not actually distributed!");
            }
            bdb.remove_blocked_or_expired_buckets(&key);
            // Remove any trust upgrade migrations from this
            // bucket
            self.trustup_migration_table.table.retain(|&k, _| k != key);
            self.bridge_table.buckets.remove(&key);
            self.bridge_table.keys.remove(&key);
            //and add them to the recyclable keys
            self.bridge_table.recycleable_keys.push(key);
        }
        // update the open_inv_keys vector to only include the fresh keys
        self.bridge_table.open_inv_keys = fresh
    }

    #[cfg(test)]
    /// For testing only: manually advance the day by 1 day
    pub fn advance_day(&mut self) {
        self.time_offset += time::Duration::days(1);
    }

    ///#[cfg(test)]
    /// For testing only: manually advance the day by the given number
    /// of days
    pub fn advance_days(&mut self, days: u16) {
        self.time_offset += time::Duration::days(days.into());
    }

    /// Get today's (real or simulated) date as u32
    pub fn today(&self) -> u32 {
        // We will not encounter negative Julian dates (~6700 years ago)
        // or ones larger than 32 bits
        (time::OffsetDateTime::now_utc().date() + self.time_offset)
            .to_julian_day()
            .try_into()
            .unwrap()
    }

    /// Get today's (real or simulated) date as a DateTime<Utc> value
    pub fn today_date(&self) -> DateTime<Utc> {
        Utc::now()
    }

    /// Get a reference to the encrypted bridge table.
    ///
    /// Be sure to call this function when you want the latest version
    /// of the table, since it will put fresh Bucket Reachability
    /// credentials in the buckets each day.
    pub fn enc_bridge_table(&mut self) -> &HashMap<u32, EncryptedBucket> {
        let today = self.today();
        if self.bridge_table.date_last_enc != today {
            self.bridge_table
                .encrypt_table(today, &self.reachability_priv);
        }
        &self.bridge_table.encbuckets
    }

    #[cfg(test)]
    /// Verify the two MACs on a Lox credential
    pub fn verify_lox(&self, cred: &cred::Lox) -> bool {
        if cred.P.is_identity() {
            return false;
        }

        let Q = (self.lox_priv.x[0]
            + cred.id * self.lox_priv.x[1]
            + cred.bucket * self.lox_priv.x[2]
            + cred.trust_level * self.lox_priv.x[3]
            + cred.level_since * self.lox_priv.x[4]
            + cred.invites_remaining * self.lox_priv.x[5]
            + cred.blockages * self.lox_priv.x[6])
            * cred.P;

        Q == cred.Q
    }

    #[cfg(test)]
    /// Verify the MAC on a Migration credential
    pub fn verify_migration(&self, cred: &cred::Migration) -> bool {
        if cred.P.is_identity() {
            return false;
        }

        let Q = (self.migration_priv.x[0]
            + cred.lox_id * self.migration_priv.x[1]
            + cred.from_bucket * self.migration_priv.x[2]
            + cred.to_bucket * self.migration_priv.x[3]
            + cred.migration_type * self.migration_priv.x[4])
            * cred.P;

        Q == cred.Q
    }

    #[cfg(test)]
    /// Verify the MAC on a Bucket Reachability credential
    pub fn verify_reachability(&self, cred: &cred::BucketReachability) -> bool {
        if cred.P.is_identity() {
            return false;
        }

        let Q = (self.reachability_priv.x[0]
            + cred.date * self.reachability_priv.x[1]
            + cred.bucket * self.reachability_priv.x[2])
            * cred.P;

        Q == cred.Q
    }

    #[cfg(test)]
    /// Verify the MAC on a Invitation credential
    pub fn verify_invitation(&self, cred: &cred::Invitation) -> bool {
        if cred.P.is_identity() {
            return false;
        }

        let Q = (self.invitation_priv.x[0]
            + cred.inv_id * self.invitation_priv.x[1]
            + cred.date * self.invitation_priv.x[2]
            + cred.bucket * self.invitation_priv.x[3]
            + cred.blockages * self.invitation_priv.x[4])
            * cred.P;

        Q == cred.Q
    }
}

/// Try to extract a u64 from a Scalar
pub fn scalar_u64(s: &Scalar) -> Option<u64> {
    // Check that the top 24 bytes of the Scalar are 0
    let sbytes = s.as_bytes();
    if sbytes[8..].ct_eq(&[0u8; 24]).unwrap_u8() == 0 {
        return None;
    }
    Some(u64::from_le_bytes(sbytes[..8].try_into().unwrap()))
}

/// Try to extract a u32 from a Scalar
pub fn scalar_u32(s: &Scalar) -> Option<u32> {
    // Check that the top 28 bytes of the Scalar are 0
    let sbytes = s.as_bytes();
    if sbytes[4..].ct_eq(&[0u8; 28]).unwrap_u8() == 0 {
        return None;
    }
    Some(u32::from_le_bytes(sbytes[..4].try_into().unwrap()))
}

/// Double a Scalar
pub fn scalar_dbl(s: &Scalar) -> Scalar {
    s + s
}

/// Double a RistrettoPoint
pub fn pt_dbl(P: &RistrettoPoint) -> RistrettoPoint {
    P + P
}

/// The protocol modules.
///
/// Each protocol lives in a submodule. Each submodule defines structs
/// for Request (the message from the client to the bridge authority),
/// State (the state held by the client while waiting for the reply),
/// and Response (the message from the bridge authority to the client).
/// Each submodule defines functions request, which produces a (Request,
/// State) pair, and handle_response, which consumes a State and a
/// Response. It also adds a handle_* function to the BridgeAuth struct
/// that consumes a Request and produces a Result<Response, ProofError>.
pub mod proto {
    pub mod blockage_migration;
    pub mod check_blockage;
    pub mod errors;
    pub mod issue_invite;
    pub mod level_up;
    pub mod migration;
    pub mod open_invite;
    pub mod redeem_invite;
    pub mod trust_promotion;
    pub mod update_cred;
    pub mod update_invite;
}

// Unit tests
#[cfg(test)]
mod tests;
