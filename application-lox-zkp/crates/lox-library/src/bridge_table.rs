/*! The encrypted table of bridges.

The table consists of a number of buckets, each holding some number
(currently up to 3) of bridges.  Each bucket is individually encrypted
with a bucket key.  Users will have a credential containing a bucket
(number, key) combination, and so will be able to read one of the
buckets.  Users will either download the whole encrypted bucket list or
use PIR to download a piece of it, so that the bridge authority does not
learn which bucket the user has access to. */
use super::cred;
use super::IssuerPrivKey;
use super::CMZ_B_TABLE;
use aes_gcm::aead;
use aes_gcm::aead::{generic_array::GenericArray, Aead};
use aes_gcm::{Aes128Gcm, KeyInit};
#[cfg(feature = "bridgeauth")]
#[allow(unused_imports)]
use base64::{engine::general_purpose, Engine as _};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::scalar::Scalar;
#[allow(unused_imports)]
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use subtle::ConstantTimeEq;

/// Each bridge information line is serialized into this many bytes
pub const BRIDGE_BYTES: usize = 250;

/// The max number of bridges per bucket
pub const MAX_BRIDGES_PER_BUCKET: usize = 3;

/// The minimum number of bridges in a bucket that must be reachable for
/// the bucket to get a Bucket Reachability credential that will allow
/// users of that bucket to gain trust levels (once they are already at
/// level 1)
pub const MIN_BUCKET_REACHABILITY: usize = 2;

/// A bridge information line
#[serde_as]
#[derive(Serialize, Deserialize, Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub struct BridgeLine {
    /// IPv4 or IPv6 address
    pub addr: [u8; 16],
    /// port
    pub port: u16,
    /// fingerprint
    #[serde_as(as = "DisplayFromStr")]
    pub uid_fingerprint: u64,
    /// other protocol information, including pluggable transport,
    /// public key, etc.
    #[serde_as(as = "[_; BRIDGE_BYTES - 26]")]
    pub info: [u8; BRIDGE_BYTES - 26],
}

/// A bucket contains MAX_BRIDGES_PER_BUCKET bridges plus the
/// information needed to construct a Bucket Reachability credential,
/// which is a 4-byte date, and a (P,Q) MAC
type Bucket = (
    [BridgeLine; MAX_BRIDGES_PER_BUCKET],
    Option<cred::BucketReachability>,
);

/// The size of a plaintext bucket
pub const BUCKET_BYTES: usize = BRIDGE_BYTES * MAX_BRIDGES_PER_BUCKET + 4 + 32 + 32;

/// The size of an encrypted bucket
pub const ENC_BUCKET_BYTES: usize = BUCKET_BYTES + 12 + 16;

impl Default for BridgeLine {
    /// An "empty" BridgeLine is represented by all zeros
    fn default() -> Self {
        Self {
            addr: [0; 16],
            port: 0,
            uid_fingerprint: 0,
            info: [0; BRIDGE_BYTES - 26],
        }
    }
}

impl BridgeLine {
    /// Encode a BridgeLine to a byte array
    pub fn encode(&self) -> [u8; BRIDGE_BYTES] {
        let mut res: [u8; BRIDGE_BYTES] = [0; BRIDGE_BYTES];
        res[0..16].copy_from_slice(&self.addr);
        res[16..18].copy_from_slice(&self.port.to_be_bytes());
        res[18..26].copy_from_slice(&self.uid_fingerprint.to_be_bytes());
        res[26..].copy_from_slice(&self.info);
        res
    }
    /// Decode a BridgeLine from a byte array
    pub fn decode(data: &[u8; BRIDGE_BYTES]) -> Self {
        let mut res: Self = Default::default();
        res.addr.copy_from_slice(&data[0..16]);
        res.port = u16::from_be_bytes(data[16..18].try_into().unwrap());
        res.uid_fingerprint = u64::from_be_bytes(data[18..26].try_into().unwrap());
        res.info.copy_from_slice(&data[26..]);
        res
    }
    /// Encode a bucket to a byte array, including a Bucket Reachability
    /// credential if appropriate
    pub fn bucket_encode(
        bucket: &[BridgeLine; MAX_BRIDGES_PER_BUCKET],
        reachable: &HashMap<BridgeLine, Vec<(u32, usize)>>,
        today: u32,
        bucket_attr: &Scalar,
        reachability_priv: &IssuerPrivKey,
    ) -> [u8; BUCKET_BYTES] {
        let mut res: [u8; BUCKET_BYTES] = [0; BUCKET_BYTES];
        let mut pos: usize = 0;
        let mut num_reachable: usize = 0;
        for bridge in bucket {
            res[pos..pos + BRIDGE_BYTES].copy_from_slice(&bridge.encode());
            if reachable.contains_key(bridge) {
                num_reachable += 1;
            }
            pos += BRIDGE_BYTES;
        }
        if num_reachable >= MIN_BUCKET_REACHABILITY {
            // Construct a Bucket Reachability credential for this
            // bucket and today's date
            let today_attr: Scalar = today.into();
            let mut rng = rand::rngs::OsRng;
            let Btable: &RistrettoBasepointTable = &CMZ_B_TABLE;
            let b = Scalar::random(&mut rng);
            let P = &b * Btable;
            let Q = &(b
                * (reachability_priv.x[0]
                    + reachability_priv.x[1] * today_attr
                    + reachability_priv.x[2] * bucket_attr))
                * Btable;
            res[pos..pos + 4].copy_from_slice(&today.to_le_bytes());
            res[pos + 4..pos + 36].copy_from_slice(P.compress().as_bytes());
            res[pos + 36..].copy_from_slice(Q.compress().as_bytes());
        }
        res
    }
    /// Decode a bucket from a byte array, yielding the array of
    /// BridgeLine entries and an optional Bucket Reachability
    /// credential
    fn bucket_decode(data: &[u8; BUCKET_BYTES], bucket_attr: &Scalar) -> Bucket {
        let mut pos: usize = 0;
        let mut bridges: [BridgeLine; MAX_BRIDGES_PER_BUCKET] = Default::default();
        for bridge in bridges.iter_mut().take(MAX_BRIDGES_PER_BUCKET) {
            *bridge = BridgeLine::decode(data[pos..pos + BRIDGE_BYTES].try_into().unwrap());
            pos += BRIDGE_BYTES;
        }
        // See if there's a nonzero date in the Bucket Reachability
        // Credential
        let date = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let (optP, optQ) = if date > 0 {
            (
                CompressedRistretto::from_slice(&data[pos + 4..pos + 36])
                    .expect("Unable to extract P from bucket")
                    .decompress(),
                CompressedRistretto::from_slice(&data[pos + 36..])
                    .expect("Unable to extract Q from bucket")
                    .decompress(),
            )
        } else {
            (None, None)
        };
        if let (Some(P), Some(Q)) = (optP, optQ) {
            let date_attr: Scalar = date.into();
            (
                bridges,
                Some(cred::BucketReachability {
                    P,
                    Q,
                    date: date_attr,
                    bucket: *bucket_attr,
                }),
            )
        } else {
            (bridges, None)
        }
    }

    /// Create a random BridgeLine for testing
    #[cfg(test)]
    pub fn random() -> Self {
        let mut rng = rand::rngs::OsRng;
        let mut res: Self = Default::default();
        // Pick a random 4-byte address
        let mut addr: [u8; 4] = [0; 4];
        rng.fill_bytes(&mut addr);
        // If the leading byte is 224 or more, that's not a valid IPv4
        // address.  Choose an IPv6 address instead (but don't worry too
        // much about it being well formed).
        if addr[0] >= 224 {
            rng.fill_bytes(&mut res.addr);
        } else {
            // Store an IPv4 address as a v4-mapped IPv6 address
            res.addr[10] = 255;
            res.addr[11] = 255;
            res.addr[12..16].copy_from_slice(&addr);
        };
        let ports: [u16; 4] = [443, 4433, 8080, 43079];
        let portidx = (rng.next_u32() % 4) as usize;
        res.port = ports[portidx];
        res.uid_fingerprint = rng.next_u64();
        let mut cert: [u8; 52] = [0; 52];
        rng.fill_bytes(&mut cert);
        let infostr: String = format!(
            "obfs4 cert={}, iat-mode=0",
            general_purpose::STANDARD_NO_PAD.encode(cert)
        );
        res.info[..infostr.len()].copy_from_slice(infostr.as_bytes());
        res
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct EncryptedBucket([u8; ENC_BUCKET_BYTES]);

impl From<EncryptedBucket> for Vec<u8> {
    fn from(e: EncryptedBucket) -> Vec<u8> {
        e.0.into()
    }
}

#[derive(thiserror::Error, Debug)]
#[error("wrong slice length")]
pub struct WrongSliceLengthError;

impl TryFrom<Vec<u8>> for EncryptedBucket {
    type Error = WrongSliceLengthError;
    fn try_from(v: Vec<u8>) -> Result<EncryptedBucket, Self::Error> {
        Ok(EncryptedBucket(
            *Box::<[u8; ENC_BUCKET_BYTES]>::try_from(v).map_err(|_| WrongSliceLengthError)?,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct K {
    encbucket: EncryptedBucket,
}

/// A BridgeTable is the internal structure holding the buckets
/// containing the bridges, the keys used to encrypt the buckets, and
/// the encrypted buckets. The encrypted buckets will be exposed to the
/// users of the system, and each user credential will contain the
/// decryption key for one bucket.
#[serde_as]
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BridgeTable {
    /// All structures in the bridgetable are indexed by counter
    pub counter: u32,
    /// The keys of all buckets, indexed by counter, that are still part of the bridge table.
    pub keys: HashMap<u32, [u8; 16]>,
    /// All buckets, indexed by counter corresponding to the key above, that are
    /// part of the bridge table.
    pub buckets: HashMap<u32, [BridgeLine; MAX_BRIDGES_PER_BUCKET]>,
    pub encbuckets: HashMap<u32, EncryptedBucket>,
    /// Individual bridges that are reachable.
    #[serde_as(as = "HashMap<serde_with::json::JsonString, _>")]
    pub reachable: HashMap<BridgeLine, Vec<(u32, usize)>>,
    /// Bucket ids of "hot spare" buckets. These buckets are not handed
    /// to users, nor do they have any Migration credentials pointing to
    /// them. When a new Migration credential is needed, a bucket is
    /// removed from this set and used for that purpose.
    pub spares: HashSet<u32>,
    /// In some instances a single bridge may need to be added to a bucket as a replacement
    /// or otherwise. In that case, a spare bucket will be removed from the set of spares, one
    /// bridge will be used as the replacement and the left over bridges will be appended to
    /// unallocated_bridges.
    pub unallocated_bridges: Vec<BridgeLine>,
    // To prevent issues with the counter for the hashmap keys, keep a list of keys that
    // no longer match any buckets that can be used before increasing the counter.
    pub recycleable_keys: Vec<u32>,
    // A list of keys that have been blocked (bucket_id: u32), as well as the
    // time (julian_date: u32) of their blocking so that they can be repurposed with new
    // buckets after the EXPIRY_DATE.
    pub blocked_keys: Vec<(u32, u32)>,
    // Similarly, a list of open entry buckets (bucket_id: u32) and the time they were
    // created (julian_date: u32) so they will be listed as expired after the EXPIRY_DATE.
    // TODO: add open entry buckets to the open_inv_keys only once they have been distributed
    pub open_inv_keys: Vec<(u32, u32)>,
    /// The date the buckets were last encrypted to make the encbucket.
    /// The encbucket must be rebuilt at least each day so that the Bucket
    /// Reachability credentials in the buckets can be refreshed.
    pub date_last_enc: u32,
}

// Invariant: the lengths of the keys and bucket hashmap are the same.
// The encbuckets hashmap only gets updated when encrypt_table is called.

impl BridgeTable {
    /// Get the number of buckets in the bridge table
    #[cfg(feature = "bridgeauth")]
    pub fn num_buckets(&self) -> usize {
        self.buckets.len()
    }

    /// Insert a new bucket into the bridge table, returning its index
    #[cfg(feature = "bridgeauth")]
    pub fn new_bucket(&mut self, index: u32, bucket: &[BridgeLine; MAX_BRIDGES_PER_BUCKET]) {
        // Pick a random key to encrypt this bucket
        let mut rng = rand::rngs::OsRng;
        let mut key: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut key);
        self.keys.insert(index, key);
        self.buckets.insert(index, *bucket);
        // TODO: maybe we don't need this if the hashtable can keep track of available bridges
        // Mark the new bridges as available
        for (i, b) in bucket.iter().enumerate() {
            if b.port > 0 {
                if let Some(v) = self.reachable.get_mut(b) {
                    v.push((index, i));
                } else {
                    let v = vec![(index, i)];
                    self.reachable.insert(*b, v);
                }
            }
        }
    }

    /// Create the vector of encrypted buckets from the keys and buckets
    /// in the BridgeTable. All of the entries will be (randomly)
    /// re-encrypted, so it will be hidden whether any individual bucket
    /// has changed (except for entirely new buckets, of course).
    /// Bucket Reachability credentials are added to the buckets when
    /// enough (at least MIN_BUCKET_REACHABILITY) bridges in the bucket
    /// are reachable.
    #[cfg(feature = "bridgeauth")]
    pub fn encrypt_table(&mut self, today: u32, reachability_priv: &IssuerPrivKey) {
        let mut rng = rand::rngs::OsRng;
        self.encbuckets.clear();
        for (uid, key) in self.keys.iter() {
            let bucket = self.buckets.get(uid).unwrap();
            let mut encbucket: [u8; ENC_BUCKET_BYTES] = [0; ENC_BUCKET_BYTES];
            let plainbucket: [u8; BUCKET_BYTES] = BridgeLine::bucket_encode(
                bucket,
                &self.reachable,
                today,
                &to_scalar(*uid, key),
                reachability_priv,
            );
            // Set the AES key
            let aeskey = GenericArray::from_slice(key);
            // Pick a random nonce
            let mut noncebytes: [u8; 12] = [0; 12];
            rng.fill_bytes(&mut noncebytes);
            let nonce = GenericArray::from_slice(&noncebytes);
            // Encrypt
            let cipher = Aes128Gcm::new(aeskey);
            let ciphertext: Vec<u8> = cipher.encrypt(nonce, plainbucket.as_ref()).unwrap();
            encbucket[0..12].copy_from_slice(&noncebytes);
            encbucket[12..].copy_from_slice(ciphertext.as_slice());
            let k = EncryptedBucket(encbucket);
            self.encbuckets.insert(*uid, k);
        }
        self.date_last_enc = today;
    }

    /// Decrypt an individual encrypted bucket, given its id, key, and
    /// the encrypted bucket itself
    pub fn decrypt_bucket(
        id: u32,
        key: &[u8; 16],
        encbucket: &EncryptedBucket,
    ) -> Result<Bucket, aead::Error> {
        // Set the nonce and the key
        let k = K {
            encbucket: *encbucket,
        };
        let nonce = GenericArray::from_slice(&k.encbucket.0[0..12]);
        let aeskey = GenericArray::from_slice(key);
        // Decrypt
        let cipher = Aes128Gcm::new(aeskey);
        let plaintext: Vec<u8> = cipher.decrypt(nonce, k.encbucket.0[12..].as_ref())?;
        // Convert the plaintext bytes to an array of BridgeLines
        Ok(BridgeLine::bucket_decode(
            plaintext.as_slice().try_into().unwrap(),
            &to_scalar(id, key),
        ))
    }

    /// Decrypt an individual encrypted bucket, given its id and key
    #[cfg(feature = "bridgeauth")]
    pub fn decrypt_bucket_id(&self, id: u32, key: &[u8; 16]) -> Result<Bucket, aead::Error> {
        let encbucket: &EncryptedBucket = match self.encbuckets.get(&id) {
            Some(encbucket) => encbucket,
            None => panic!("Provided ID not found"),
        };
        BridgeTable::decrypt_bucket(id, key, encbucket)
    }
}

// Unit tests that require access to the testing-only function
// BridgeLine::random()
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_table() -> Result<(), aead::Error> {
        // Create private keys for the Bucket Reachability credentials
        let reachability_priv = IssuerPrivKey::new(2);
        // Create an empty bridge table
        let mut btable: BridgeTable = Default::default();
        // Make 20 buckets with one random bridge each
        for _ in 0..20 {
            let bucket: [BridgeLine; 3] =
                [BridgeLine::random(), Default::default(), Default::default()];
            btable.counter += 1;
            btable.new_bucket(btable.counter, &bucket);
        }
        // And 20 more with three random bridges each
        for _ in 0..20 {
            let bucket: [BridgeLine; 3] = [
                BridgeLine::random(),
                BridgeLine::random(),
                BridgeLine::random(),
            ];
            btable.counter += 1;
            btable.new_bucket(btable.counter, &bucket);
        }
        let today: u32 = time::OffsetDateTime::now_utc()
            .date()
            .to_julian_day()
            .try_into()
            .unwrap();
        // Create the encrypted bridge table
        btable.encrypt_table(today, &reachability_priv);
        // Try to decrypt a 1-bridge bucket
        let key7 = btable.keys.get(&7u32).unwrap();
        let bucket7 = btable.decrypt_bucket_id(7, key7)?;
        println!("bucket 7 = {:?}", bucket7);
        // Try to decrypt a 3-bridge bucket
        let key24 = btable.keys.get(&24u32).unwrap();
        let bucket24 = btable.decrypt_bucket_id(24, key24)?;
        println!("bucket 24 = {:?}", bucket24);
        // Try to decrypt a bucket with the wrong key
        let key12 = btable.keys.get(&12u32).unwrap();
        let res = btable.decrypt_bucket_id(15, key12).unwrap_err();
        println!("bucket key mismatch = {:?}", res);
        Ok(())
    }
}

/// Convert an id and key to a Scalar attribute
pub fn to_scalar(id: u32, key: &[u8; 16]) -> Scalar {
    let mut b: [u8; 32] = [0; 32];
    // b is a little-endian representation of the Scalar; put the key in
    // the low 16 bytes, and the id in the next 4 bytes.
    b[0..16].copy_from_slice(key);
    b[16..20].copy_from_slice(&id.to_le_bytes());
    // This cannot fail, since we're only using the low 20 bytes of b
    Scalar::from_canonical_bytes(b).unwrap()
}

/// Convert a Scalar attribute to an id and key if possible
pub fn from_scalar(s: Scalar) -> Result<(u32, [u8; 16]), aead::Error> {
    // Check that the top 12 bytes of the Scalar are 0
    let sbytes = s.as_bytes();
    if sbytes[20..].ct_eq(&[0u8; 12]).unwrap_u8() == 0 {
        return Err(aead::Error);
    }
    let id = u32::from_le_bytes(sbytes[16..20].try_into().unwrap());
    let mut key: [u8; 16] = [0; 16];
    key.copy_from_slice(&sbytes[..16]);
    Ok((id, key))
}
