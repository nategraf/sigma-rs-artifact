use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use cmz::CMZPubkey;
use curve25519_dalek::ristretto::RistrettoPoint as G;
use lox_extensions::{
    bridge_table::{from_scalar, BridgeLine, BridgeTable, EncryptedBucket, MAX_BRIDGES_PER_BUCKET},
    lox_creds::{BucketReachability, Invitation, Lox},
    migration_table::EncMigrationTable,
    proto::*,
    OPENINV_LENGTH,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::array::TryFromSliceError;
use std::collections::HashMap;

const LOX_INVITE_TOKEN: &str = "loxinvite_";

#[derive(Serialize, Deserialize)]
pub struct Invite {
    #[serde(with = "base64serde")]
    pub invite: [u8; OPENINV_LENGTH],
}

mod base64serde {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
    use lox_extensions::OPENINV_LENGTH;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    use crate::LOX_INVITE_TOKEN;

    pub fn serialize<S: Serializer>(v: &[u8; OPENINV_LENGTH], s: S) -> Result<S::Ok, S::Error> {
        let mut base64 = STANDARD_NO_PAD.encode(v);
        base64.insert_str(0, LOX_INVITE_TOKEN);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; OPENINV_LENGTH], D::Error> {
        let mut base64 = String::deserialize(d)?;
        let encoded_str = base64.split_off(LOX_INVITE_TOKEN.len());
        if base64 != LOX_INVITE_TOKEN {
            return Err(serde::de::Error::custom("Token identifier does not match"));
        }
        match STANDARD_NO_PAD.decode(encoded_str) {
            Ok(output) => {
                let out: Result<[u8; OPENINV_LENGTH], D::Error> = match output.try_into() {
                    Ok(out) => Ok(out),
                    Err(e) => Err(serde::de::Error::custom(String::from_utf8(e).unwrap())),
                };
                out
            }
            Err(e) => Err(serde::de::Error::custom(e)),
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct OpenReqState {
    pub open_inv_req: OpenInvReq,
    pub state: open_invite::open_invitation::ClientState,
}

#[derive(Deserialize, Serialize)]
pub struct OpenInvReq {
    pub request: open_invite::open_invitation::Request,
    pub invite: Invite,
}

#[derive(Deserialize, Serialize)]
pub struct OpenResponse {
    pub reply: open_invite::open_invitation::Reply,
    pub bridgeline: BridgeLine,
}

#[derive(Deserialize, Serialize)]
pub struct TrustReqState {
    pub request: trust_promotion::trust_promotion::Request,
    pub state: trust_promotion::trust_promotion::ClientState,
}

#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct TrustResponse {
    pub reply: trust_promotion::trust_promotion::Reply,
    pub enc_mig_table: EncMigrationTable,
}

#[derive(Deserialize, Serialize)]
pub struct MigReqState {
    pub request: migration::migration::Request,
    pub state: migration::migration::ClientState,
}

#[derive(Deserialize, Serialize)]
pub struct LevelupReqState {
    pub request: level_up::level_up::Request,
    pub state: level_up::level_up::ClientState,
}

#[derive(Deserialize, Serialize)]
pub struct IssueInviteReqState {
    pub request: issue_invite::issue_invite::Request,
    pub state: issue_invite::issue_invite::ClientState,
}

#[derive(Deserialize, Serialize)]
pub struct RedeemReqState {
    pub request: redeem_invite::redeem_invite::Request,
    pub state: redeem_invite::redeem_invite::ClientState,
}

#[derive(Deserialize, Serialize)]
pub struct CheckBlockageReqState {
    pub request: check_blockage::check_blockage::Request,
    pub state: check_blockage::check_blockage::ClientState,
}

#[serde_as]
#[derive(Deserialize, Serialize)]
pub struct CheckBlockageResponse {
    pub reply: check_blockage::check_blockage::Reply,
    pub enc_mig_table: EncMigrationTable,
}

#[derive(Deserialize, Serialize)]
pub struct BlockageMigReqState {
    pub request: blockage_migration::blockage_migration::Request,
    pub state: blockage_migration::blockage_migration::ClientState,
}

#[derive(Deserialize, Serialize)]
pub struct UpdateCredReqState {
    pub request: update_cred::update_cred::Request,
    pub state: update_cred::update_cred::ClientState,
}

#[derive(Deserialize, Serialize)]
pub struct UpdateCredReq {
    pub old_key: CMZPubkey<G>,
    pub request: update_cred::update_cred::Request,
}

#[derive(Deserialize, Serialize)]
pub struct UpdateCredOption {
    pub updated: bool,
    pub req: String,
}

#[derive(Deserialize, Serialize)]
pub struct UpdateInviteReqState {
    pub request: update_invite::update_invite::Request,
    pub state: update_invite::update_invite::ClientState,
}

#[derive(Deserialize, Serialize)]
pub struct UpdateInviteReq {
    pub old_key: CMZPubkey<G>,
    pub request: update_invite::update_invite::Request,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PubKeys {
    pub lox_pub: CMZPubkey<G>,
    pub migration_pub: CMZPubkey<G>,
    pub migrationkey_pub: CMZPubkey<G>,
    pub reachability_pub: CMZPubkey<G>,
    pub invitation_pub: CMZPubkey<G>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoxSystemInfo {
    pub max_level: usize,
    pub untrusted_interval: u32,
    pub max_blockages: [u32; level_up::MAX_LEVEL + 1],
    pub level_interval: [u32; level_up::MAX_LEVEL + 1],
    pub level_invitations: [u32; level_up::MAX_LEVEL + 1],
    pub min_blockage_migration_trust_level: u32,
}

pub const LOX_SYSTEM_INFO: LoxSystemInfo = LoxSystemInfo {
    max_level: level_up::MAX_LEVEL,
    untrusted_interval: trust_promotion::UNTRUSTED_INTERVAL,
    max_blockages: level_up::MAX_BLOCKAGES,
    level_interval: level_up::LEVEL_INTERVAL,
    level_invitations: level_up::LEVEL_INVITATIONS,
    min_blockage_migration_trust_level: check_blockage::MIN_TRUST_LEVEL,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct LoxNextUnlock {
    pub trust_level_unlock_date: DateTime<Utc>,
    pub invitation_unlock_date: DateTime<Utc>,
    pub num_invitations_unlocked: u32,
    pub blockage_migration_unlock_date: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct EncBridgeTable {
    pub etable: HashMap<u32, EncryptedBucket>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoxCredential {
    pub lox_credential: Lox,
    pub bridgelines: Option<Vec<BridgeLine>>,
    pub invitation: Option<Invitation>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IssuedInvitation {
    pub invitation: Invitation,
}

// This should also check the pubkey
pub fn validate(invite: &[u8]) -> Result<[u8; OPENINV_LENGTH], TryFromSliceError> {
    invite.try_into()
}

pub fn generate_reachability_cred(
    lox_cred: &Lox,
    encrypted_table: String,
    reachability_pubkey: CMZPubkey<G>,
) -> BucketReachability {
    let (id, key) = from_scalar(lox_cred.bucket.unwrap()).unwrap();
    let enc_buckets: EncBridgeTable = serde_json::from_str(&encrypted_table).unwrap();
    let bucket = BridgeTable::decrypt_bucket(
        id,
        &key,
        enc_buckets.etable.get(&id).unwrap(),
        &reachability_pubkey,
    )
    .unwrap();
    bucket.1.unwrap()
}

pub fn get_credential_bridgelines(
    lox_cred: &Lox,
    encrypted_table: String,
    reachability_pubkey: CMZPubkey<G>,
) -> [BridgeLine; MAX_BRIDGES_PER_BUCKET] {
    let (id, key) = from_scalar(lox_cred.bucket.unwrap()).unwrap();
    let enc_buckets: EncBridgeTable = serde_json::from_str(&encrypted_table).unwrap();
    let bucket = BridgeTable::decrypt_bucket(
        id,
        &key,
        enc_buckets.etable.get(&id).unwrap(),
        &reachability_pubkey,
    )
    .unwrap();
    bucket.0
}

//pub const MAX_LEVEL: usize = 4;
//pub const LEVEL_INTERVAL: [u32; MAX_LEVEL + 1] = [0, 14, 28, 56, 84];
pub fn calc_test_days(trust_level: i64) -> i64 {
    let mut total = 31;
    // for level in 0..trust_level {
    //      let level_interval: u32 = LEVEL_INTERVAL[trust_level as usize];
    //     total += level_interval;
    total += trust_level * 85;
    //  }
    total
}

pub fn random() -> BridgeLine {
    let mut rng = rand::thread_rng();
    let mut res: BridgeLine = BridgeLine::default();
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
