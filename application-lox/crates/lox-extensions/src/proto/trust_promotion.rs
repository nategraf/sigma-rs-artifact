/*! A module for the protocol for the user to get promoted from
untrusted (trust level 0) to trusted (trust level 1).

They are allowed to do this as long as UNTRUSTED_INTERVAL days have
passed since they obtained their level 0 Lox credential, and their
bridge (level 0 users get put in a one-bridge bucket) has not been
blocked.  (Blocked bridges in one-bridge buckets will have their entries
removed from the bridge authority's trust_promotion table.)

The user presents their current Lox credential:
- id: revealed
- bucket: blinded
- trust_level: revealed to be 0
- level_since: blinded, but proved in ZK that it's at least
  UNTRUSTED_INTERVAL days ago
- invites_remaining: revealed to be 0
- blockages: revealed to be 0

They will receive in return the encrypted MAC (Pk, EncQk) for their
implicit Migration Key credential with attributes id and bucket,
along with a HashMap of encrypted Migration credentials.  For each
(from_i, to_i) in the BA's migration list, there will be an entry in
the HashMap with key H1(id, from_attr_i, Qk_i) and value
Enc_{H2(id, from_attr_i, Qk_i)}(to_attr_i, P_i, Q_i).  Here H1 and H2
are the first 16 bytes and the second 16 bytes respectively of the
SHA256 hash of the input, P_i and Q_i are a MAC on the Migration
credential with attributes id, from_attr_i, and to_attr_i. Qk_i is the
value EncQk would decrypt to if bucket were equal to from_attr_i. */

#[cfg(feature = "bridgeauth")]
use super::super::dup_filter::SeenType;
#[cfg(feature = "bridgeauth")]
use super::super::BridgeAuth;
use super::super::{scalar_u32, G};
use super::errors::CredentialError;
#[cfg(feature = "dump")]
use crate::dumper::dump;
use crate::lox_creds::{Lox, Migration, MigrationKey};
#[cfg(feature = "bridgeauth")]
use crate::migration_table::WNAF_SIZE;
use crate::migration_table::{self, EncMigrationTable};
use cmz::*;
use group::Group;
#[cfg(feature = "bridgeauth")]
use group::WnafBase;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use web_time::Instant;

const SESSION_ID: &[u8] = b"trust_promo";

/// The minimum number of days a user has to be at trust level 0
/// (untrusted) with their (single) bridge unblocked before they can
/// move to level 1.
///
/// The implementation also puts an upper bound of UNTRUSTED_INTERVAL +
/// 511 days, which is not unreasonable; we want users to be engaging
/// with the system in order to move up trust levels.
pub const UNTRUSTED_INTERVAL: u32 = 30;

muCMZProtocol! { trust_promotion<credential_expiry, eligibility_max_age>,
    L: Lox { id: R, bucket: H, trust_level: R, level_since: H, invites_remaining: R, blockages: R },
    M: MigrationKey { lox_id: R, from_bucket: H} ,
    M.lox_id = L.id,
    M.from_bucket = L.bucket,
    (credential_expiry..=eligibility_max_age).contains(L.level_since),
}

pub fn request(
    rng: &mut (impl CryptoRng + RngCore),
    L: Lox,
    migkey_pubkeys: CMZPubkey<G>,
    today: u32,
) -> Result<(trust_promotion::Request, trust_promotion::ClientState), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

    // Ensure that the credentials can be correctly shown; that is, the
    // ids match and the Lox credential bucket matches the Migration
    // credential from_bucket
    if L.id.is_none() {
        return Err(CredentialError::CredentialMismatch);
    }

    // This protocol only allows migrating from trust level 0 to trust
    // level 1
    if let Some(ls) = L.level_since {
        let level_since = match scalar_u32(&ls) {
            Some(v) => v,
            None => {
                return Err(CredentialError::InvalidField(
                    String::from("level_since"),
                    String::from("could not be converted to u32"),
                ))
            }
        };
        if level_since + UNTRUSTED_INTERVAL > today {
            return Err(CredentialError::TimeThresholdNotMet(
                level_since + UNTRUSTED_INTERVAL - today,
            ));
        }
        let diffdays = today - (level_since + UNTRUSTED_INTERVAL);
        if diffdays > 511 {
            return Err(CredentialError::CredentialExpired);
        }
    }
    let eligibility_max_age = today - UNTRUSTED_INTERVAL;

    let params = trust_promotion::Params {
        credential_expiry: (eligibility_max_age - 511).into(),
        eligibility_max_age: eligibility_max_age.into(),
    };
    let mut M = MigrationKey::using_pubkey(&migkey_pubkeys);
    M.lox_id = L.id;
    M.from_bucket = L.bucket;
    match trust_promotion::prepare(rng, SESSION_ID, &L, M, &params) {
        Ok(req_state) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "trust-promo client request size: {:#?} trust-promo client request time {:#?}",
                    bincode::serialize(&req_state.0).unwrap().len(),
                    duration
                ));
            };
            Ok(req_state)
        }
        Err(e) => Err(CredentialError::CMZError(e)),
    }
}

#[allow(clippy::type_complexity)]
#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    pub fn handle_trust_promotion(
        &mut self,
        req: trust_promotion::Request,
    ) -> Result<(trust_promotion::Reply, EncMigrationTable), CredentialError> {
        let now = Instant::now();
        let mut rng = rand::thread_rng();
        let reqbytes = req.as_bytes();
        let recvreq = trust_promotion::Request::try_from(&reqbytes[..]).unwrap();
        let today = self.today();
        match trust_promotion::handle(
            &mut rng,
            SESSION_ID,
            recvreq,
            |L: &mut Lox, M: &mut MigrationKey| {
                L.set_privkey(&self.lox_priv);
                M.set_privkey(&self.migrationkey_priv);
                let eligibility_max_age = today - UNTRUSTED_INTERVAL;
                Ok(trust_promotion::Params {
                    credential_expiry: (eligibility_max_age - 511).into(),
                    eligibility_max_age: eligibility_max_age.into(),
                })
            },
            |L: &Lox, _M: &MigrationKey| {
                if self.id_filter.check(&L.id.unwrap()) == SeenType::Seen
                    || self.trust_promotion_filter.filter(&L.id.unwrap()) == SeenType::Seen
                {
                    return Err(CMZError::RevealAttrMissing("id", "Credential Expired"));
                }
                Ok(())
            },
        ) {
            Ok((response, (L_issuer, M_issuer))) => {
                let Pktable: WnafBase<G, WNAF_SIZE> = WnafBase::new(M_issuer.MAC.P);
                let enc_migration_table = EncMigrationTable {
                    mig_table: self.trustup_migration_table.encrypt_table(
                        L_issuer.id.unwrap(),
                        &self.bridge_table,
                        &Pktable,
                        &self.migration_priv,
                        &self.migrationkey_priv,
                    ),
                };
                println!(
                    "trust-promo reply size: {:?}",
                    bincode::serialize(&(response.clone(), enc_migration_table.clone()))
                        .unwrap()
                        .len()
                );
                let duration = now.elapsed();
                println!("trust-promo reply time: {:?}", duration);
                Ok((response, enc_migration_table))
            }
            Err(e) => Err(CredentialError::CMZError(e)),
        }
    }
}

pub fn handle_response(
    migration_pubkey: CMZPubkey<G>,
    state: trust_promotion::ClientState,
    rep: trust_promotion::Reply,
    enc_migration_table: EncMigrationTable,
) -> Result<Migration, CMZError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let replybytes = rep.as_bytes();
    let recvreply = trust_promotion::Reply::try_from(&replybytes[..]).unwrap();
    let migkey = match state.finalize(recvreply) {
        Ok(cred) => cred,
        Err(_e) => return Err(CMZError::Unknown),
    };
    match migration_table::decrypt_cred(
        migkey,
        migration_table::MigrationType::TrustUpgrade,
        migration_pubkey,
        &enc_migration_table.mig_table,
    ) {
        Some(cred) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "trust-promo client handle reply time {:#?}",
                    duration
                ));
            };
            Ok(cred)
        }
        None => Err(CMZError::Unknown),
    }
}

#[cfg(all(test, feature = "bridgeauth"))]
mod tests {
    use crate::mock_auth::TestHarness;

    #[test]
    fn test_trust_promotion() {
        println!("\n----TRUST-PROMOTION-1: 30 days---\n");
        let mut th = TestHarness::new();
        let rng = &mut rand::thread_rng();
        let invite = th.bdb.invite().unwrap();
        let (_, lox_cred) = th.open_invite(rng, &invite);
        let (perf_stat, mig_cred) = th.trust_promotion(rng, lox_cred.clone());
        th.verify_migration(&mig_cred);
        th.print_test_results(perf_stat);
    }
}
