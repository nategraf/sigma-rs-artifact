/*! A module for the protocol for the user to check for the availability
of a migration credential they can use in order to move to a new bucket
if theirs has been blocked.

The user presents their current Lox credential:
- id: revealed
- bucket: blinded
- trust_level: revealed to be 3 or above
- level_since: blinded
- invites_remaining: blinded
- blockages: blinded

They are allowed to to this as long as they are level 3 or above.  If
they have too many blockages (but are level 3 or above), they will be
allowed to perform this migration, but will not be able to advance to
level 3 in their new bucket, so this will be their last allowed
migration without rejoining the system either with a new invitation or
an open invitation.

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
use super::level_up::MAX_LEVEL;
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
use serde_with::serde_as;
use sha2::Sha512;
use web_time::Instant;

/// The minimum trust level a Lox credential must have to be allowed to
/// perform this protocol.
pub const MIN_TRUST_LEVEL: u32 = 3;
const SESSION_ID: &[u8] = b"check_blockage";

muCMZProtocol! { check_blockage,
    L: Lox { id: R, bucket: H, trust_level: R, level_since: H, invites_remaining: H, blockages: H },
    M: MigrationKey { lox_id: R, from_bucket: H},
    M.lox_id = L.id,
    M.from_bucket = L.bucket,
}

pub fn request(
    rng: &mut (impl CryptoRng + RngCore),
    L: Lox,
    migkey_pubkeys: CMZPubkey<G>,
) -> Result<(check_blockage::Request, check_blockage::ClientState), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

    // Ensure that the credentials can be correctly shown; that is, the
    // ids match and the Lox credential bucket matches the Migration
    // credential from_bucket
    if L.id.is_none() {
        return Err(CredentialError::CredentialMismatch);
    }
    // Ensure the credential can be correctly shown: it must be the case
    // that trust_level >= MIN_TRUST_LEVEL
    if let Some(tl) = L.trust_level {
        let level: u32 = match scalar_u32(&tl) {
            Some(v) => v,
            None => {
                return Err(CredentialError::InvalidField(
                    String::from("trust_level"),
                    String::from("could not be converted to u32"),
                ))
            }
        };
        if !(MIN_TRUST_LEVEL..=MAX_LEVEL as u32).contains(&level) {
            return Err(CredentialError::InvalidField(
                String::from("trust_level"),
                format!("level {:?} not in range", level),
            ));
        }
    }
    let mut M = MigrationKey::using_pubkey(&migkey_pubkeys);
    M.lox_id = L.id;
    M.from_bucket = L.bucket;

    match check_blockage::prepare(rng, SESSION_ID, &L, M) {
        Ok(req_state) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "check-blockage client request time {:#?}",
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
    pub fn handle_check_blockage(
        &mut self,
        req: check_blockage::Request,
    ) -> Result<(check_blockage::Reply, EncMigrationTable), CredentialError> {
        let now = Instant::now();
        let mut rng = rand::thread_rng();
        let reqbytes = req.as_bytes();
        let recvreq = check_blockage::Request::try_from(&reqbytes[..]).unwrap();

        match check_blockage::handle(
            &mut rng,
            SESSION_ID,
            recvreq,
            |L: &mut Lox, M: &mut MigrationKey| {
                // Ensure the credential can be correctly shown: it must be the case
                // that trust_level >= MIN_TRUST_LEVEL
                if let Some(tl) = L.trust_level {
                    let level: u32 = match scalar_u32(&tl) {
                        Some(v) => v,
                        None => {
                            return Err(CMZError::RevealAttrMissing(
                                "trust_level",
                                "could not be converted to u32",
                            ))
                        }
                    };
                    if !(MIN_TRUST_LEVEL..=MAX_LEVEL as u32).contains(&level) {
                        return Err(CMZError::RevealAttrMissing(
                            "trust_level",
                            "level not in range",
                        ));
                    }
                };
                L.set_privkey(&self.lox_priv);
                M.set_privkey(&self.migrationkey_priv);
                Ok(())
            },
            |L: &Lox, _M: &MigrationKey| {
                if self.id_filter.check(&L.id.unwrap()) == SeenType::Seen {
                    return Err(CMZError::RevealAttrMissing("id", "Credential Expired"));
                }
                Ok(())
            },
        ) {
            Ok((response, (L_issuer, M_issuer))) => {
                let Pktable: WnafBase<G, WNAF_SIZE> = WnafBase::new(M_issuer.MAC.P);
                let enc_migration_table = EncMigrationTable {
                    mig_table: self.blockage_migration_table.encrypt_table(
                        L_issuer.id.unwrap(),
                        &self.bridge_table,
                        &Pktable,
                        &self.migration_priv,
                        &self.migrationkey_priv,
                    ),
                };
                let duration = now.elapsed();
                println!(
                    "check-blockage reply size: {:?}",
                    bincode::serialize(&(response.clone(), enc_migration_table.clone()))
                        .unwrap()
                        .len()
                );
                println!("check-blockage reply time: {:?}", duration);
                Ok((response, enc_migration_table))
            }
            Err(e) => Err(CredentialError::CMZError(e)),
        }
    }
}

pub fn handle_response(
    migration_pubkey: CMZPubkey<G>,
    state: check_blockage::ClientState,
    rep: check_blockage::Reply,
    enc_migration_table: EncMigrationTable,
) -> Result<Migration, CMZError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let replybytes = rep.as_bytes();
    let recvreply = check_blockage::Reply::try_from(&replybytes[..]).unwrap();
    let migkey = match state.finalize(recvreply) {
        Ok(cred) => cred,
        Err(_e) => return Err(CMZError::Unknown),
    };

    match migration_table::decrypt_cred(
        migkey,
        migration_table::MigrationType::Blockage,
        migration_pubkey,
        &enc_migration_table.mig_table,
    ) {
        Some(cred) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "check-blockage client handle reply time {:#?}",
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
    fn test_check_blockage() {
        println!("\n----CHECK-BLOCKAGE----\n");
        let mut th = TestHarness::new();
        let rng = &mut rand::thread_rng();
        let invite = th.bdb.invite().unwrap();
        let (_, mut lox_cred) = th.open_invite(rng, &invite);
        let (_, mig_cred) = th.trust_promotion(rng, lox_cred.clone());
        (_, lox_cred) = th.migration(rng, lox_cred.clone(), mig_cred.clone());
        let (_, lox_cred_1) = th.level_up(rng, lox_cred.clone());
        let (_, lox_cred_2) = th.level_up(rng, lox_cred_1.clone());
        let (_, lox_cred_3) = th.level_up(rng, lox_cred_2.clone());
        th.block_bridges(lox_cred_3.clone());
        let (perf_stat, mig_cred) = th.check_blockage(rng, lox_cred_3.clone());
        th.verify_migration(&mig_cred);
        th.print_test_results(perf_stat)
    }
}
