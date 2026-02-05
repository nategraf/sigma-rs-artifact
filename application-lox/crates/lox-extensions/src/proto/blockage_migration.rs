/*! A module for the protocol for the user of trust level 3 or higher to
migrate from one bucket to another because their current bucket has been
blocked.  Their trust level will go down by 2.

The user presents their current Lox credential:

- id: revealed
- bucket: hidden
- trust_level: revealed to be 3 or higher
- level_since: hidden
- invites_remaining: hidden
- blockages: hidden

and a Migration credential:

- id: revealed as the same as the Lox credential id above
- from_bucket: hidden, but proved in ZK that it's the same as the
  bucket in the Lox credential above
- to_bucket: hidden

and a new Lox credential to be issued:

- id: jointly chosen by the user and BA
- bucket: hidden, but proved in ZK that it's the same as the to_bucket
  in the Migration credential above
- trust_level: revealed to be 2 less than the trust_level above
- level_since: set by the server to today
- invites_remaining: implicit to both the client and server as LEVEL_INVITATIONS for the new trust level
- blockages: hidden, but proved in ZK that it's one more than the
  blockages above

*/

#[cfg(feature = "bridgeauth")]
use super::super::dup_filter::SeenType;
#[cfg(feature = "bridgeauth")]
use super::super::BridgeAuth;
use super::super::{scalar_u32, Scalar, G};
use super::check_blockage::MIN_TRUST_LEVEL;
use super::errors::CredentialError;
use super::level_up::LEVEL_INVITATIONS;
#[cfg(feature = "bridgeauth")]
use super::level_up::MAX_LEVEL;
#[cfg(feature = "dump")]
use crate::dumper::dump;
pub use crate::lox_creds::{Lox, Migration};
#[cfg(feature = "bridgeauth")]
use crate::migration_table::MigrationType;
use cmz::*;
#[cfg(feature = "bridgeauth")]
use ff::PrimeField;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use web_time::Instant;

const SESSION_ID: &[u8] = b"blockage_migration";

muCMZProtocol! { blockage_migration,
    [ L: Lox { id: R, bucket: H, trust_level: R, level_since: H, invites_remaining: H, blockages: H },
    M: Migration { lox_id: R, from_bucket: H, to_bucket: H, migration_type: I } ],
    N: Lox {id: J, bucket: H, trust_level: I, level_since: S, invites_remaining: I, blockages: H },
    L.id = M.lox_id,
    L.bucket = M.from_bucket,
    N.bucket = M.to_bucket,
    N.blockages = L.blockages + 1,
}

pub fn request(
    rng: &mut (impl CryptoRng + RngCore),
    L: Lox,
    M: Migration,
) -> Result<(blockage_migration::Request, blockage_migration::ClientState), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

    // Ensure that the credenials can be correctly shown; that is, the
    // ids match and the Lox credential bucket matches the Migration
    // credential from_bucket
    if L.id.is_some_and(|i| i != M.lox_id.unwrap()) {
        return Err(CredentialError::CredentialMismatch);
    }

    if L.bucket.is_some_and(|b| b != M.from_bucket.unwrap()) {
        return Err(CredentialError::CredentialMismatch);
    }

    // The trust level must be at least MIN_TRUST_LEVEL
    let level: u32 = match scalar_u32(&L.trust_level.unwrap()) {
        Some(v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("trust_level"),
                String::from("could not be converted to u32"),
            ))
        }
    };
    if level < MIN_TRUST_LEVEL {
        return Err(CredentialError::InvalidField(
            String::from("trust_level"),
            format!("level {:?} not in range", level),
        ));
    }

    let mut N = Lox::using_pubkey(L.get_pubkey());
    N.bucket = M.to_bucket;
    N.trust_level = Some((level - 2).into());
    // The invites remaining is the appropriate number for the new
    // level (note that LEVEL_INVITATIONS[i] is the number of
    // invitations for moving from level i to level i+1)
    N.invites_remaining = Some(LEVEL_INVITATIONS[(level - 3) as usize].into());
    N.blockages = Some(L.blockages.unwrap() + Scalar::ONE);

    match blockage_migration::prepare(rng, SESSION_ID, &L, &M, N) {
        Ok(req_state) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "blockage-migration client request time {:#?}",
                    duration
                ));
            };
            Ok(req_state)
        }
        Err(e) => Err(CredentialError::CMZError(e)),
    }
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    pub fn handle_blockage_migration(
        &mut self,
        req: blockage_migration::Request,
    ) -> Result<blockage_migration::Reply, CredentialError> {
        let now = Instant::now();
        let mut rng = rand::thread_rng();
        let reqbytes = req.as_bytes();
        let recvreq = blockage_migration::Request::try_from(&reqbytes[..]).unwrap();

        let today = self.today();
        match blockage_migration::handle(
            &mut rng,
            SESSION_ID,
            recvreq,
            |L: &mut Lox, M: &mut Migration, N: &mut Lox| {
                let level: u32 = match scalar_u32(&L.trust_level.unwrap()) {
                    Some(v) if v >= MIN_TRUST_LEVEL && v as usize <= MAX_LEVEL => v,
                    _ => {
                        return Err(CMZError::RevealAttrMissing(
                            "level",
                            "Could not be converted to u32 or value not in range",
                        ));
                    }
                };
                if L.id.is_some_and(|b| b != M.lox_id.unwrap()) {
                    return Err(CMZError::IssProofFailed);
                }
                L.set_privkey(&self.lox_priv);
                M.set_privkey(&self.migration_priv);
                N.set_privkey(&self.lox_priv);
                M.migration_type = Some(Scalar::from_u128(MigrationType::Blockage.into()));
                N.trust_level = Some((level - 2).into());
                N.level_since = Some(today.into());
                N.invites_remaining = Some(LEVEL_INVITATIONS[(level - 3) as usize].into());
                Ok(())
            },
            |L: &Lox, _M: &Migration, _N: &Lox| {
                if self.id_filter.filter(&L.id.unwrap()) == SeenType::Seen {
                    return Err(CMZError::RevealAttrMissing("id", ""));
                }
                Ok(())
            },
        ) {
            Ok((response, (_L_issuer, _M_isser, _N_issuer))) => {
                let duration = now.elapsed();
                println!(
                    "blockage-migration reply size: {:?}",
                    bincode::serialize(&response).unwrap().len()
                );
                println!("blockage-migration reply time: {:?}", duration);
                Ok(response)
            }
            Err(e) => Err(CredentialError::CMZError(e)),
        }
    }
}

pub fn handle_response(
    state: blockage_migration::ClientState,
    rep: blockage_migration::Reply,
) -> Result<Lox, CMZError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let replybytes = rep.as_bytes();
    let recvreply = blockage_migration::Reply::try_from(&replybytes[..]).unwrap();
    match state.finalize(recvreply) {
        Ok(cred) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "blockage-migration client handle reply time {:#?}",
                    duration
                ));
            };
            Ok(cred)
        }
        Err(_e) => Err(CMZError::Unknown),
    }
}

#[cfg(all(test, feature = "bridgeauth"))]
mod tests {
    use crate::mock_auth::TestHarness;

    #[test]
    fn test_blockage_migration() {
        println!("\n----BLOCKAGE-MIGRATION----\n");
        let mut th = TestHarness::new();
        let rng = &mut rand::thread_rng();
        let invite = th.bdb.invite().unwrap();
        let (_, mut lox_cred) = th.open_invite(rng, &invite);
        let (_, mut mig_cred) = th.trust_promotion(rng, lox_cred.clone());
        (_, lox_cred) = th.migration(rng, lox_cred.clone(), mig_cred.clone());
        let (_, lox_cred_1) = th.level_up(rng, lox_cred.clone());
        let (_, lox_cred_2) = th.level_up(rng, lox_cred_1.clone());
        let (_, lox_cred_3) = th.level_up(rng, lox_cred_2.clone());
        th.block_bridges(lox_cred_3.clone());
        (_, mig_cred) = th.check_blockage(rng, lox_cred_3.clone());
        let (perf_stats, lox_cred) =
            th.blockage_migration(rng, lox_cred_3.clone(), mig_cred.clone());
        th.verify_lox(&lox_cred);
        th.print_test_results(perf_stats);
    }
}
