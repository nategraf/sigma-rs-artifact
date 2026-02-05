/*! A module for the protocol for the user to migrate from one bucket to
another and change trust level from untrusted (trust level 0) to trusted
(trust level 1).

The user presents their current Lox credential:

- id: revealed
- bucket: blinded
- trust_level: revealed to be 0
- level_since: blinded
- invites_remaining: revealed to be 0
- blockages: revealed to be 0

and a Migration credential:

- id: revealed as the same as the Lox credential id above
- from_bucket: blinded, but proved in ZK that it's the same as the
  bucket in the Lox credential above
- to_bucket: blinded

and a new Lox credential to be issued:

- id: jointly chosen by the user and BA
- bucket: blinded, but proved in ZK that it's the same as the to_bucket
  in the Migration credential above
- trust_level: 1
- level_since: today
- invites_remaining: 0
- blockages: 0

*/

#[cfg(feature = "bridgeauth")]
use super::super::dup_filter::SeenType;
#[cfg(feature = "bridgeauth")]
use super::super::BridgeAuth;
use super::super::{Scalar, G};
use super::errors::CredentialError;
#[cfg(feature = "dump")]
use crate::dumper::dump;
use crate::lox_creds::{Lox, Migration};
#[cfg(feature = "bridgeauth")]
use crate::migration_table::MigrationType;
#[cfg(feature = "bridgeauth")]
use crate::scalar_u32;
use cmz::*;
#[cfg(feature = "bridgeauth")]
use ff::PrimeField;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use web_time::Instant;

const SESSION_ID: &[u8] = b"migration";

muCMZProtocol! { migration,
    [ L: Lox { id: R, bucket: H, trust_level: R, level_since: H, invites_remaining: R, blockages: R },
    M: Migration { lox_id: R, from_bucket: H, to_bucket: H, migration_type: I} ],
    N: Lox {id: J, bucket: H, trust_level: I, level_since: S, invites_remaining: I, blockages: I },
    L.id = M.lox_id,
    L.bucket = M.from_bucket,
    N.bucket = M.to_bucket,
}

pub fn request(
    rng: &mut (impl CryptoRng + RngCore),
    L: Lox,
    M: Migration,
) -> Result<(migration::Request, migration::ClientState), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

    // Ensure that the credenials can be correctly shown; that is, the
    // ids match and the Lox credential bucket matches the Migration
    // credential from_bucket
    if L.id.is_some_and(|i| i != M.lox_id.unwrap()) {
        return Err(CredentialError::CredentialMismatch);
    }

    // This protocol only allows migrating from trust level 0 to trust
    // level 1
    if L.trust_level.is_some_and(|t| t != Scalar::ZERO) {
        return Err(CredentialError::InvalidField(
            String::from("trust_level"),
            String::from("must be zero"),
        ));
    }

    if L.bucket.is_some_and(|b| b != M.from_bucket.unwrap()) {
        return Err(CredentialError::CredentialMismatch);
    }

    let mut N = Lox::using_pubkey(L.get_pubkey());
    N.bucket = M.to_bucket;
    N.trust_level = Some(Scalar::ONE);
    N.invites_remaining = Some(Scalar::ZERO);
    N.blockages = Some(Scalar::ZERO);

    match migration::prepare(rng, SESSION_ID, &L, &M, N) {
        Ok(req_state) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "migration client request size: {:#?} migration client request time {:#?}",
                    bincode::serialize(&req_state.0).unwrap().len(),
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
    pub fn handle_migration(
        &mut self,
        req: migration::Request,
    ) -> Result<migration::Reply, CredentialError> {
        let now = Instant::now();
        let mut rng = rand::thread_rng();
        let reqbytes = req.as_bytes();
        let recvreq = migration::Request::try_from(&reqbytes[..]).unwrap();

        let today = self.today();
        match migration::handle(
            &mut rng,
            SESSION_ID,
            recvreq,
            |L: &mut Lox, M: &mut Migration, N: &mut Lox| {
                match scalar_u32(&L.trust_level.unwrap()) {
                    Some(v) if v as usize == 0 => v,
                    _ => {
                        // This error should be improved i.e., InvalidAttr and the type
                        // with a description
                        return Err(CMZError::RevealAttrMissing(
                            "migration",
                            "Could not be converted to u32 or trust_level not 0",
                        ));
                    }
                };
                L.set_privkey(&self.lox_priv);
                M.set_privkey(&self.migration_priv);
                N.set_privkey(&self.lox_priv);
                M.migration_type = Some(Scalar::from_u128(MigrationType::TrustUpgrade.into()));
                N.trust_level = Some(Scalar::ONE);
                N.level_since = Some(today.into());
                N.invites_remaining = Some(Scalar::ZERO);
                N.blockages = Some(Scalar::ZERO);
                Ok(())
            },
            |L: &Lox, _M: &Migration, _N: &Lox| {
                if self.id_filter.filter(&L.id.unwrap()) == SeenType::Seen {
                    return Err(CMZError::RevealAttrMissing("id", "Credential Expired"));
                }
                Ok(())
            },
        ) {
            Ok((response, (_L_issuer, _M_isser, _N_issuer))) => {
                println!(
                    "migration reply size: {:?}",
                    bincode::serialize(&response).unwrap().len()
                );
                let duration = now.elapsed();
                println!("migration reply time {:?}", duration);
                Ok(response)
            }
            Err(e) => Err(CredentialError::CMZError(e)),
        }
    }
}

pub fn handle_response(
    state: migration::ClientState,
    rep: migration::Reply,
) -> Result<Lox, CMZError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let replybytes = rep.as_bytes();
    let recvreply = migration::Reply::try_from(&replybytes[..]).unwrap();
    match state.finalize(recvreply) {
        Ok(cred) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "migration client handle response time {:#?}",
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
    fn test_trust_migration() {
        println!("\n----TRUST-MIGRATION-0: 30 days----\n");
        let mut th = TestHarness::new();
        let rng = &mut rand::thread_rng();
        let invite = th.bdb.invite().unwrap();
        let (_, lox_cred) = th.open_invite(rng, &invite);
        let (_, mig_cred) = th.trust_promotion(rng, lox_cred.clone());
        let (perf_stat, new_lox) = th.migration(rng, lox_cred.clone(), mig_cred.clone());
        th.verify_lox(&new_lox);
        th.print_test_results(perf_stat);
    }
}
