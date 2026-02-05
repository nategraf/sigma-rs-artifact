/*! A module for the protocol for a user to request the issuing of an updated credential after a key rotation has occurred


They are allowed to do this as long as their current Lox credential is valid

The user presents their current Lox credential:
- id: revealed
- bucket: blinded
- trust_level: blinded
- level_since: blinded
- invites_remaining: blinded
- blockages: blinded

and a new Lox credential to be issued:
- id: jointly chosen by the user and BA
- bucket: blinded, but proved in ZK that it's the same as in the Lox
  credential above
- trust_level: blinded, but proved in ZK that it's the same as in the
  Lox credential above
- level_since: blinded, but proved in ZK that it's the same as in the
  Lox credential above
- invites_remaining: blinded, but proved in ZK that it's the same as in the Lox credential above
- blockages: blinded, but proved in ZK that it's the same as in the
  Lox credential above

*/

#[cfg(feature = "bridgeauth")]
use super::super::dup_filter::SeenType;
#[cfg(feature = "bridgeauth")]
use super::super::BridgeAuth;
use super::super::G;
use super::errors::CredentialError;
#[cfg(feature = "dump")]
use crate::dumper::dump;
use crate::lox_creds::Lox;
use cmz::*;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use web_time::Instant;

const SESSION_ID: &[u8] = b"update_cred";

muCMZProtocol! { update_cred,
    L: Lox { id: R, bucket: H, trust_level: H, level_since: H, invites_remaining: H, blockages: H },
    N: Lox {id: J, bucket: H, trust_level: H, level_since: H, invites_remaining: H, blockages: H },
    N.bucket = L.bucket,
    N.trust_level = L.trust_level,
    N.level_since = L.level_since,
    N.invites_remaining = L.invites_remaining,
    N.blockages = L.blockages,
}

pub fn request(
    rng: &mut (impl CryptoRng + RngCore),
    L: Lox,
    pubkeys: CMZPubkey<G>,
) -> Result<(update_cred::Request, update_cred::ClientState), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));
    let mut N: Lox = Lox::using_pubkey(&pubkeys);
    N.bucket = L.bucket;
    N.trust_level = L.trust_level;
    N.level_since = L.level_since;
    N.invites_remaining = L.invites_remaining;
    N.blockages = L.blockages;

    match update_cred::prepare(&mut *rng, SESSION_ID, &L, N) {
        Ok(req_state) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!("update-cred client request time {:#?}", duration));
            };
            Ok(req_state)
        }
        Err(e) => Err(CredentialError::CMZError(e)),
    }
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    pub fn handle_update_cred(
        &mut self,
        old_pub_key: CMZPubkey<G>,
        req: update_cred::Request,
    ) -> Result<update_cred::Reply, CredentialError> {
        let now = Instant::now();
        let mut rng = rand::thread_rng();
        // Both of these must be true and should be true after rotate_lox_keys is called
        if self.old_keys.lox_keys.is_empty() || self.old_filters.lox_filter.is_empty() {
            return Err(CredentialError::CredentialMismatch);
        }
        let reqbytes = req.as_bytes();
        let recvreq = update_cred::Request::try_from(&reqbytes[..]).unwrap();
        match update_cred::handle(
            &mut rng,
            SESSION_ID,
            recvreq,
            |L: &mut Lox, N: &mut Lox| {
                // calling this function will automatically use the most recent old private key for
                // verification and the new private key for issuing.

                // Recompute the "error factors" using knowledge of our own
                // (the issuer's) outdated private key instead of knowledge of the
                // hidden attributes
                let old_keys = match self
                    .old_keys
                    .lox_keys
                    .iter()
                    .find(|x| x.pub_key == old_pub_key)
                {
                    Some(old_keys) => old_keys,
                    None => {
                        return Err(CMZError::RevealAttrMissing("Key", "Mismatch"));
                    }
                };
                let old_priv_key = old_keys.priv_key.clone();
                L.set_privkey(&old_priv_key);
                N.set_privkey(&self.lox_priv);
                Ok(())
            },
            |L: &Lox, _N: &Lox| {
                let index = match self
                    .old_keys
                    .lox_keys
                    .iter()
                    .position(|x| x.pub_key == old_pub_key)
                {
                    Some(index) => {
                        println!("Check3");
                        index
                    }
                    None => return Err(CMZError::RevealAttrMissing("Key", "Mismatch")),
                };
                if self
                    .old_filters
                    .lox_filter
                    .get_mut(index)
                    .unwrap()
                    .filter(&L.id.unwrap())
                    == SeenType::Seen
                {
                    return Err(CMZError::RevealAttrMissing("id", "Credential Expired"));
                }
                Ok(())
            },
        ) {
            Ok((response, (_L_issuer, _N_issuer))) => {
                let duration = now.elapsed();
                println!(
                    "update-cred response Size: {:?}",
                    bincode::serialize(&response).unwrap().len()
                );
                println!("Check4");
                println!("update-cred response time: {:?}", duration);
                Ok(response)
            }
            Err(e) => Err(CredentialError::CMZError(e)),
        }
    }
}

pub fn handle_response(
    state: update_cred::ClientState,
    rep: update_cred::Reply,
) -> Result<Lox, CMZError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let replybytes = rep.as_bytes();
    let recvreply = update_cred::Reply::try_from(&replybytes[..]).unwrap();
    match state.finalize(recvreply) {
        Ok(cred) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "update-cred client handle reply time {:#?}",
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
    fn test_update_cred() {
        println!("\n----UPDATE-CRED----\n");
        let mut th = TestHarness::new();
        let rng = &mut rand::thread_rng();
        let invite = th.bdb.invite().unwrap();
        let (_, lox_cred) = th.open_invite(rng, &invite);
        let old_pub = th.ba.lox_pub.clone();
        let (perf_stat, lox_cred) = th.update_cred(rng, lox_cred, old_pub);
        th.verify_lox(&lox_cred);
        th.print_test_results(perf_stat);
    }
}
