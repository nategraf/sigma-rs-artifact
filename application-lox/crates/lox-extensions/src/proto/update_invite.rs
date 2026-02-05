/*! A module for the protocol for a user to request the issuing of an updated
 * invitation credential after a key rotation has occurred


The user presents their current Invitation credential:
- id: revealed
- date: blinded
- bucket: blinded
- blockages: blinded

and a new Invitation credential to be issued:
- id: jointly chosen by the user and BA
- date: blinded, but proved in ZK that it's the same as in the invitation
  date above
- bucket: blinded, but proved in ZK that it's the same as in the Invitation
  credential above
- blockages: blinded, but proved in ZK that it's the same as in the
  Invitation credential above

*/

#[cfg(feature = "bridgeauth")]
use super::super::dup_filter::SeenType;
#[cfg(feature = "bridgeauth")]
use super::super::BridgeAuth;
use super::super::G;
use super::errors::CredentialError;
#[cfg(feature = "dump")]
use crate::dumper::dump;
use crate::lox_creds::Invitation;
use cmz::*;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use web_time::Instant;

const SESSION_ID: &[u8] = b"update_invite";

muCMZProtocol! { update_invite,
    I: Invitation { inv_id: R, date: H, bucket: H, blockages: H },
    N: Invitation { inv_id: J, date: H, bucket: H, blockages: H },
    I.date = N.date,
    I.bucket = N.bucket,
    I.blockages = N.blockages,
}

pub fn request(
    rng: &mut (impl CryptoRng + RngCore),
    I: Invitation,
    new_pubkeys: CMZPubkey<G>,
) -> Result<(update_invite::Request, update_invite::ClientState), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

    let mut N = Invitation::using_pubkey(&new_pubkeys);
    N.date = I.date;
    N.bucket = I.bucket;
    N.blockages = I.blockages;

    match update_invite::prepare(&mut *rng, SESSION_ID, &I, N) {
        Ok(req_state) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "update-invite client request time {:#?}",
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
    pub fn handle_update_invite(
        &mut self,
        old_pub_key: CMZPubkey<G>,
        req: update_invite::Request,
    ) -> Result<update_invite::Reply, CredentialError> {
        let now = Instant::now();
        let mut rng = rand::thread_rng();
        // Both of these must be true and should be true after rotate_lox_keys is called
        if self.old_keys.invitation_keys.is_empty() || self.old_filters.invitation_filter.is_empty()
        {
            return Err(CredentialError::CredentialMismatch);
        }

        let reqbytes = req.as_bytes();
        let recvreq = update_invite::Request::try_from(&reqbytes[..]).unwrap();
        match update_invite::handle(
            &mut rng,
            SESSION_ID,
            recvreq,
            |I: &mut Invitation, N: &mut Invitation| {
                // calling this function will automatically use the most recent old private key for
                // verification and the new private key for issuing.
                // Recompute the "error factors" using knowledge of our own
                // (the issuer's) outdated private key instead of knowledge of the
                // hidden attributes
                let old_keys = match self
                    .old_keys
                    .invitation_keys
                    .iter()
                    .find(|x| x.pub_key == old_pub_key)
                {
                    Some(old_keys) => old_keys,
                    None => return Err(CMZError::RevealAttrMissing("Key", "Mismatch")),
                };
                let old_priv_key = old_keys.priv_key.clone();
                I.set_privkey(&old_priv_key);
                N.set_privkey(&self.invitation_priv);
                Ok(())
            },
            |I: &Invitation, _N: &Invitation| {
                let index = match self
                    .old_keys
                    .invitation_keys
                    .iter()
                    .position(|x| x.pub_key == old_pub_key)
                {
                    Some(index) => index,
                    None => return Err(CMZError::RevealAttrMissing("Key", "Mismatch")),
                };
                if self
                    .old_filters
                    .invitation_filter
                    .get_mut(index)
                    .unwrap()
                    .filter(&I.inv_id.unwrap())
                    == SeenType::Seen
                {
                    return Err(CMZError::RevealAttrMissing("id", "Credential Expired"));
                }
                Ok(())
            },
        ) {
            Ok((response, (_I_issuer, _N_issuer))) => {
                let duration = now.elapsed();
                println!(
                    "update-invite reply size: {:?}",
                    bincode::serialize(&response).unwrap().len()
                );
                println!("update-invite reply time: {:?}", duration);
                Ok(response)
            }
            Err(e) => Err(CredentialError::CMZError(e)),
        }
    }
}

pub fn handle_response(
    state: update_invite::ClientState,
    rep: update_invite::Reply,
) -> Result<Invitation, CMZError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let replybytes = rep.as_bytes();
    let recvreply = update_invite::Reply::try_from(&replybytes[..]).unwrap();
    match state.finalize(recvreply) {
        Ok(cred) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "update-invite client handle reply time {:#?}",
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
    fn test_update_invite() {
        println!("\n----UPDATE-INVITE----\n");
        let mut th = TestHarness::new();
        let rng = &mut rand::thread_rng();
        let invite = th.bdb.invite().unwrap();
        let (_, mut lox_cred) = th.open_invite(rng, &invite);
        let (_, mig_cred) = th.trust_promotion(rng, lox_cred.clone());
        (_, lox_cred) = th.migration(rng, lox_cred.clone(), mig_cred.clone());
        (_, lox_cred) = th.level_up(rng, lox_cred.clone());
        let (_, (invitation, _)) = th.issue_invite(rng, lox_cred.clone());
        let old_pub = th.ba.invitation_pub.clone();
        let (perf_stats, creds) = th.update_invite(rng, invitation, old_pub);
        th.verify_invitation(&creds);
        th.print_test_results(perf_stats);
    }
}
