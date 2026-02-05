/*! A module for the protocol for a new user to redeem an Invitation
credential.  The user will start at trust level 1 (instead of 0 for
untrusted uninvited users).

The user presents the Invitation credential:
- id: revealed
- date: blinded, but proved in ZK to be at most INVITATION_EXPIRY days ago
- bucket: blinded
- blockages: blinded

and a new Lox credential to be issued:

- id: jointly chosen by the user and BA
- bucket: blinded, but proved in ZK that it's the same as in the
  Invitation credential above
- trust_level: revealed to be 1
- level_since: today
- invites_remaining: revealed to be 0
- blockages: blinded, but proved in ZK that it's the same as in the
  Invitations credential above

*/

#[cfg(feature = "bridgeauth")]
use super::super::dup_filter::SeenType;
#[cfg(feature = "bridgeauth")]
use super::super::BridgeAuth;
use super::super::{scalar_u32, Scalar, G};
use super::errors::CredentialError;
#[cfg(feature = "dump")]
use crate::dumper::dump;
use crate::lox_creds::{Invitation, Lox};
use crate::proto::level_up::LEVEL_INVITATIONS;
use cmz::*;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use web_time::Instant;

const SESSION_ID: &[u8] = b"redeem_invite";

/// Invitations must be used within this many days of being issued.
/// Note that if you change this number to be larger than 15, you must
/// also add bits to the zero knowledge proof.
pub const INVITATION_EXPIRY: u32 = 15;

muCMZProtocol! { redeem_invite<credential_expiry, today>,
    [ I: Invitation { inv_id: R, date: H, bucket: H, blockages: H } ],
    N: Lox {id: J, bucket: H, trust_level: I, level_since: S, invites_remaining: I, blockages: H },
    (credential_expiry..=today).contains(I.date),
    N.bucket = I.bucket,
    N.blockages = I.blockages,
}

pub fn request(
    rng: &mut (impl CryptoRng + RngCore),
    I: Invitation,
    lox_pubkeys: CMZPubkey<G>,
    today: u32,
) -> Result<(redeem_invite::Request, redeem_invite::ClientState), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));
    // Ensure the credential can be correctly shown: it must be the case
    // that date + INVITATION_EXPIRY >= today.
    let date: u32 = match scalar_u32(&I.date.unwrap()) {
        Some(v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("date"),
                String::from("could not be converted to u32"),
            ))
        }
    };
    if date + INVITATION_EXPIRY < today {
        return Err(CredentialError::CredentialExpired);
    }
    let diffdays = date + INVITATION_EXPIRY - today;
    // If diffdays > 15, then since INVITATION_EXPIRY <= 15, then date
    // must be in the future.  Reject.
    if diffdays > 15 {
        return Err(CredentialError::InvalidField(
            String::from("date"),
            String::from("credential was created in the future"),
        ));
    }

    let params = redeem_invite::Params {
        credential_expiry: (today - INVITATION_EXPIRY).into(),
        today: today.into(),
    };

    let mut N = Lox::using_pubkey(&lox_pubkeys);
    N.bucket = I.bucket;
    N.trust_level = Some(Scalar::ONE);
    N.invites_remaining = Some(LEVEL_INVITATIONS[1].into());
    N.blockages = I.blockages;

    match redeem_invite::prepare(rng, SESSION_ID, &I, N, &params) {
        Ok(req_state) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "redeem-invite client request time {:#?}",
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
    pub fn handle_redeem_invite(
        &mut self,
        req: redeem_invite::Request,
    ) -> Result<redeem_invite::Reply, CredentialError> {
        let now = Instant::now();
        let mut rng = rand::thread_rng();
        let reqbytes = req.as_bytes();
        let recvreq = redeem_invite::Request::try_from(&reqbytes[..]).unwrap();
        let today = self.today();
        match redeem_invite::handle(
            &mut rng,
            SESSION_ID,
            recvreq,
            |I: &mut Invitation, N: &mut Lox| {
                I.set_privkey(&self.invitation_priv);
                N.set_privkey(&self.lox_priv);
                let eligibility_max_age: u32 = today - INVITATION_EXPIRY;
                N.trust_level = Some(Scalar::ONE);
                N.level_since = Some(today.into());
                N.invites_remaining = Some(LEVEL_INVITATIONS[1].into());
                Ok(redeem_invite::Params {
                    credential_expiry: eligibility_max_age.into(),
                    today: today.into(),
                })
            },
            |I: &Invitation, _N: &Lox| {
                if self.inv_id_filter.filter(&I.inv_id.unwrap()) == SeenType::Seen {
                    return Err(CMZError::RevealAttrMissing("id", "Credential expired"));
                }
                Ok(())
            },
        ) {
            Ok((response, (_I_isser, _N_issuer))) => {
                let duration = now.elapsed();
                println!(
                    "redeem-invite response size: {:?}",
                    bincode::serialize(&response).unwrap().len()
                );
                println!("redeem-invite response time: {:?}", duration);
                Ok(response)
            }
            Err(e) => Err(CredentialError::CMZError(e)),
        }
    }
}

pub fn handle_response(
    state: redeem_invite::ClientState,
    rep: redeem_invite::Reply,
) -> Result<Lox, CMZError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let replybytes = rep.as_bytes();
    let recvreply = redeem_invite::Reply::try_from(&replybytes[..]).unwrap();
    match state.finalize(recvreply) {
        Ok(creds) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!("redeem-invite client handle time {:#?}", duration));
            };
            Ok(creds)
        }
        Err(_e) => Err(CMZError::Unknown),
    }
}

#[cfg(all(test, feature = "bridgeauth"))]
mod tests {
    use crate::mock_auth::TestHarness;

    #[test]
    fn test_redeem_invite() {
        println!("\n----REDEEM-INVITATION----\n");
        let mut th = TestHarness::new();
        let rng = &mut rand::thread_rng();
        let invite = th.bdb.invite().unwrap();
        let (_, lox_cred) = th.open_invite(rng, &invite);
        let (_, mig_cred) = th.trust_promotion(rng, lox_cred.clone());
        let (_, lox_cred) = th.migration(rng, lox_cred.clone(), mig_cred.clone());
        let (_, lox_cred) = th.level_up(rng, lox_cred.clone());
        let (_, issue_invite_cred) = th.issue_invite(rng, lox_cred.clone());
        let (perf_stat, r_cred) = th.redeem_invite(rng, issue_invite_cred.0);
        th.verify_lox(&r_cred);
        th.print_test_results(perf_stat);
    }
}
