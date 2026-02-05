/*! A module for the protocol for a user to request the issuing of an
Invitation credential they can pass to someone they know.

They are allowed to do this as long as their current Lox credentials has
a non-zero "invites_remaining" attribute (which will be decreased by
one), and they have a Bucket Reachability credential for their current
bucket and today's date.  (Such credentials are placed daily in the
encrypted bridge table.)

The user presents their current Lox credential:
- id: revealed
- bucket: hidden
- trust_level: hidden
- level_since: hidden
- invites_remaining: hidden, but proved in ZK that it's not zero
- blockages: hidden

and a Bucket Reachability credential:
- date: revealed to be today
- bucket: hidden, but proved in ZK that it's the same as in the Lox
  credential above

and a new Lox credential to be issued:

- id: jointly chosen by the user and BA
- bucket: hidden, but proved in ZK that it's the same as in the Lox
  credential above
- trust_level: hidden, but proved in ZK that it's the same as in the
  Lox credential above
- level_since: hidden, but proved in ZK that it's the same as in the
  Lox credential above
- invites_remaining: hidden, but proved in ZK that it's one less than
  the number in the Lox credential above
- blockages: hidden, but proved in ZK that it's the same as in the
  Lox credential above

and a new Invitation credential to be issued:

- inv_id: jointly chosen by the user and BA
- date: selected by the server to be today's date
- bucket: hidden, but proved in ZK that it's the same as in the Lox
  credential above
- blockages: hidden, but proved in ZK that it's the same as in the Lox
  credential above

*/

#[cfg(feature = "bridgeauth")]
use super::super::dup_filter::SeenType;
#[cfg(feature = "bridgeauth")]
use super::super::BridgeAuth;
use super::super::{scalar_u32, Scalar, G};
use super::errors::CredentialError;
#[cfg(feature = "dump")]
use crate::dumper::dump;
use crate::lox_creds::{BucketReachability, Invitation, Lox};
use cmz::*;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use web_time::Instant;

const SESSION_ID: &[u8] = b"issue_invite";

/// Invitations must be used within this many days of being issued.
/// Note that if you change this number to be larger than 15, you must
/// also add bits to the zero knowledge proof.
pub const INVITATION_EXPIRY: u32 = 15;

muCMZProtocol! { issue_invite,
    [L: Lox {id: R, bucket: H, trust_level: H, level_since: H, invites_remaining: H, blockages: H}, B: BucketReachability { date: R, bucket: H } ],
    [ I: Invitation { inv_id: J, date: S, bucket: H, blockages: H }, N: Lox {id: J, bucket: H, trust_level: H, level_since: H, invites_remaining: H, blockages: H }],
    L.bucket = B.bucket,
    L.invites_remaining != 0,
    N.bucket = L.bucket,
    N.trust_level = L.trust_level,
    N.level_since = L.level_since,
    N.invites_remaining = L.invites_remaining - 1,
    N.blockages = L.blockages,
    I.bucket = L.bucket,
    I.blockages = L.blockages
}

pub fn request(
    rng: &mut (impl CryptoRng + RngCore),
    L: Lox,
    B: BucketReachability,
    inv_pub: CMZPubkey<G>,
    today: u32,
) -> Result<(issue_invite::Request, issue_invite::ClientState), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

    // Ensure the credential can be correctly shown: it must be the case
    // that invites_remaining not be 0
    if let Some(invites_remaining) = L.invites_remaining {
        if invites_remaining == Scalar::ZERO {
            return Err(CredentialError::NoInvitationsRemaining);
        }
    } else {
        return Err(CredentialError::InvalidField(
            String::from("invites_remaining"),
            String::from("None"),
        ));
    }

    // The buckets in the Lox and Bucket Reachability credentials have
    // to match
    if L.bucket.is_some_and(|b| b != B.bucket.unwrap()) {
        return Err(CredentialError::CredentialMismatch);
    }
    // The Bucket Reachability credential has to be dated today
    let reach_date: u32 = match scalar_u32(&B.date.unwrap()) {
        Some(v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("date"),
                String::from("could not be converted to u32"),
            ))
        }
    };
    if reach_date != today {
        return Err(CredentialError::InvalidField(
            String::from("date"),
            String::from("reachability credential must be generated today"),
        ));
    }

    let mut I: Invitation = Invitation::using_pubkey(&inv_pub);
    I.inv_id = Some(Scalar::random(rng));
    I.date = Some(today.into());
    I.bucket = L.bucket;
    I.blockages = L.blockages;

    let mut N: Lox = Lox::using_pubkey(L.get_pubkey());
    N.bucket = L.bucket;
    N.trust_level = L.trust_level;
    N.level_since = L.level_since;
    N.invites_remaining = Some(L.invites_remaining.unwrap() - Scalar::ONE);
    N.blockages = L.blockages;

    match issue_invite::prepare(rng, SESSION_ID, &L, &B, I, N) {
        Ok(req_state) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!("issue-invite client request time {:#?}", duration));
            };
            Ok(req_state)
        }
        Err(e) => Err(CredentialError::CMZError(e)),
    }
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    pub fn handle_issue_invite(
        &mut self,
        req: issue_invite::Request,
    ) -> Result<issue_invite::Reply, CredentialError> {
        let now = Instant::now();
        let mut rng = rand::thread_rng();
        let reqbytes = req.as_bytes();
        let recvreq = issue_invite::Request::try_from(&reqbytes[..]).unwrap();
        let today = self.today();
        match issue_invite::handle(
            &mut rng,
            SESSION_ID,
            recvreq,
            |L: &mut Lox, B: &mut BucketReachability, I: &mut Invitation, N: &mut Lox| {
                L.set_privkey(&self.lox_priv);
                B.set_privkey(&self.reachability_priv);
                I.set_privkey(&self.invitation_priv);
                N.set_privkey(&self.lox_priv);
                if B.date.is_some_and(|b| b != today.into()) {
                    return Err(CMZError::RevealAttrMissing("date", "not today"));
                }
                I.date = Some(today.into());
                Ok(())
            },
            |L: &Lox, _B: &BucketReachability, _I: &Invitation, _N: &Lox| {
                if self.id_filter.filter(&L.id.unwrap()) == SeenType::Seen {
                    return Err(CMZError::RevealAttrMissing("id", "Credential Expired"));
                }
                Ok(())
            },
        ) {
            Ok((response, (_L_issuer, _B_issuer, _I_issuer, _N_issuer))) => {
                let duration = now.elapsed();
                println!(
                    "issue-invite reply size: {:?}",
                    bincode::serialize(&response).unwrap().len()
                );
                println!("issue-invite reply time: {:?}", duration);
                Ok(response)
            }
            Err(e) => Err(CredentialError::CMZError(e)),
        }
    }
}

pub fn handle_response(
    state: issue_invite::ClientState,
    rep: issue_invite::Reply,
) -> Result<(Invitation, Lox), CMZError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let replybytes = rep.as_bytes();
    let recvreply = issue_invite::Reply::try_from(&replybytes[..]).unwrap();
    match state.finalize(recvreply) {
        Ok(creds) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!("issue-invite client handle time {:#?}", duration));
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
    fn test_issue_invite() {
        println!("\n----ISSUE-INVITATION----\n");
        let mut th = TestHarness::new();
        let rng = &mut rand::thread_rng();
        let invite = th.bdb.invite().unwrap();
        let (_, mut lox_cred) = th.open_invite(rng, &invite);
        let (_, mig_cred) = th.trust_promotion(rng, lox_cred.clone());
        (_, lox_cred) = th.migration(rng, lox_cred.clone(), mig_cred.clone());
        (_, lox_cred) = th.level_up(rng, lox_cred.clone());
        let (perf_stats, issue_invite_cred) = th.issue_invite(rng, lox_cred.clone());
        th.verify_lox(&issue_invite_cred.clone().1);
        th.verify_invitation(&issue_invite_cred.clone().0);
        th.print_test_results(perf_stats);
    }
}
