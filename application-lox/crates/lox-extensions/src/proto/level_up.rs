/*! A module for the protocol for the user to increase their trust level
(from a level at least 1; use the trust promotion protocol to go from
untrusted (level 0) to minimally trusted (level 1).

They are allowed to do this as long as some amount of time (depending on
their current level) has elapsed since their last level change, and they
have a Bucket Reachability credential for their current bucket and
today's date.  (Such credentials are placed daily in the encrypted
bridge table.)

The user presents their current Lox credential:
- id: revealed
- bucket: blinded
- trust_level: revealed, and must be at least 1
- level_since: blinded, but proved in ZK that it's at least the
  appropriate number of days ago
- invites_remaining: blinded
- blockages: blinded, but proved in ZK that it's at most the appropriate
  blockage limit for the target trust level

and a Bucket Reachability credential:
- date: revealed to be today
- bucket: blinded, but proved in ZK that it's the same as in the Lox
  credential above

and a new Lox credential to be issued:

- id: jointly chosen by the user and BA
- bucket: blinded, but proved in ZK that it's the same as in the Lox
  credential above
- trust_level: revealed to be one more than the trust level above
- level_since: today
- invites_remaining: revealed to be the number of invites for the new
  level (note that the invites_remaining from the previous credential
  are _not_ carried over)
- blockages: blinded, but proved in ZK that it's the same as in the
  Lox credential above

*/
#[cfg(feature = "bridgeauth")]
use super::super::dup_filter::SeenType;
#[cfg(feature = "bridgeauth")]
use super::super::BridgeAuth;
use super::super::{scalar_u32, G};
use super::errors::CredentialError;
#[cfg(feature = "dump")]
use crate::dumper::dump;
use crate::lox_creds::{BucketReachability, Lox};
use cmz::*;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use web_time::Instant;

const SESSION_ID: &[u8] = b"level_up";

/// The maximum trust level in the system.  A user can run this level
/// upgrade protocol when they're already at the max level; they will
/// get a fresh invites_remaining batch, and reset their level_since
/// field to today's date, but will remain in the max level.
pub const MAX_LEVEL: usize = 4;

/// LEVEL_INTERVAL\[i\] for i >= 1 is the minimum number of days a user
/// must be at trust level i before advancing to level i+1 (or as above,
/// remain at level i if i == MAX_LEVEL).  Note that the
/// LEVEL_INTERVAL\[0\] entry is a dummy; the trust_promotion protocol
/// is used instead of this one to move from level 0 to level 1.
pub const LEVEL_INTERVAL: [u32; MAX_LEVEL + 1] = [0, 14, 28, 56, 84];

/// LEVEL_INVITATIONS\[i\] for i >= 1 is the number of invitations a
/// user will be eligible to issue upon advancing from level i to level
/// i+1.  Again the LEVEL_INVITATIONS\[0\] entry is a dummy, as for
/// LEVEL_INTERVAL.
pub const LEVEL_INVITATIONS: [u32; MAX_LEVEL + 1] = [0, 2, 4, 6, 8];

/// MAX_BLOCKAGES\[i\] for i >= 1 is the maximum number of bucket
/// blockages this credential is allowed to have recorded in order to
/// advance from level i to level i+1.  Again the LEVEL_INVITATIONS\[0\]
/// entry is a dummy, as for LEVEL_INTERVAL.
// If you change this to have a number greater than 7, you need to add
// one or more bits to the ZKP.
pub const MAX_BLOCKAGES: [u32; MAX_LEVEL + 1] = [0, 4, 3, 2, 2];

muCMZProtocol! { level_up<credential_expiry, eligibility_max_age, max_blockage, today>,
    [ L: Lox { id: R, bucket: H, trust_level: R, level_since: H, invites_remaining: H, blockages: H },
    B: BucketReachability { date: R, bucket: H } ],
    N: Lox {id: J, bucket: H, trust_level: R, level_since: S, invites_remaining: I, blockages: H },
    (credential_expiry..=eligibility_max_age).contains(L.level_since),
    (0..=max_blockage).contains(L.blockages),
    B.date = today,
    B.bucket = L.bucket,
    N.bucket = L.bucket,
    N.trust_level = L.trust_level + 1,
    N.blockages = L.blockages,
}

pub fn request(
    rng: &mut (impl CryptoRng + RngCore),
    L: Lox,
    B: BucketReachability,
    today: u32,
) -> Result<(level_up::Request, level_up::ClientState), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));
    // Ensure the credential can be correctly shown: it must be the case
    // that level_since + LEVEL_INTERVAL[level] <= today.
    let level_since: u32 = match scalar_u32(&L.level_since.unwrap()) {
        Some(v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("level_since"),
                String::from("could not be converted to u32"),
            ))
        }
    };
    // The trust level has to be at least 1
    let trust_level: u32 = match scalar_u32(&L.trust_level.unwrap()) {
        Some(v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("trust_level"),
                String::from("could not be converted to u32"),
            ))
        }
    };
    if trust_level < 1 || (trust_level as usize) > MAX_LEVEL {
        return Err(CredentialError::InvalidField(
            String::from("trust_level"),
            format!("level {:?} not in range", trust_level),
        ));
    }
    // The trust level has to be no higher than the highest level
    let level_interval: u32 = match LEVEL_INTERVAL.get(trust_level as usize) {
        Some(&v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("trust_level"),
                format!("level {:?} not in range", trust_level),
            ))
        }
    };
    if level_since + level_interval > today {
        return Err(CredentialError::TimeThresholdNotMet(
            level_since + level_interval - today,
        ));
    }
    // The credential can't be _too_ old
    let diffdays = today - (level_since + level_interval);
    if diffdays > 511 {
        return Err(CredentialError::CredentialExpired);
    }
    // The current number of blockages
    let blockages = match scalar_u32(&L.blockages.unwrap()) {
        Some(v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("blockages"),
                String::from("could not be converted to u32"),
            ))
        }
    };
    if blockages > MAX_BLOCKAGES[trust_level as usize] {
        return Err(CredentialError::ExceededBlockagesThreshold);
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
    // The new trust level
    let new_level = if (trust_level as usize) < MAX_LEVEL {
        trust_level + 1
    } else {
        trust_level
    };
    let mut N = Lox::using_pubkey(L.get_pubkey());
    N.bucket = L.bucket;
    N.trust_level = Some(new_level.into());
    N.invites_remaining = Some(LEVEL_INVITATIONS[trust_level as usize].into());
    N.blockages = L.blockages;
    let eligibility_max_age = today - (LEVEL_INTERVAL[trust_level as usize]);

    let params = level_up::Params {
        credential_expiry: (eligibility_max_age - 511).into(),
        eligibility_max_age: eligibility_max_age.into(),
        max_blockage: MAX_BLOCKAGES[new_level as usize].into(),
        today: today.into(),
    };
    match level_up::prepare(rng, SESSION_ID, &L, &B, N, &params) {
        Ok(req_state) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!("level-up client request time {:#?}", duration));
            };
            Ok(req_state)
        }
        Err(e) => Err(CredentialError::CMZError(e)),
    }
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    pub fn handle_level_up(
        &mut self,
        req: level_up::Request,
    ) -> Result<level_up::Reply, CredentialError> {
        let now = Instant::now();
        let mut rng = rand::thread_rng();
        let reqbytes = req.as_bytes();
        let recvreq = level_up::Request::try_from(&reqbytes[..]).unwrap();
        let today = self.today();
        match level_up::handle(
            &mut rng,
            SESSION_ID,
            recvreq,
            |L: &mut Lox, B: &mut BucketReachability, N: &mut Lox| {
                let trust_level: u32 = match scalar_u32(&L.trust_level.unwrap()) {
                    Some(v) if v as usize >= 1 && v as usize <= MAX_LEVEL => v,
                    _ => {
                        // This error should be improved i.e., InvalidAttr and the type
                        // with a description
                        return Err(CMZError::RevealAttrMissing(
                            "trust_level",
                            "Could not be converted to u32 or value not in range",
                        ));
                    }
                };
                let eligibility_max_age: u32 = today - LEVEL_INTERVAL[trust_level as usize];
                L.set_privkey(&self.lox_priv);
                B.set_privkey(&self.reachability_priv);
                N.set_privkey(&self.lox_priv);
                N.trust_level = Some((trust_level + 1).into());
                N.level_since = Some(today.into());
                N.invites_remaining = Some(LEVEL_INVITATIONS[trust_level as usize].into());
                Ok(level_up::Params {
                    credential_expiry: (eligibility_max_age - 511).into(),
                    eligibility_max_age: eligibility_max_age.into(),
                    max_blockage: MAX_BLOCKAGES[(trust_level + 1) as usize].into(),
                    today: today.into(),
                })
            },
            |L: &Lox, _B: &BucketReachability, _N: &Lox| {
                if self.id_filter.filter(&L.id.unwrap()) == SeenType::Seen {
                    return Err(CMZError::RevealAttrMissing("id", ""));
                }
                Ok(())
            },
        ) {
            Ok((response, (_L_issuer, _B_isser, _N_issuer))) => {
                let duration = now.elapsed();
                println!(
                    "level-up reply size: {:?}",
                    bincode::serialize(&response).unwrap().len()
                );
                println!("level-up reply time: {:?}", duration);
                Ok(response)
            }
            Err(e) => Err(CredentialError::CMZError(e)),
        }
    }
}

pub fn handle_response(
    state: level_up::ClientState,
    rep: level_up::Reply,
) -> Result<Lox, CMZError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let replybytes = rep.as_bytes();
    let recvreply = level_up::Reply::try_from(&replybytes[..]).unwrap();
    match state.finalize(recvreply) {
        Ok(cred) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!("level-up client handle time {:#?}", duration));
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
    fn test_level_up() {
        println!("\n----LEVEL-UP-2: 44 days----\n");
        let mut th = TestHarness::new();
        let rng = &mut rand::thread_rng();
        let invite = th.bdb.invite().unwrap();
        let (_, mut lox_cred) = th.open_invite(rng, &invite);
        let (_, mig_cred) = th.trust_promotion(rng, lox_cred.clone());
        (_, lox_cred) = th.migration(rng, lox_cred.clone(), mig_cred.clone());
        let (perf_stat, lox_cred) = th.level_up(rng, lox_cred.clone());
        th.verify_lox(&lox_cred);
        th.print_test_results(perf_stat);
    }
}
