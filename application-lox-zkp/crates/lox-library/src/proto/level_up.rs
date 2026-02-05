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

use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;

use lox_zkp::CompactProof;
use lox_zkp::ProofError;
use lox_zkp::Transcript;

use serde::{Deserialize, Serialize};

use super::super::cred;
#[cfg(feature = "bridgeauth")]
use super::super::dup_filter::SeenType;
#[cfg(feature = "bridgeauth")]
use super::super::pt_dbl;
#[cfg(feature = "bridgeauth")]
use super::super::BridgeAuth;
use super::super::IssuerPubKey;
use super::super::{scalar_dbl, scalar_u32};
use super::super::{CMZ_A, CMZ_A_TABLE, CMZ_B};
#[cfg(feature = "dump")]
use crate::dumper::dump;
#[cfg(feature = "dump")]
use web_time::Instant;

use super::errors::CredentialError;

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

#[derive(Serialize, Clone, Deserialize)]
pub struct Request {
    // Fields for blind showing the Lox credential
    P: RistrettoPoint,
    id: Scalar,
    CBucket: RistrettoPoint,
    level: Scalar,
    CSince: RistrettoPoint,
    CInvRemain: RistrettoPoint,
    CBlockages: RistrettoPoint,
    CQ: RistrettoPoint,

    // Fields for blind showing the Bucket Reachability credential
    P_reach: RistrettoPoint,
    CBucket_reach: RistrettoPoint,
    CQ_reach: RistrettoPoint,

    // Fields for the inequality proof
    // level_since + LEVEL_INTERVAL[level] <= today
    CG1: RistrettoPoint,
    CG2: RistrettoPoint,
    CG3: RistrettoPoint,
    CG4: RistrettoPoint,
    CG5: RistrettoPoint,
    CG6: RistrettoPoint,
    CG7: RistrettoPoint,
    CG8: RistrettoPoint,
    CG0sq: RistrettoPoint,
    CG1sq: RistrettoPoint,
    CG2sq: RistrettoPoint,
    CG3sq: RistrettoPoint,
    CG4sq: RistrettoPoint,
    CG5sq: RistrettoPoint,
    CG6sq: RistrettoPoint,
    CG7sq: RistrettoPoint,
    CG8sq: RistrettoPoint,

    // Fields for the inequality proof
    // blockages <= MAX_BLOCKAGES[level]
    CH1: RistrettoPoint,
    CH2: RistrettoPoint,
    CH0sq: RistrettoPoint,
    CH1sq: RistrettoPoint,
    CH2sq: RistrettoPoint,

    // Fields for user blinding of the Lox credential to be issued
    CommitLoxBlind: RistrettoPoint,

    // The combined ZKP
    piUser: CompactProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    s: Scalar,
    id_client: Scalar,
    bucket: Scalar,
    level: Scalar,
    invremain: Scalar,
    blockages: Scalar,
}

#[derive(Serialize, Clone, Deserialize)]
pub struct Response {
    // The fields for the new Lox credential; the new trust level is one
    // more than the old trust level, so we don't have to include it
    // here explicitly
    P: RistrettoPoint,
    BlindLoxQ: RistrettoPoint,
    level_since: Scalar,
    server_id: Scalar,

    // The ZKP
    piBlindIssue: CompactProof,
}

define_proof! {
    requestproof,
    "Level Upgrade Request",
    (bucket, since, invremain, blockages, zbucket, zsince, zinvremain,
     zblockages, negzQ,
     zbucket_reach, negzQ_reach,
     s, id_client,
     g0, g1, g2, g3, g4, g5, g6, g7, g8,
     zg0, zg1, zg2, zg3, zg4, zg5, zg6, zg7, zg8,
     wg0, wg1, wg2, wg3, wg4, wg5, wg6, wg7, wg8,
     yg0, yg1, yg2, yg3, yg4, yg5, yg6, yg7, yg8,
     h0, h1, h2,
     zh0, zh1, zh2,
     wh0, wh1, wh2,
     yh0, yh1, yh2),
    (P, CBucket, CSince, CInvRemain, CBlockages, V, Xid, Xbucket, Xsince,
     Xinvremain, Xblockages,
     P_reach, CBucket_reach, V_reach, Xbucket_reach,
     CommitLoxBlind,
     CG0, CG1, CG2, CG3, CG4, CG5, CG6, CG7, CG8,
     CG0sq, CG1sq, CG2sq, CG3sq, CG4sq, CG5sq, CG6sq, CG7sq, CG8sq,
     CH0, CH1, CH2,
     CH0sq, CH1sq, CH2sq),
    (A) :
    // Blind showing of the Lox credential
    CBucket = (bucket*P + zbucket*A),
    CSince = (since*P + zsince*A),
    CInvRemain = (invremain*P + zinvremain*A),
    CBlockages = (blockages*P + zblockages*A),
    // Blind showing of the Bucket Reachability credential; note the
    // same bucket is used in the proof
    CBucket_reach = (bucket*P_reach + zbucket_reach*A),
    // User blinding of the Lox credential to be issued
    CommitLoxBlind = (s*A + id_client * Xid + bucket * Xbucket + blockages * Xblockages),
    // Prove CSince encodes a value at least LEVEL_INTERVAL
    // days ago (and technically at most LEVEL_INTERVAL+511 days
    // ago): first prove each of g0, ..., g8 is a bit by proving that
    // gi = gi^2
    CG0 = (g0*P + zg0*A), CG0sq = (g0*CG0 + wg0*A), CG0sq = (g0*P + yg0*A),
    CG1 = (g1*P + zg1*A), CG1sq = (g1*CG1 + wg1*A), CG1sq = (g1*P + yg1*A),
    CG2 = (g2*P + zg2*A), CG2sq = (g2*CG2 + wg2*A), CG2sq = (g2*P + yg2*A),
    CG3 = (g3*P + zg3*A), CG3sq = (g3*CG3 + wg3*A), CG3sq = (g3*P + yg3*A),
    CG4 = (g4*P + zg4*A), CG4sq = (g4*CG4 + wg4*A), CG4sq = (g4*P + yg4*A),
    CG5 = (g5*P + zg5*A), CG5sq = (g5*CG5 + wg5*A), CG5sq = (g5*P + yg5*A),
    CG6 = (g6*P + zg6*A), CG6sq = (g6*CG6 + wg6*A), CG6sq = (g6*P + yg6*A),
    CG7 = (g7*P + zg7*A), CG7sq = (g7*CG7 + wg7*A), CG7sq = (g7*P + yg7*A),
    CG8 = (g8*P + zg8*A), CG8sq = (g8*CG8 + wg8*A), CG8sq = (g8*P + yg8*A),
    // Then we'll check that CSince + LEVEL_INTERVAL*P + CG0 + 2*CG1
    // + 4*CG2 + 8*CG3 + ... + 256*CG8 = today*P by having the verifier
    // plug in today*P - (CSince + LEVEL_INTERVAL*P + 2*CG1 + 4*CG2
    // + ... + 256*CG8) as its value of CG0.

    // Prove CBlockage encodes a value at most MAX_BLOCKAGES (and at least
    // MAX_BLOCKAGES-7)
    CH0 = (h0*P + zh0*A), CH0sq = (h0*CH0 + wh0*A), CH0sq = (h0*P + yh0*A),
    CH1 = (h1*P + zh1*A), CH1sq = (h1*CH1 + wh1*A), CH1sq = (h1*P + yh1*A),
    CH2 = (h2*P + zh2*A), CH2sq = (h2*CH2 + wh2*A), CH2sq = (h2*P + yh2*A)
    // Then we'll check that CBlockage + CH0 + 2*CH1 + 4*CH2 =
    // MAX_BLOCKAGES*P by having the verifier plug in MAX_BLOCKAGES*P -
    // (CBlockage - 2*CH1 - 4*CH2) as its value of CH0.
}

define_proof! {
    blindissue,
    "Level Upgrade Issuing",
    (x0, x0tilde, xlevel, xsince, xinvremain,  b),
    (P, BlindLoxQ, X0, Xlevel, Xsince, Xinvremain,
     Plevel, Psince, Pinvremain, CommitLoxBlind),
    (A, B):
    Xlevel = (xlevel*A),
    Xsince = (xsince*A),
    Xinvremain = (xinvremain*A),
    X0 = (x0*B + x0tilde*A),
    P = (b*A),
    BlindLoxQ = (b*CommitLoxBlind + x0 * P + xlevel * Plevel + xsince * Psince + xinvremain * Pinvremain)
}

pub fn request(
    lox_cred: &cred::Lox,
    reach_cred: &cred::BucketReachability,
    lox_pub: &IssuerPubKey,
    reach_pub: &IssuerPubKey,
    today: u32,
) -> Result<(Request, State), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;
    let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

    // Ensure the credential can be correctly shown: it must be the case
    // that level_since + LEVEL_INTERVAL[level] <= today.
    let level_since: u32 = match scalar_u32(&lox_cred.level_since) {
        Some(v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("level_since"),
                String::from("could not be converted to u32"),
            ))
        }
    };
    // The trust level has to be at least 1
    let trust_level: u32 = match scalar_u32(&lox_cred.trust_level) {
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
            format!("level {trust_level} not in range"),
        ));
    }
    // The trust level has to be no higher than the highest level
    let level_interval: u32 = match LEVEL_INTERVAL.get(trust_level as usize) {
        Some(&v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("trust_level"),
                format!("level {trust_level} not in range"),
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
    let blockages: u32 = match scalar_u32(&lox_cred.blockages) {
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
    let blockage_diff = MAX_BLOCKAGES[trust_level as usize] - blockages;
    // The buckets in the Lox and Bucket Reachability credentials have
    // to match
    if lox_cred.bucket != reach_cred.bucket {
        return Err(CredentialError::CredentialMismatch);
    }
    // The Bucket Reachability credential has to be dated today
    let reach_date: u32 = match scalar_u32(&reach_cred.date) {
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

    // Blind showing the Lox credential

    // Reblind P and Q
    let mut rng = rand::rngs::OsRng;
    let t = Scalar::random(&mut rng);
    let P = t * lox_cred.P;
    let Q = t * lox_cred.Q;

    // Form Pedersen commitments to the blinded attributes
    let zbucket = Scalar::random(&mut rng);
    let zsince = Scalar::random(&mut rng);
    let zinvremain = Scalar::random(&mut rng);
    let zblockages = Scalar::random(&mut rng);
    let CBucket = lox_cred.bucket * P + &zbucket * Atable;
    let CSince = lox_cred.level_since * P + &zsince * Atable;
    let CInvRemain = lox_cred.invites_remaining * P + &zinvremain * Atable;
    let CBlockages = lox_cred.blockages * P + &zblockages * Atable;

    // Form a Pedersen commitment to the MAC Q
    // We flip the sign of zQ from that of the Hyphae paper so that
    // the ZKP has a "+" instead of a "-", as that's what the zkp
    // macro supports.
    let negzQ = Scalar::random(&mut rng);
    let CQ = Q - &negzQ * Atable;

    // Compute the "error factor"
    let V = zbucket * lox_pub.X[2]
        + zsince * lox_pub.X[4]
        + zinvremain * lox_pub.X[5]
        + zblockages * lox_pub.X[6]
        + &negzQ * Atable;

    // Blind showing the Bucket Reachability credential

    // Reblind P and Q
    let t_reach = Scalar::random(&mut rng);
    let P_reach = t_reach * reach_cred.P;
    let Q_reach = t_reach * reach_cred.Q;

    // Form Pedersen commitments to the blinded attributes
    let zbucket_reach = Scalar::random(&mut rng);
    let CBucket_reach = reach_cred.bucket * P_reach + &zbucket_reach * Atable;

    // Form a Pedersen commitment to the MAC Q
    // We flip the sign of zQ from that of the Hyphae paper so that
    // the ZKP has a "+" instead of a "-", as that's what the zkp
    // macro supports.
    let negzQ_reach = Scalar::random(&mut rng);
    let CQ_reach = Q_reach - &negzQ_reach * Atable;

    // Compute the "error factor"
    let V_reach = zbucket_reach * reach_pub.X[2] + &negzQ_reach * Atable;

    // User blinding for the Lox certificate to be issued

    // Pick a random client component of the id
    let id_client = Scalar::random(&mut rng);

    // Pick a scalar to randomize our commitment
    let s = Scalar::random(&mut rng);
    // Commit to the new credential values with sum(m_i*X_i) + s * A
    // where A is our generator
    let CommitLoxBlind = s * A
        + (id_client * lox_pub.X[1]
            + lox_cred.bucket * lox_pub.X[2]
            + lox_cred.blockages * lox_pub.X[6]);

    let newinvites: Scalar = LEVEL_INVITATIONS[trust_level as usize].into();

    // The range proof that 0 <= diffdays <= 511

    // Extract the 9 bits from diffdays
    let g0: Scalar = (diffdays & 1).into();
    let g1: Scalar = ((diffdays >> 1) & 1).into();
    let g2: Scalar = ((diffdays >> 2) & 1).into();
    let g3: Scalar = ((diffdays >> 3) & 1).into();
    let g4: Scalar = ((diffdays >> 4) & 1).into();
    let g5: Scalar = ((diffdays >> 5) & 1).into();
    let g6: Scalar = ((diffdays >> 6) & 1).into();
    let g7: Scalar = ((diffdays >> 7) & 1).into();
    let g8: Scalar = ((diffdays >> 8) & 1).into();

    // Pick random factors for the Pedersen commitments
    let wg0 = Scalar::random(&mut rng);
    let zg1 = Scalar::random(&mut rng);
    let wg1 = Scalar::random(&mut rng);
    let zg2 = Scalar::random(&mut rng);
    let wg2 = Scalar::random(&mut rng);
    let zg3 = Scalar::random(&mut rng);
    let wg3 = Scalar::random(&mut rng);
    let zg4 = Scalar::random(&mut rng);
    let wg4 = Scalar::random(&mut rng);
    let zg5 = Scalar::random(&mut rng);
    let wg5 = Scalar::random(&mut rng);
    let zg6 = Scalar::random(&mut rng);
    let wg6 = Scalar::random(&mut rng);
    let zg7 = Scalar::random(&mut rng);
    let wg7 = Scalar::random(&mut rng);
    let zg8 = Scalar::random(&mut rng);
    let wg8 = Scalar::random(&mut rng);

    // Compute zg0 to cancel things out as
    // zg0 = -(zsince + 2*zg1 + 4*zg2 + 8*zg3 + 16*zg4 + 32*zg5 + 64*zg6 + 128*zg7 + 256*zg8)
    // but use Horner's method
    let zg0 = -(scalar_dbl(
        &(scalar_dbl(
            &(scalar_dbl(
                &(scalar_dbl(
                    &(scalar_dbl(
                        &(scalar_dbl(&(scalar_dbl(&(scalar_dbl(&zg8) + zg7)) + zg6)) + zg5),
                    ) + zg4),
                ) + zg3),
            ) + zg2),
        ) + zg1),
    ) + zsince);

    let yg0 = wg0 + g0 * zg0;
    let yg1 = wg1 + g1 * zg1;
    let yg2 = wg2 + g2 * zg2;
    let yg3 = wg3 + g3 * zg3;
    let yg4 = wg4 + g4 * zg4;
    let yg5 = wg5 + g5 * zg5;
    let yg6 = wg6 + g6 * zg6;
    let yg7 = wg7 + g7 * zg7;
    let yg8 = wg8 + g8 * zg8;

    let CG0 = g0 * P + &zg0 * Atable;
    let CG1 = g1 * P + &zg1 * Atable;
    let CG2 = g2 * P + &zg2 * Atable;
    let CG3 = g3 * P + &zg3 * Atable;
    let CG4 = g4 * P + &zg4 * Atable;
    let CG5 = g5 * P + &zg5 * Atable;
    let CG6 = g6 * P + &zg6 * Atable;
    let CG7 = g7 * P + &zg7 * Atable;
    let CG8 = g8 * P + &zg8 * Atable;

    let CG0sq = g0 * P + &yg0 * Atable;
    let CG1sq = g1 * P + &yg1 * Atable;
    let CG2sq = g2 * P + &yg2 * Atable;
    let CG3sq = g3 * P + &yg3 * Atable;
    let CG4sq = g4 * P + &yg4 * Atable;
    let CG5sq = g5 * P + &yg5 * Atable;
    let CG6sq = g6 * P + &yg6 * Atable;
    let CG7sq = g7 * P + &yg7 * Atable;
    let CG8sq = g8 * P + &yg8 * Atable;

    // The range proof that 0 <= blockage_diff <= 7

    // Extract the 3 bits from blockage_diff
    let h0: Scalar = (blockage_diff & 1).into();
    let h1: Scalar = ((blockage_diff >> 1) & 1).into();
    let h2: Scalar = ((blockage_diff >> 2) & 1).into();

    // Pick random factors for the Pedersen commitments
    let wh0 = Scalar::random(&mut rng);
    let zh1 = Scalar::random(&mut rng);
    let wh1 = Scalar::random(&mut rng);
    let zh2 = Scalar::random(&mut rng);
    let wh2 = Scalar::random(&mut rng);

    // Compute zh0 to cancel things out as
    // zh0 = -(zblockages + 2*zh1 + 4*zh2)
    // but use Horner's method
    let zh0 = -(scalar_dbl(&(scalar_dbl(&zh2) + zh1)) + zblockages);

    let yh0 = wh0 + h0 * zh0;
    let yh1 = wh1 + h1 * zh1;
    let yh2 = wh2 + h2 * zh2;

    let CH0 = h0 * P + &zh0 * Atable;
    let CH1 = h1 * P + &zh1 * Atable;
    let CH2 = h2 * P + &zh2 * Atable;

    let CH0sq = h0 * P + &yh0 * Atable;
    let CH1sq = h1 * P + &yh1 * Atable;
    let CH2sq = h2 * P + &yh2 * Atable;

    // Construct the proof
    let mut transcript = Transcript::new(b"level upgrade request");
    let piUser = requestproof::prove_compact(
        &mut transcript,
        requestproof::ProveAssignments {
            A,
            P: &P,
            CBucket: &CBucket,
            CSince: &CSince,
            CInvRemain: &CInvRemain,
            CBlockages: &CBlockages,
            V: &V,
            Xbucket: &lox_pub.X[2],
            Xsince: &lox_pub.X[4],
            Xinvremain: &lox_pub.X[5],
            Xblockages: &lox_pub.X[6],
            P_reach: &P_reach,
            CBucket_reach: &CBucket_reach,
            V_reach: &V_reach,
            Xbucket_reach: &reach_pub.X[2],
            CG0: &CG0,
            CG1: &CG1,
            CG2: &CG2,
            CG3: &CG3,
            CG4: &CG4,
            CG5: &CG5,
            CG6: &CG6,
            CG7: &CG7,
            CG8: &CG8,
            CG0sq: &CG0sq,
            CG1sq: &CG1sq,
            CG2sq: &CG2sq,
            CG3sq: &CG3sq,
            CG4sq: &CG4sq,
            CG5sq: &CG5sq,
            CG6sq: &CG6sq,
            CG7sq: &CG7sq,
            CG8sq: &CG8sq,
            CH0: &CH0,
            CH1: &CH1,
            CH2: &CH2,
            CH0sq: &CH0sq,
            CH1sq: &CH1sq,
            CH2sq: &CH2sq,
            bucket: &lox_cred.bucket,
            since: &lox_cred.level_since,
            invremain: &lox_cred.invites_remaining,
            blockages: &lox_cred.blockages,
            zbucket: &zbucket,
            zsince: &zsince,
            zinvremain: &zinvremain,
            zblockages: &zblockages,
            negzQ: &negzQ,
            zbucket_reach: &zbucket_reach,
            negzQ_reach: &negzQ_reach,
            s: &s,
            Xid: &lox_pub.X[1],
            CommitLoxBlind: &CommitLoxBlind,
            id_client: &id_client,
            g0: &g0,
            g1: &g1,
            g2: &g2,
            g3: &g3,
            g4: &g4,
            g5: &g5,
            g6: &g6,
            g7: &g7,
            g8: &g8,
            zg0: &zg0,
            zg1: &zg1,
            zg2: &zg2,
            zg3: &zg3,
            zg4: &zg4,
            zg5: &zg5,
            zg6: &zg6,
            zg7: &zg7,
            zg8: &zg8,
            wg0: &wg0,
            wg1: &wg1,
            wg2: &wg2,
            wg3: &wg3,
            wg4: &wg4,
            wg5: &wg5,
            wg6: &wg6,
            wg7: &wg7,
            wg8: &wg8,
            yg0: &yg0,
            yg1: &yg1,
            yg2: &yg2,
            yg3: &yg3,
            yg4: &yg4,
            yg5: &yg5,
            yg6: &yg6,
            yg7: &yg7,
            yg8: &yg8,
            h0: &h0,
            h1: &h1,
            h2: &h2,
            zh0: &zh0,
            zh1: &zh1,
            zh2: &zh2,
            wh0: &wh0,
            wh1: &wh1,
            wh2: &wh2,
            yh0: &yh0,
            yh1: &yh1,
            yh2: &yh2,
        },
    )
    .0;
    #[cfg(feature = "dump")]
    let duration = now.elapsed();
    #[cfg(feature = "dump")]
    let _dumper = if cfg!(feature = "dump") {
        dump(&format!("level-up client request time {:#?}", duration));
    };

    Ok((
        Request {
            P,
            id: lox_cred.id,
            CBucket,
            level: lox_cred.trust_level,
            CSince,
            CInvRemain,
            CBlockages,
            CQ,
            P_reach,
            CBucket_reach,
            CQ_reach,
            CG1,
            CG2,
            CG3,
            CG4,
            CG5,
            CG6,
            CG7,
            CG8,
            CG0sq,
            CG1sq,
            CG2sq,
            CG3sq,
            CG4sq,
            CG5sq,
            CG6sq,
            CG7sq,
            CG8sq,
            CH1,
            CH2,
            CH0sq,
            CH1sq,
            CH2sq,
            CommitLoxBlind,
            piUser,
        },
        State {
            s,
            id_client,
            bucket: lox_cred.bucket,
            level: new_level.into(),
            invremain: newinvites,
            blockages: lox_cred.blockages,
        },
    ))
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    /// Receive a level up request
    pub fn handle_level_up(&mut self, req: Request) -> Result<Response, ProofError> {
        let A: &RistrettoPoint = &CMZ_A;
        let B: &RistrettoPoint = &CMZ_B;
        let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

        if req.P.is_identity() || req.P_reach.is_identity() {
            return Err(ProofError::VerificationFailure);
        }

        let today: Scalar = self.today().into();

        // Get the level and ensure it's at most MAX_LEVEL
        let level: usize = match scalar_u32(&req.level) {
            Some(l) if l as usize <= MAX_LEVEL => l as usize,
            _ => return Err(ProofError::VerificationFailure),
        };

        // Recompute the "error factors" using knowledge of our own
        // (the issuer's) private key instead of knowledge of the
        // hidden attributes
        let Vprime =
            (self.lox_priv.x[0] + self.lox_priv.x[1] * req.id + self.lox_priv.x[3] * req.level)
                * req.P
                + self.lox_priv.x[2] * req.CBucket
                + self.lox_priv.x[4] * req.CSince
                + self.lox_priv.x[5] * req.CInvRemain
                + self.lox_priv.x[6] * req.CBlockages
                - req.CQ;

        let Vprime_reach = (self.reachability_priv.x[0] + self.reachability_priv.x[1] * today)
            * req.P_reach
            + self.reachability_priv.x[2] * req.CBucket_reach
            - req.CQ_reach;

        // Recompute CG0 using Horner's method
        let interval: Scalar = LEVEL_INTERVAL[level].into();
        let CG0prime = (today - interval) * req.P
            - req.CSince
            - pt_dbl(
                &(pt_dbl(
                    &(pt_dbl(
                        &(pt_dbl(
                            &(pt_dbl(
                                &(pt_dbl(&(pt_dbl(&(pt_dbl(&req.CG8) + req.CG7)) + req.CG6))
                                    + req.CG5),
                            ) + req.CG4),
                        ) + req.CG3),
                    ) + req.CG2),
                ) + req.CG1),
            );

        // Recompute CH0 using Horner's method
        let mblk: Scalar = MAX_BLOCKAGES[level].into();
        let CH0prime = mblk * req.P - req.CBlockages - pt_dbl(&(pt_dbl(&req.CH2) + req.CH1));

        // Verify the ZKP
        let mut transcript = Transcript::new(b"level upgrade request");
        requestproof::verify_compact(
            &req.piUser,
            &mut transcript,
            requestproof::VerifyAssignments {
                A: &A.compress(),
                P: &req.P.compress(),
                CBucket: &req.CBucket.compress(),
                CSince: &req.CSince.compress(),
                CInvRemain: &req.CInvRemain.compress(),
                CBlockages: &req.CBlockages.compress(),
                V: &Vprime.compress(),
                Xid: &self.lox_pub.X[1].compress(),
                Xbucket: &self.lox_pub.X[2].compress(),
                Xsince: &self.lox_pub.X[4].compress(),
                Xinvremain: &self.lox_pub.X[5].compress(),
                Xblockages: &self.lox_pub.X[6].compress(),
                P_reach: &req.P_reach.compress(),
                CBucket_reach: &req.CBucket_reach.compress(),
                V_reach: &Vprime_reach.compress(),
                Xbucket_reach: &self.reachability_pub.X[2].compress(),
                CommitLoxBlind: &req.CommitLoxBlind.compress(),
                CG0: &CG0prime.compress(),
                CG1: &req.CG1.compress(),
                CG2: &req.CG2.compress(),
                CG3: &req.CG3.compress(),
                CG4: &req.CG4.compress(),
                CG5: &req.CG5.compress(),
                CG6: &req.CG6.compress(),
                CG7: &req.CG7.compress(),
                CG8: &req.CG8.compress(),
                CG0sq: &req.CG0sq.compress(),
                CG1sq: &req.CG1sq.compress(),
                CG2sq: &req.CG2sq.compress(),
                CG3sq: &req.CG3sq.compress(),
                CG4sq: &req.CG4sq.compress(),
                CG5sq: &req.CG5sq.compress(),
                CG6sq: &req.CG6sq.compress(),
                CG7sq: &req.CG7sq.compress(),
                CG8sq: &req.CG8sq.compress(),
                CH0: &CH0prime.compress(),
                CH1: &req.CH1.compress(),
                CH2: &req.CH2.compress(),
                CH0sq: &req.CH0sq.compress(),
                CH1sq: &req.CH1sq.compress(),
                CH2sq: &req.CH2sq.compress(),
            },
        )?;

        // Ensure the id has not been seen before, and add it to the
        // seen list.
        if self.id_filter.filter(&req.id) == SeenType::Seen {
            return Err(ProofError::VerificationFailure);
        }

        // Blind issuing of the new Lox credential

        let mut rng = rand::rngs::OsRng;

        // Create the trust_level attrubute (Scalar), which will be
        // one more than the current level, unless the current level is
        // MAX_LEVEL, in which case it stays the same
        let new_level = if level < MAX_LEVEL { level + 1 } else { level };
        let trust_level: Scalar = (new_level as u64).into();

        // Create the level_since attribute (Scalar), which is today's
        // Julian date
        let level_since: Scalar = self.today().into();

        // Create the invitations_remaining attribute (Scalar), which is
        // the number of invitations at the new level
        let invitations_remaining: Scalar = LEVEL_INVITATIONS[level].into();

        // Compute the MAC on the visible and blinded attributes
        let b = Scalar::random(&mut rng);
        let P = &b * Atable;

        // Create server contribution of the Lox id
        let server_id = Scalar::random(&mut rng);

        // Append the server id to the client's commitment
        let CommitLoxSrv = req.CommitLoxBlind + (server_id * self.lox_pub.X[1]);

        let BlindLoxQ = b * CommitLoxSrv
            + (self.lox_priv.x[0]
                + trust_level * self.lox_priv.x[3]
                + level_since * self.lox_priv.x[4]
                + invitations_remaining * self.lox_priv.x[5])
                * P;

        let mut transcript = Transcript::new(b"level upgrade issuing");
        let piBlindIssue = blindissue::prove_compact(
            &mut transcript,
            blindissue::ProveAssignments {
                A,
                B,
                P: &P,
                X0: &self.lox_pub.X[0],
                Xlevel: &self.lox_pub.X[3],
                Xsince: &self.lox_pub.X[4],
                Xinvremain: &self.lox_pub.X[5],
                Plevel: &(trust_level * P),
                Psince: &(level_since * P),
                Pinvremain: &(invitations_remaining * P),
                x0: &self.lox_priv.x[0],
                x0tilde: &self.lox_priv.x0tilde,
                xlevel: &self.lox_priv.x[3],
                xsince: &self.lox_priv.x[4],
                xinvremain: &self.lox_priv.x[5],
                b: &b,
                BlindLoxQ: &BlindLoxQ,
                CommitLoxBlind: &CommitLoxSrv,
            },
        )
        .0;

        Ok(Response {
            P,
            BlindLoxQ,
            server_id,
            level_since,
            piBlindIssue,
        })
    }
}

/// Handle the response to the request, producing the new Lox credential
/// if successful.
pub fn handle_response(
    state: State,
    resp: Response,
    lox_pub: &IssuerPubKey,
) -> Result<cred::Lox, ProofError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;
    let B: &RistrettoPoint = &CMZ_B;

    if resp.P.is_identity() {
        return Err(ProofError::VerificationFailure);
    }

    // Verify the proof
    let mut transcript = Transcript::new(b"level upgrade issuing");
    blindissue::verify_compact(
        &resp.piBlindIssue,
        &mut transcript,
        blindissue::VerifyAssignments {
            A: &A.compress(),
            B: &B.compress(),
            P: &resp.P.compress(),
            X0: &lox_pub.X[0].compress(),
            Xlevel: &lox_pub.X[3].compress(),
            Xsince: &lox_pub.X[4].compress(),
            Xinvremain: &lox_pub.X[5].compress(),
            Plevel: &(state.level * resp.P).compress(),
            Psince: &(resp.level_since * resp.P).compress(),
            Pinvremain: &(state.invremain * resp.P).compress(),
            BlindLoxQ: &resp.BlindLoxQ.compress(),
            CommitLoxBlind: &(state.s * A
                + state.id_client * lox_pub.X[1]
                + resp.server_id * lox_pub.X[1]
                + state.bucket * lox_pub.X[2]
                + state.blockages * lox_pub.X[6])
                .compress(),
        },
    )?;

    // Decrypt BlindLoxQ
    let mut rng = rand::rngs::OsRng;
    let r = Scalar::random(&mut rng);
    let Q = r * (resp.BlindLoxQ - state.s * resp.P);

    #[cfg(feature = "dump")]
    let duration = now.elapsed();
    #[cfg(feature = "dump")]
    let _dumper = if cfg!(feature = "dump") {
        dump(&format!("level-up client handle time {:#?}", duration));
    };
    Ok(cred::Lox {
        P: r * resp.P,
        Q,
        id: state.id_client + resp.server_id,
        bucket: state.bucket,
        trust_level: state.level,
        level_since: resp.level_since,
        invites_remaining: state.invremain,
        blockages: state.blockages,
    })
}

#[cfg(all(test, feature = "bridgeauth"))]
mod tests {
    use crate::mock_auth::TestHarness;

    #[test]
    fn test_artifact_level_up() {
        println!("\n----LEVEL-UP-2: 44 days----\n");
        let mut th = TestHarness::new();
        let invite = th.bdb.invite().unwrap();
        let (_, lox_cred) = th.open_invite(&invite);
        let (_, mig_cred) = th.trust_promotion(lox_cred.0.clone());
        let (_, lox_cred_new) = th.migration(lox_cred.0.clone(), mig_cred.clone());
        let (perf_stat, lox_cred) = th.level_up(lox_cred_new.clone());
        th.verify_lox(&lox_cred);
        th.print_test_results(perf_stat);
    }
}
