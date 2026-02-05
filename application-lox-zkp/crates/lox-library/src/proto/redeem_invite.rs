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

use super::errors::CredentialError;
#[cfg(feature = "dump")]
use crate::dumper::dump;
use web_time::Instant;

/// Invitations must be used within this many days of being issued.
/// Note that if you change this number to be larger than 15, you must
/// also add bits to the zero knowledge proof.
pub const INVITATION_EXPIRY: u32 = 15;

#[derive(Serialize, Clone, Deserialize)]
pub struct Request {
    // Fields for showing the Invitation credential
    P: RistrettoPoint,
    inv_id: Scalar,
    CDate: RistrettoPoint,
    CBucket: RistrettoPoint,
    CBlockages: RistrettoPoint,
    CQ: RistrettoPoint,

    // Fields for the inequality proof
    // date + INVITATION_EXPIRY >= today
    CG1: RistrettoPoint,
    CG2: RistrettoPoint,
    CG3: RistrettoPoint,
    CG0sq: RistrettoPoint,
    CG1sq: RistrettoPoint,
    CG2sq: RistrettoPoint,
    CG3sq: RistrettoPoint,
    // Commitment to the Lox credential to be issued
    CommitLoxBlind: RistrettoPoint,

    // The combined ZKP
    piUser: CompactProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    s: Scalar,
    id_client: Scalar,
    bucket: Scalar,
    blockages: Scalar,
}

#[derive(Serialize, Clone, Deserialize)]
pub struct Response {
    // The fields for the new Lox credential; the new trust level is 1
    // and the new invites_remaining is 0, so we don't have to include
    // them here explicitly
    P: RistrettoPoint,
    BlindLoxQ: RistrettoPoint,
    server_id: Scalar,
    level_since: Scalar,

    // The ZKP
    piBlindIssue: CompactProof,
}

define_proof! {
    requestproof,
    "Redeem Invite Request",
    (date, bucket, blockages, zdate, zbucket, zblockages, negzQ,
    s, id_client,
     g0, g1, g2, g3,
     zg0, zg1, zg2, zg3,
     wg0, wg1, wg2, wg3,
     yg0, yg1, yg2, yg3),
    (P, CDate, CBucket, CBlockages, V, Xinv_date, Xinv_bucket, Xinv_blockages,
     Xid, Xbucket, Xblockages, CommitLoxBlind,
     CG0, CG1, CG2, CG3,
     CG0sq, CG1sq, CG2sq, CG3sq),
    (A):
    // Blind showing of the Invitation credential
    CDate = (date*P + zdate*A),
    CBucket = (bucket*P + zbucket*A),
    CBlockages = (blockages*P + zblockages*A),
    // User blinding of the Lox credential to be issue
    CommitLoxBlind = (s * A + id_client * Xid + bucket * Xbucket + blockages * Xblockages),
    // Prove CDate encodes a value at most INVITATION_EXPIRY
    // days ago: first prove each of g0, ..., g3 is a bit by
    // proving that gi = gi^2
    CG0 = (g0*P + zg0*A), CG0sq = (g0*CG0 + wg0*A), CG0sq = (g0*P + yg0*A),
    CG1 = (g1*P + zg1*A), CG1sq = (g1*CG1 + wg1*A), CG1sq = (g1*P + yg1*A),
    CG2 = (g2*P + zg2*A), CG2sq = (g2*CG2 + wg2*A), CG2sq = (g2*P + yg2*A),
    CG3 = (g3*P + zg3*A), CG3sq = (g3*CG3 + wg3*A), CG3sq = (g3*P + yg3*A)
    // Then we'll check that today*P + CG0 + 2*CG1 + 4*CG2 + 8*CG3 =
    // CDate + INVITATION_EXPIRY*P by having the verifier
    // plug in CDate + INVITATION_EXPIRY*P - (today*P + 2*CG1 + 4*CG2
    // + 8*CG3) as its value of CG0.
}

define_proof! {
    blindissue,
    "Redeem Invite Issuing",
    (x0, x0tilde, xid, xbucket, xlevel, xsince, xblockages, b),
    (P, BlindLoxQ, X0, Xlevel, Xsince,
    Plevel, Psince, CommitLoxBlind),
    (A, B):
    Xlevel = (xlevel*A),
    Xsince = (xsince*A),
    X0 = (x0*B + x0tilde*A),
    P = (b*A),
    BlindLoxQ = (b*CommitLoxBlind + x0*P + xlevel*Plevel + xsince * Psince)
}

pub fn request(
    inv_cred: &cred::Invitation,
    lox_pub: &IssuerPubKey,
    invitation_pub: &IssuerPubKey,
    today: u32,
) -> Result<(Request, State), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();

    let A: &RistrettoPoint = &CMZ_A;
    let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

    // Ensure the credential can be correctly shown: it must be the case
    // that date + INVITATION_EXPIRY >= today.
    let date: u32 = match scalar_u32(&inv_cred.date) {
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

    // Blind showing the Invitation credential

    // Reblind P and Q
    let mut rng = rand::rngs::OsRng;
    let t = Scalar::random(&mut rng);
    let P = t * inv_cred.P;
    let Q = t * inv_cred.Q;

    // Form Pedersen commitments to the blinded attributes
    let zdate = Scalar::random(&mut rng);
    let zbucket = Scalar::random(&mut rng);
    let zblockages = Scalar::random(&mut rng);
    let CDate = inv_cred.date * P + &zdate * Atable;
    let CBucket = inv_cred.bucket * P + &zbucket * Atable;
    let CBlockages = inv_cred.blockages * P + &zblockages * Atable;

    // Form a Pedersen commitment to the MAC Q
    // We flip the sign of zQ from that of the Hyphae paper so that
    // the ZKP has a "+" instead of a "-", as that's what the zkp
    // macro supports.
    let negzQ = Scalar::random(&mut rng);
    let CQ = Q - &negzQ * Atable;

    // Compute the "error factor"
    let V = zdate * invitation_pub.X[2]
        + zbucket * invitation_pub.X[3]
        + zblockages * invitation_pub.X[4]
        + &negzQ * Atable;

    // User blinding for the Lox certificate to be issued

    // Pick a random client component of the id
    let id_client = Scalar::random(&mut rng);

    // Pick a scalar to randomize our commitment
    let s = Scalar::random(&mut rng);

    // Commit to the new credential values with sum(m_i*X_i) + s * A
    // where A is our generator
    let CommitLoxBlind = s * A
        + id_client * lox_pub.X[1]
        + inv_cred.bucket * lox_pub.X[2]
        + inv_cred.blockages * lox_pub.X[6];

    // The range proof that 0 <= diffdays <= 15

    // Extract the 4 bits from diffdays
    let g0: Scalar = (diffdays & 1).into();
    let g1: Scalar = ((diffdays >> 1) & 1).into();
    let g2: Scalar = ((diffdays >> 2) & 1).into();
    let g3: Scalar = ((diffdays >> 3) & 1).into();

    // Pick random factors for the Pedersen commitments
    let wg0 = Scalar::random(&mut rng);
    let zg1 = Scalar::random(&mut rng);
    let wg1 = Scalar::random(&mut rng);
    let zg2 = Scalar::random(&mut rng);
    let wg2 = Scalar::random(&mut rng);
    let zg3 = Scalar::random(&mut rng);
    let wg3 = Scalar::random(&mut rng);

    // Compute zg0 to cancel things out as
    // zg0 = zdate - (2*zg1 + 4*zg2 + 8*zg3)
    // but use Horner's method
    let zg0 = zdate - scalar_dbl(&(scalar_dbl(&(scalar_dbl(&zg3) + zg2)) + zg1));

    let yg0 = wg0 + g0 * zg0;
    let yg1 = wg1 + g1 * zg1;
    let yg2 = wg2 + g2 * zg2;
    let yg3 = wg3 + g3 * zg3;

    let CG0 = g0 * P + &zg0 * Atable;
    let CG1 = g1 * P + &zg1 * Atable;
    let CG2 = g2 * P + &zg2 * Atable;
    let CG3 = g3 * P + &zg3 * Atable;

    let CG0sq = g0 * P + &yg0 * Atable;
    let CG1sq = g1 * P + &yg1 * Atable;
    let CG2sq = g2 * P + &yg2 * Atable;
    let CG3sq = g3 * P + &yg3 * Atable;

    // Construct the proof
    let mut transcript = Transcript::new(b"redeem invite request");
    let piUser = requestproof::prove_compact(
        &mut transcript,
        requestproof::ProveAssignments {
            A,
            P: &P,
            CDate: &CDate,
            CBucket: &CBucket,
            CBlockages: &CBlockages,
            V: &V,
            Xinv_date: &invitation_pub.X[2],
            Xinv_bucket: &invitation_pub.X[3],
            Xinv_blockages: &invitation_pub.X[4],
            CG0: &CG0,
            CG1: &CG1,
            CG2: &CG2,
            CG3: &CG3,
            CG0sq: &CG0sq,
            CG1sq: &CG1sq,
            CG2sq: &CG2sq,
            CG3sq: &CG3sq,
            date: &inv_cred.date,
            bucket: &inv_cred.bucket,
            blockages: &inv_cred.blockages,
            zdate: &zdate,
            zbucket: &zbucket,
            zblockages: &zblockages,
            negzQ: &negzQ,

            s: &s,
            id_client: &id_client,
            Xid: &lox_pub.X[1],
            Xbucket: &lox_pub.X[2],
            Xblockages: &lox_pub.X[6],
            CommitLoxBlind: &CommitLoxBlind,
            g0: &g0,
            g1: &g1,
            g2: &g2,
            g3: &g3,
            zg0: &zg0,
            zg1: &zg1,
            zg2: &zg2,
            zg3: &zg3,
            wg0: &wg0,
            wg1: &wg1,
            wg2: &wg2,
            wg3: &wg3,
            yg0: &yg0,
            yg1: &yg1,
            yg2: &yg2,
            yg3: &yg3,
        },
    )
    .0;
    #[cfg(feature = "dump")]
    let duration = now.elapsed();
    #[cfg(feature = "dump")]
    let _dumper = if cfg!(feature = "dump") {
        dump(&format!(
            "redeem-invite client request time {:#?}",
            duration
        ));
    };

    Ok((
        Request {
            P,
            inv_id: inv_cred.inv_id,
            CDate,
            CBucket,
            CBlockages,
            CQ,
            CG1,
            CG2,
            CG3,
            CG0sq,
            CG1sq,
            CG2sq,
            CG3sq,
            CommitLoxBlind,
            piUser,
        },
        State {
            s,
            id_client,
            bucket: inv_cred.bucket,
            blockages: inv_cred.blockages,
        },
    ))
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    /// Receive a redeem invite request
    pub fn handle_redeem_invite(&mut self, req: Request) -> Result<Response, ProofError> {
        let A: &RistrettoPoint = &CMZ_A;
        let B: &RistrettoPoint = &CMZ_B;
        let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

        if req.P.is_identity() {
            return Err(ProofError::VerificationFailure);
        }

        let today: Scalar = self.today().into();

        // Recompute the "error factor" using knowledge of our own
        // (the issuer's) private key instead of knowledge of the
        // hidden attributes
        let Vprime = (self.invitation_priv.x[0] + self.invitation_priv.x[1] * req.inv_id) * req.P
            + self.invitation_priv.x[2] * req.CDate
            + self.invitation_priv.x[3] * req.CBucket
            + self.invitation_priv.x[4] * req.CBlockages
            - req.CQ;

        // Recompute CG0 using Horner's method
        let expiry: Scalar = INVITATION_EXPIRY.into();
        let CG0prime = (expiry - today) * req.P + req.CDate
            - pt_dbl(&(pt_dbl(&(pt_dbl(&req.CG3) + req.CG2)) + req.CG1));

        // Verify the ZKP
        let mut transcript = Transcript::new(b"redeem invite request");
        requestproof::verify_compact(
            &req.piUser,
            &mut transcript,
            requestproof::VerifyAssignments {
                A: &A.compress(),
                P: &req.P.compress(),
                CDate: &req.CDate.compress(),
                CBucket: &req.CBucket.compress(),
                CBlockages: &req.CBlockages.compress(),
                V: &Vprime.compress(),
                CG0: &CG0prime.compress(),
                CG1: &req.CG1.compress(),
                CG2: &req.CG2.compress(),
                CG3: &req.CG3.compress(),
                CG0sq: &req.CG0sq.compress(),
                CG1sq: &req.CG1sq.compress(),
                CG2sq: &req.CG2sq.compress(),
                CG3sq: &req.CG3sq.compress(),
                Xinv_date: &self.invitation_pub.X[2].compress(),
                Xinv_bucket: &self.invitation_pub.X[3].compress(),
                Xinv_blockages: &self.invitation_pub.X[4].compress(),
                Xid: &self.lox_pub.X[1].compress(),
                Xbucket: &self.lox_pub.X[2].compress(),
                Xblockages: &self.lox_pub.X[6].compress(),
                CommitLoxBlind: &req.CommitLoxBlind.compress(),
            },
        )?;

        // Ensure the id has not been seen before, and add it to the
        // invite id seen list.
        if self.inv_id_filter.filter(&req.inv_id) == SeenType::Seen {
            return Err(ProofError::VerificationFailure);
        }

        // Blind issuing of the new Lox credential

        let mut rng = rand::rngs::OsRng;

        // The trust level for invitees is always 1
        let level = Scalar::ONE;

        // The invites remaining for invitees is always 0 (as
        // appropriate for trust level 1), so we don't need to actually
        // construct it

        // Compute the MAC on the visible attributes
        let b = Scalar::random(&mut rng);
        let P = &b * Atable;

        // Create server contribution of the Lox id
        let server_id = Scalar::random(&mut rng);

        // Append the server id to the client's commitment
        let CommitLoxSrv = req.CommitLoxBlind + (server_id * self.lox_pub.X[1]);

        let BlindLoxQ = b * CommitLoxSrv
            + (self.lox_priv.x[0] + self.lox_priv.x[3] * level + self.lox_priv.x[4] * today) * P;

        let mut transcript = Transcript::new(b"redeem invite issuing");
        let piBlindIssue = blindissue::prove_compact(
            &mut transcript,
            blindissue::ProveAssignments {
                A,
                B,
                P: &P,
                X0: &self.lox_pub.X[0],
                Xlevel: &self.lox_pub.X[3],
                Xsince: &self.lox_pub.X[4],
                Plevel: &(level * P),
                Psince: &(today * P),
                x0: &self.lox_priv.x[0],
                x0tilde: &self.lox_priv.x0tilde,
                xid: &self.lox_priv.x[1],
                xbucket: &self.lox_priv.x[2],
                xlevel: &self.lox_priv.x[3],
                xsince: &self.lox_priv.x[4],
                xblockages: &self.lox_priv.x[6],
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
            level_since: today,
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
    let mut transcript = Transcript::new(b"redeem invite issuing");
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
            Plevel: &(Scalar::ONE * resp.P).compress(),
            Psince: &(resp.level_since * resp.P).compress(),
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
        dump(&format!("redeem-invite client handle time {:#?}", duration));
    };

    Ok(cred::Lox {
        P: r * resp.P,
        Q,
        id: state.id_client + resp.server_id,
        bucket: state.bucket,
        trust_level: Scalar::ONE,
        level_since: resp.level_since,
        invites_remaining: Scalar::ZERO,
        blockages: state.blockages,
    })
}

#[cfg(all(test, feature = "bridgeauth"))]
mod tests {
    use crate::mock_auth::TestHarness;

    #[test]
    fn test_artifact_redeem_invite() {
        println!("\n----REDEEM-INVITATION----\n");
        let mut th = TestHarness::new();
        let invite = th.bdb.invite().unwrap();
        let (_, lox_cred) = th.open_invite(&invite);
        let (_, mig_cred) = th.trust_promotion(lox_cred.0.clone());
        let (_, lox_cred) = th.migration(lox_cred.0.clone(), mig_cred.clone());
        let (_, lox_cred) = th.level_up(lox_cred.clone());
        let (_, issue_invite_cred) = th.issue_invite(lox_cred.clone());
        let (perf_stat, r_cred) = th.redeem_invite(issue_invite_cred.1);
        th.verify_lox(&r_cred);
        th.print_test_results(perf_stat);
    }
}
