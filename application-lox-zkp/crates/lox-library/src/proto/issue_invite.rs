/*! A module for the protocol for a user to request the issuing of an
Invitation credential they can pass to someone they know.

They are allowed to do this as long as their current Lox credentials has
a non-zero "invites_remaining" attribute (which will be decreased by
one), and they have a Bucket Reachability credential for their current
bucket and today's date.  (Such credentials are placed daily in the
encrypted bridge table.)

The user presents their current Lox credential:
- id: revealed
- bucket: blinded
- trust_level: blinded
- level_since: blinded
- invites_remaining: blinded, but proved in ZK that it's not zero
- blockages: blinded

and a Bucket Reachability credential:
- date: revealed to be today
- bucket: blinded, but proved in ZK that it's the same as in the Lox
  credential above

and a new Lox credential to be issued:

- id: jointly chosen by the user and BA
- bucket: blinded, but proved in ZK that it's the same as in the Lox
  credential above
- trust_level: blinded, but proved in ZK that it's the same as in the
  Lox credential above
- level_since: blinded, but proved in ZK that it's the same as in the
  Lox credential above
- invites_remaining: blinded, but proved in ZK that it's one less than
  the number in the Lox credential above
- blockages: blinded, but proved in ZK that it's the same as in the
  Lox credential above

and a new Invitation credential to be issued:

- inv_id: jointly chosen by the user and BA
- date: revealed to be today
- bucket: blinded, but proved in ZK that it's the same as in the Lox
  credential above
- blockages: blinded, but proved in ZK that it's the same as in the Lox
  credential above

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
use super::super::scalar_u32;
#[cfg(feature = "bridgeauth")]
use super::super::BridgeAuth;
use super::super::IssuerPubKey;
use super::super::{CMZ_A, CMZ_A_TABLE, CMZ_B};

use super::errors::CredentialError;
#[cfg(feature = "dump")]
use crate::dumper::dump;
#[cfg(feature = "dump")]
use web_time::Instant;

#[derive(Serialize, Clone, Deserialize)]
pub struct Request {
    // Fields for blind showing the Lox credential
    P: RistrettoPoint,
    id: Scalar,
    CBucket: RistrettoPoint,
    CLevel: RistrettoPoint,
    CSince: RistrettoPoint,
    CInvRemain: RistrettoPoint,
    CBlockages: RistrettoPoint,
    CQ: RistrettoPoint,

    // Fields for blind showing the Bucket Reachability credential
    P_reach: RistrettoPoint,
    CBucket_reach: RistrettoPoint,
    CQ_reach: RistrettoPoint,

    // Commitment to the Lox credential to be issued
    CommitLoxBlind: RistrettoPoint,

    // Commitment to the the Inivtation credential to be issued
    CommitInviteBlind: RistrettoPoint,

    // The combined ZKP
    piUser: CompactProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    s: Scalar,
    id_client: Scalar,
    bucket: Scalar,
    level: Scalar,
    since: Scalar,
    invremain: Scalar,
    blockages: Scalar,
    s_inv: Scalar,
    inv_id_client: Scalar,
}

#[derive(Serialize, Clone, Deserialize)]
pub struct Response {
    // The fields for the new Lox credential; the new invites_remaining
    // is one less than the old value, so we don't have to include it
    // here explicitly
    P: RistrettoPoint,
    BlindLoxQ: RistrettoPoint,
    server_id: Scalar,
    // The fields for the new Invitation credential
    P_inv: RistrettoPoint,
    BlindInviteQ: RistrettoPoint,
    server_inv_id: Scalar,
    date_inv: Scalar,

    // The ZKP
    piBlindIssue: CompactProof,
}

define_proof! {
    requestproof,
    "Issue Invite Request",
    (bucket, level, since, invremain, blockages, zbucket, zlevel,
     zsince, zinvremain, zblockages, negzQ,
     zbucket_reach, negzQ_reach,
     s, id_client, new_invites_remaining,
     s_inv, inv_id_client,
     invremain_inverse, zinvremain_inverse),
    (P, CBucket, CLevel, CSince, CInvRemain, CBlockages, V, Xid, Xbucket,
     Xlevel, Xsince, Xinvremain, Xblockages,
     P_reach, CBucket_reach, V_reach, Xbucket_reach, Xinv_id, Xinv_bucket, Xinv_blockages,
     CommitLoxBlind, CommitInviteBlind),
    (A):
    // Blind showing of the Lox credential
    CBucket = (bucket*P + zbucket*A),
    CLevel = (level*P + zlevel*A),
    CSince = (since*P + zsince*A),
    CInvRemain = (invremain*P + zinvremain*A),
    CBlockages = (blockages*P + zblockages*A),
    // Proof that invremain is not 0
    P = (invremain_inverse*CInvRemain + zinvremain_inverse*A),
    // Blind showing of the Bucket Reachability credential; note the
    // same bucket is used in the proof
    CBucket_reach = (bucket*P_reach + zbucket_reach*A),
    // User blinding of the Lox credential to be issued
    CommitLoxBlind = (s*A + id_client * Xid + bucket * Xbucket + level * Xlevel + since * Xsince + new_invites_remaining * Xinvremain + blockages * Xblockages),
    // User blinding of the Invitation to be issued
    CommitInviteBlind = (s_inv * A + inv_id_client * Xinv_id + bucket * Xinv_bucket + blockages * Xinv_blockages)
}

define_proof! {
    blindissue,
    "Issue Invite Issuing",
    (x0, x0tilde, xid, xbucket, xlevel, xsince, xinvremain, xblockages,
     b, x0_inv, x0tilde_inv, xid_inv, xdate_inv, xbucket_inv,
     xblockages_inv, b_inv),
    (P, BlindLoxQ, X0, P_inv, BlindInviteQ, X0_inv, Xid_inv, Xdate_inv,
     Xbucket_inv, Xblockages_inv, Pdate_inv, CommitLoxBlind, CommitInviteBlind),
    (A, B):
    X0 = (x0*B + x0tilde*A),
    P = (b*A),
    BlindLoxQ = (b*CommitLoxBlind + x0 * P),
    Xid_inv = (xid_inv*A),
    Xdate_inv = (xdate_inv*A),
    Xbucket_inv = (xbucket_inv*A),
    Xblockages_inv = (xblockages_inv*A),
    X0_inv = (x0_inv*B + x0tilde_inv*A),
    P_inv = (b_inv*A),
    BlindInviteQ = (b_inv * CommitInviteBlind + x0_inv * P_inv + xdate_inv * Pdate_inv)
}

pub fn request(
    lox_cred: &cred::Lox,
    reach_cred: &cred::BucketReachability,
    lox_pub: &IssuerPubKey,
    reach_pub: &IssuerPubKey,
    inv_pub: &IssuerPubKey,
    today: u32,
) -> Result<(Request, State), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;
    let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

    // Ensure the credential can be correctly shown: it must be the case
    // that invites_remaining not be 0
    if lox_cred.invites_remaining == Scalar::ZERO {
        return Err(CredentialError::NoInvitationsRemaining);
    }
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
    // The new invites_remaining
    let new_invites_remaining = lox_cred.invites_remaining - Scalar::ONE;

    // Blind showing the Lox credential

    // Reblind P and Q
    let mut rng = rand::rngs::OsRng;
    let t = Scalar::random(&mut rng);
    let P = t * lox_cred.P;
    let Q = t * lox_cred.Q;

    // Form Pedersen commitments to the blinded attributes
    let zbucket = Scalar::random(&mut rng);
    let zlevel = Scalar::random(&mut rng);
    let zsince = Scalar::random(&mut rng);
    let zinvremain = Scalar::random(&mut rng);
    let zblockages = Scalar::random(&mut rng);
    let CBucket = lox_cred.bucket * P + &zbucket * Atable;
    let CLevel = lox_cred.trust_level * P + &zlevel * Atable;
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
        + zlevel * lox_pub.X[3]
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
            + lox_cred.trust_level * lox_pub.X[3]
            + lox_cred.level_since * lox_pub.X[4]
            + new_invites_remaining * lox_pub.X[5]
            + lox_cred.blockages * lox_pub.X[6]);

    // User blinding for the Invitation certificate to be issued

    // Pick a scalar to randomize our commitment
    let s_inv = Scalar::random(&mut rng);

    // Pick a random client component of the id
    let inv_id_client = Scalar::random(&mut rng);

    // Commit to the new credential values with sum(m_i*X_i) + s * A
    // where A is our generator
    let CommitInviteBlind = s_inv * A
        + (inv_id_client * inv_pub.X[1]
            + lox_cred.bucket * inv_pub.X[3]
            + lox_cred.blockages * inv_pub.X[4]);

    // The proof that invites_remaining is not zero.  We prove this by
    // demonstrating that we know its inverse.
    let invremain_inverse = &lox_cred.invites_remaining.invert();

    let zinvremain_inverse = -zinvremain * invremain_inverse;

    // So now invremain_inverse * CInvRemain + zinvremain_inverse * A = P

    // Construct the proof
    let mut transcript = Transcript::new(b"issue invite request");
    let piUser = requestproof::prove_compact(
        &mut transcript,
        requestproof::ProveAssignments {
            A,
            P: &P,
            CBucket: &CBucket,
            CLevel: &CLevel,
            CSince: &CSince,
            CInvRemain: &CInvRemain,
            CBlockages: &CBlockages,
            V: &V,
            Xid: &lox_pub.X[1],
            Xbucket: &lox_pub.X[2],
            Xlevel: &lox_pub.X[3],
            Xsince: &lox_pub.X[4],
            Xinvremain: &lox_pub.X[5],
            Xblockages: &lox_pub.X[6],
            P_reach: &P_reach,
            CBucket_reach: &CBucket_reach,
            V_reach: &V_reach,
            Xbucket_reach: &reach_pub.X[2],
            Xinv_id: &inv_pub.X[1],
            Xinv_bucket: &inv_pub.X[3],
            Xinv_blockages: &inv_pub.X[4],
            bucket: &lox_cred.bucket,
            level: &lox_cred.trust_level,
            since: &lox_cred.level_since,
            invremain: &lox_cred.invites_remaining,
            blockages: &lox_cred.blockages,
            zbucket: &zbucket,
            zlevel: &zlevel,
            zsince: &zsince,
            zinvremain: &zinvremain,
            zblockages: &zblockages,
            negzQ: &negzQ,
            zbucket_reach: &zbucket_reach,
            negzQ_reach: &negzQ_reach,
            id_client: &id_client,
            inv_id_client: &inv_id_client,
            invremain_inverse,
            zinvremain_inverse: &zinvremain_inverse,
            s: &s,
            s_inv: &s_inv,
            CommitLoxBlind: &CommitLoxBlind,
            CommitInviteBlind: &CommitInviteBlind,
            new_invites_remaining: &new_invites_remaining,
        },
    )
    .0;
    #[cfg(feature = "dump")]
    let duration = now.elapsed();
    #[cfg(feature = "dump")]
    let _dumper = if cfg!(feature = "dump") {
        dump(&format!("issue-invite client request time {:#?}", duration));
    };

    Ok((
        Request {
            P,
            id: lox_cred.id,
            CBucket,
            CLevel,
            CSince,
            CInvRemain,
            CBlockages,
            CQ,
            P_reach,
            CBucket_reach,
            CQ_reach,
            CommitLoxBlind,
            CommitInviteBlind,
            piUser,
        },
        State {
            s,
            id_client,
            bucket: lox_cred.bucket,
            level: lox_cred.trust_level,
            since: lox_cred.level_since,
            invremain: new_invites_remaining,
            blockages: lox_cred.blockages,
            s_inv,
            inv_id_client,
        },
    ))
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    /// Receive an issue invite request
    pub fn handle_issue_invite(&mut self, req: Request) -> Result<Response, ProofError> {
        let A: &RistrettoPoint = &CMZ_A;
        let B: &RistrettoPoint = &CMZ_B;
        let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

        if req.P.is_identity() || req.P_reach.is_identity() {
            return Err(ProofError::VerificationFailure);
        }

        let today: Scalar = self.today().into();

        // Recompute the "error factors" using knowledge of our own
        // (the issuer's) private key instead of knowledge of the
        // hidden attributes
        let Vprime = (self.lox_priv.x[0] + self.lox_priv.x[1] * req.id) * req.P
            + self.lox_priv.x[2] * req.CBucket
            + self.lox_priv.x[3] * req.CLevel
            + self.lox_priv.x[4] * req.CSince
            + self.lox_priv.x[5] * req.CInvRemain
            + self.lox_priv.x[6] * req.CBlockages
            - req.CQ;

        let Vprime_reach = (self.reachability_priv.x[0] + self.reachability_priv.x[1] * today)
            * req.P_reach
            + self.reachability_priv.x[2] * req.CBucket_reach
            - req.CQ_reach;

        // Verify the ZKP
        let mut transcript = Transcript::new(b"issue invite request");
        requestproof::verify_compact(
            &req.piUser,
            &mut transcript,
            requestproof::VerifyAssignments {
                A: &A.compress(),
                P: &req.P.compress(),
                CBucket: &req.CBucket.compress(),
                CLevel: &req.CLevel.compress(),
                CSince: &req.CSince.compress(),
                CInvRemain: &req.CInvRemain.compress(),
                CBlockages: &req.CBlockages.compress(),
                V: &Vprime.compress(),
                Xid: &self.lox_pub.X[1].compress(),
                Xbucket: &self.lox_pub.X[2].compress(),
                Xlevel: &self.lox_pub.X[3].compress(),
                Xsince: &self.lox_pub.X[4].compress(),
                Xinvremain: &self.lox_pub.X[5].compress(),
                Xblockages: &self.lox_pub.X[6].compress(),
                P_reach: &req.P_reach.compress(),
                CBucket_reach: &req.CBucket_reach.compress(),
                V_reach: &Vprime_reach.compress(),
                Xbucket_reach: &self.reachability_pub.X[2].compress(),
                CommitLoxBlind: &req.CommitLoxBlind.compress(),
                CommitInviteBlind: &req.CommitInviteBlind.compress(),
                Xinv_id: &self.invitation_pub.X[1].compress(),
                Xinv_bucket: &self.invitation_pub.X[3].compress(),
                Xinv_blockages: &self.invitation_pub.X[4].compress(),
            },
        )?;

        // Ensure the id has not been seen before, and add it to the
        // seen list.
        if self.id_filter.filter(&req.id) == SeenType::Seen {
            return Err(ProofError::VerificationFailure);
        }

        // Blind issuing of the new Lox credential

        let mut rng = rand::rngs::OsRng;

        // Compute the MAC on the visible attributes (none here)
        let b = Scalar::random(&mut rng);
        let P = &b * Atable;

        // Create server contribution of the Lox id
        let server_id = Scalar::random(&mut rng);

        // Append the server id to the client's commitment
        let CommitLoxSrv = req.CommitLoxBlind + (server_id * self.lox_pub.X[1]);

        let BlindLoxQ = b * CommitLoxSrv + self.lox_priv.x[0] * P;

        // Blind issuing of the new Invitation credential

        // Compute the MAC on the visible attributes
        let b_inv = Scalar::random(&mut rng);
        let P_inv = &b_inv * Atable;
        // Create server contribution of the Lox id
        let server_inv_id = Scalar::random(&mut rng);

        // Append the server id to the client's commitment
        let CommitInviteSrv = req.CommitInviteBlind + (server_inv_id * self.invitation_pub.X[1]);
        let BlindInviteQ = b_inv * CommitInviteSrv
            + (self.invitation_priv.x[0] + self.invitation_priv.x[2] * today) * P_inv;

        let mut transcript = Transcript::new(b"issue invite issuing");
        let piBlindIssue = blindissue::prove_compact(
            &mut transcript,
            blindissue::ProveAssignments {
                A,
                B,
                P: &P,
                X0: &self.lox_pub.X[0],
                X0_inv: &self.invitation_pub.X[0],
                Xid_inv: &self.invitation_pub.X[1],
                Xdate_inv: &self.invitation_pub.X[2],
                Xbucket_inv: &self.invitation_pub.X[3],
                Xblockages_inv: &self.invitation_pub.X[4],
                Pdate_inv: &(today * P_inv),
                x0: &self.lox_priv.x[0],
                x0tilde: &self.lox_priv.x0tilde,
                xid: &self.lox_priv.x[1],
                xbucket: &self.lox_priv.x[2],
                xlevel: &self.lox_priv.x[3],
                xsince: &self.lox_priv.x[4],
                xinvremain: &self.lox_priv.x[5],
                xblockages: &self.lox_priv.x[6],
                b: &b,
                x0_inv: &self.invitation_priv.x[0],
                x0tilde_inv: &self.invitation_priv.x0tilde,
                xid_inv: &self.invitation_priv.x[1],
                xdate_inv: &self.invitation_priv.x[2],
                xbucket_inv: &self.invitation_priv.x[3],
                xblockages_inv: &self.invitation_priv.x[4],
                b_inv: &b_inv,
                BlindLoxQ: &BlindLoxQ,
                P_inv: &P_inv,
                BlindInviteQ: &BlindInviteQ,
                CommitLoxBlind: &CommitLoxSrv,
                CommitInviteBlind: &CommitInviteSrv,
            },
        )
        .0;

        Ok(Response {
            P,
            BlindLoxQ,
            server_id,
            P_inv,
            BlindInviteQ,
            server_inv_id,
            date_inv: today,
            piBlindIssue,
        })
    }
}

/// Handle the response to the request, producing the new Lox credential
/// and Invitation credential if successful.
pub fn handle_response(
    state: State,
    resp: Response,
    lox_pub: &IssuerPubKey,
    invitation_pub: &IssuerPubKey,
) -> Result<(cred::Lox, cred::Invitation), ProofError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;
    let B: &RistrettoPoint = &CMZ_B;

    if resp.P.is_identity() || resp.P_inv.is_identity() {
        return Err(ProofError::VerificationFailure);
    }

    // Verify the proof
    let mut transcript = Transcript::new(b"issue invite issuing");
    blindissue::verify_compact(
        &resp.piBlindIssue,
        &mut transcript,
        blindissue::VerifyAssignments {
            A: &A.compress(),
            B: &B.compress(),
            P: &resp.P.compress(),
            X0: &lox_pub.X[0].compress(),
            P_inv: &resp.P_inv.compress(),
            X0_inv: &invitation_pub.X[0].compress(),
            Xid_inv: &invitation_pub.X[1].compress(),
            Xdate_inv: &invitation_pub.X[2].compress(),
            Xbucket_inv: &invitation_pub.X[3].compress(),
            Xblockages_inv: &invitation_pub.X[4].compress(),
            Pdate_inv: &(resp.date_inv * resp.P_inv).compress(),
            BlindLoxQ: &resp.BlindLoxQ.compress(),
            CommitLoxBlind: &(state.s * A
                + state.id_client * lox_pub.X[1]
                + resp.server_id * lox_pub.X[1]
                + state.bucket * lox_pub.X[2]
                + state.level * lox_pub.X[3]
                + state.since * lox_pub.X[4]
                + state.invremain * lox_pub.X[5]
                + state.blockages * lox_pub.X[6])
                .compress(),
            BlindInviteQ: &resp.BlindInviteQ.compress(),
            CommitInviteBlind: &(state.s_inv * A
                + state.inv_id_client * invitation_pub.X[1]
                + resp.server_inv_id * invitation_pub.X[1]
                + state.bucket * invitation_pub.X[3]
                + state.blockages * invitation_pub.X[4])
                .compress(),
        },
    )?;

    // Decrypt BlindLoxQ
    let mut rng = rand::rngs::OsRng;
    let r = Scalar::random(&mut rng);
    let r_inv = Scalar::random(&mut rng);
    let Q = r * (resp.BlindLoxQ - state.s * resp.P);
    let Q_inv = r_inv * (resp.BlindInviteQ - state.s_inv * resp.P_inv);
    #[cfg(feature = "dump")]
    let duration = now.elapsed();
    #[cfg(feature = "dump")]
    let _dumper = if cfg!(feature = "dump") {
        dump(&format!("issue-invite client handle time {:#?}", duration));
    };

    Ok((
        cred::Lox {
            P: r * resp.P,
            Q,
            id: state.id_client + resp.server_id,
            bucket: state.bucket,
            trust_level: state.level,
            level_since: state.since,
            invites_remaining: state.invremain,
            blockages: state.blockages,
        },
        cred::Invitation {
            P: r_inv * resp.P_inv,
            Q: Q_inv,
            inv_id: state.inv_id_client + resp.server_inv_id,
            date: resp.date_inv,
            bucket: state.bucket,
            blockages: state.blockages,
        },
    ))
}

#[cfg(all(test, feature = "bridgeauth"))]
mod tests {
    use crate::mock_auth::TestHarness;

    #[test]
    fn test_artifact_issue_invite() {
        println!("\n----ISSUE-INVITATION----\n");
        let mut th = TestHarness::new();
        let invite = th.bdb.invite().unwrap();
        let (_, lox_cred) = th.open_invite(&invite);
        let (_, mig_cred) = th.trust_promotion(lox_cred.0.clone());
        let (_, lox_cred) = th.migration(lox_cred.0.clone(), mig_cred.clone());
        let (_, lox_cred) = th.level_up(lox_cred.clone());
        let (perf_stats, issue_invite_cred) = th.issue_invite(lox_cred.clone());
        th.verify_lox(&issue_invite_cred.0);
        th.verify_invitation(&issue_invite_cred.1);
        th.print_test_results(perf_stats);
    }
}
