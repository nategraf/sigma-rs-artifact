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
use super::super::BridgeAuth;
use super::super::IssuerPubKey;
use super::super::{CMZ_A, CMZ_A_TABLE, CMZ_B};
use super::errors::CredentialError;
#[cfg(feature = "dump")]
use crate::dumper::dump;
use web_time::Instant;

#[derive(Serialize, Clone, Deserialize)]
pub struct Request {
    // Fields for showing the old Invitation credential
    OldPubKey: IssuerPubKey,
    P: RistrettoPoint,
    inv_id: Scalar,
    CDate: RistrettoPoint,
    CBucket: RistrettoPoint,
    CBlockages: RistrettoPoint,
    CQ: RistrettoPoint,

    // Fields for user blinding of the Invitation credential to be issued
    CommitInviteBlind: RistrettoPoint,

    // The combined ZKP
    piUser: CompactProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    s: Scalar,
    inv_id_client: Scalar,
    date: Scalar,
    bucket: Scalar,
    blockages: Scalar,
}

#[derive(Serialize, Clone, Deserialize)]
pub struct Response {
    // The fields for the updated Invitation credential;
    P: RistrettoPoint,
    BlindInviteQ: RistrettoPoint,
    server_id: Scalar,

    // The ZKP
    piBlindIssue: CompactProof,
}

define_proof! {
    requestproof,
    "Update Invite Request",
    (date, bucket, blockages, zdate, zbucket, zblockages, negzQ,
     s, inv_id_client),
    (P, CDate, CBucket, CBlockages, V, Xinv_id, Xdate, Xbucket, Xblockages,
    CommitInviteBlind),
    (A):
    // Blind showing of the Invitation credential
    CDate = (date*P + zdate*A),
    CBucket = (bucket*P + zbucket*A),
    CBlockages = (blockages*P + zblockages*A),
    // User blinding of the Invitation credential to be issued
    CommitInviteBlind = (s*A + inv_id_client * Xinv_id + date * Xdate + bucket * Xbucket + blockages * Xblockages)
}

define_proof! {
    blindissue,
    "Issue Updated Invitation",
    (x0, x0tilde, b),
    (P, BlindInviteQ, X0, CommitInviteBlind),
    (A, B):
    X0 = (x0*B + x0tilde*A),
    P = (b*A),
    BlindInviteQ = (b* CommitInviteBlind + x0 * P)
}

pub fn request(
    inv_cred: &cred::Invitation,
    old_invitation_pub: &IssuerPubKey,
    new_invitation_pub: &IssuerPubKey,
) -> Result<(Request, State), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;
    let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

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
    let V = zdate * old_invitation_pub.X[2]
        + zbucket * old_invitation_pub.X[3]
        + zblockages * old_invitation_pub.X[4]
        + &negzQ * Atable;

    // User blinding for the Invitation Token to be issued

    // Pick a random client component of the id
    let inv_id_client = Scalar::random(&mut rng);

    // Pick a scalar to randomize our commitment
    let s = Scalar::random(&mut rng);
    // Commit to the new credential values with sum(m_i*X_i) + s * A
    // where A is our generator
    let CommitInviteBlind = s * A
        + inv_id_client * new_invitation_pub.X[1]
        + inv_cred.date * new_invitation_pub.X[2]
        + inv_cred.bucket * new_invitation_pub.X[3]
        + inv_cred.blockages * new_invitation_pub.X[4];

    // Construct the proof
    let mut transcript = Transcript::new(b"update invite request");
    let piUser = requestproof::prove_compact(
        &mut transcript,
        requestproof::ProveAssignments {
            A,
            P: &P,
            CDate: &CDate,
            CBucket: &CBucket,
            CBlockages: &CBlockages,
            V: &V,
            Xinv_id: &new_invitation_pub.X[1],
            Xdate: &new_invitation_pub.X[2],
            Xbucket: &new_invitation_pub.X[3],
            Xblockages: &new_invitation_pub.X[4],
            date: &inv_cred.date,
            bucket: &inv_cred.bucket,
            blockages: &inv_cred.blockages,
            zdate: &zdate,
            zbucket: &zbucket,
            zblockages: &zblockages,
            negzQ: &negzQ,
            s: &s,
            inv_id_client: &inv_id_client,
            CommitInviteBlind: &CommitInviteBlind,
        },
    )
    .0;
    #[cfg(feature = "dump")]
    let duration = now.elapsed();
    #[cfg(feature = "dump")]
    let _dumper = if cfg!(feature = "dump") {
        dump(&format!(
            "update-invite client request time {:#?}",
            duration
        ));
    };

    Ok((
        Request {
            OldPubKey: old_invitation_pub.clone(),
            P,
            inv_id: inv_cred.inv_id,
            CDate,
            CBucket,
            CBlockages,
            CQ,
            CommitInviteBlind,
            piUser,
        },
        State {
            s,
            inv_id_client,
            date: inv_cred.date,
            bucket: inv_cred.bucket,
            blockages: inv_cred.blockages,
        },
    ))
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    /// Receive a redeem invite request
    pub fn handle_update_invite(&mut self, req: Request) -> Result<Response, ProofError> {
        let A: &RistrettoPoint = &CMZ_A;
        let B: &RistrettoPoint = &CMZ_B;
        let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

        if req.P.is_identity() {
            return Err(ProofError::VerificationFailure);
        }

        // Both of these must be true and should be true after rotate_lox_keys is called
        if self.old_keys.invitation_keys.is_empty() || self.old_filters.invitation_filter.is_empty()
        {
            return Err(ProofError::VerificationFailure);
        }

        // calling this function will automatically use the most recent old private key for
        // verification and the new private key for issuing.

        // Recompute the "error factors" using knowledge of our own
        // (the issuer's) outdated private key instead of knowledge of the
        // hidden attributes
        let old_keys = match self
            .old_keys
            .invitation_keys
            .iter()
            .find(|x| x.pub_key == req.OldPubKey)
        {
            Some(old_keys) => old_keys,
            None => return Err(ProofError::VerificationFailure),
        };
        let index = self
            .old_keys
            .invitation_keys
            .iter()
            .position(|x| x.pub_key == old_keys.pub_key)
            .unwrap();
        let old_priv_key = old_keys.priv_key.clone();

        // Recompute the "error factor" using knowledge of our own
        // (the issuer's) private key instead of knowledge of the
        // hidden attributes
        let Vprime = (old_priv_key.x[0] + old_priv_key.x[1] * req.inv_id) * req.P
            + old_priv_key.x[2] * req.CDate
            + old_priv_key.x[3] * req.CBucket
            + old_priv_key.x[4] * req.CBlockages
            - req.CQ;

        // Verify the ZKP
        let mut transcript = Transcript::new(b"update invite request");
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
                Xinv_id: &self.invitation_pub.X[1].compress(),
                Xdate: &self.invitation_pub.X[2].compress(),
                Xbucket: &self.invitation_pub.X[3].compress(),
                Xblockages: &self.invitation_pub.X[4].compress(),
                CommitInviteBlind: &req.CommitInviteBlind.compress(),
            },
        )?;

        // Ensure the id has not been seen before, and add it to the
        // invite id seen list.
        if self
            .old_filters
            .invitation_filter
            .get_mut(index)
            .unwrap()
            .filter(&req.inv_id)
            == SeenType::Seen
        {
            return Err(ProofError::VerificationFailure);
        }

        // Blind issuing of the new Invitation credential

        let mut rng = rand::rngs::OsRng;

        // Compute the MAC on the visible attributes
        let b = Scalar::random(&mut rng);
        let P = &b * Atable;
        // Create server contribution of the Lox id
        let server_id = Scalar::random(&mut rng);

        // Append the server id to the client's commitment
        let CommitInviteSrv = req.CommitInviteBlind + (server_id * self.invitation_pub.X[1]);

        let BlindInviteQ = b * CommitInviteSrv + self.invitation_priv.x[0] * P;

        let mut transcript = Transcript::new(b"issue updated invitation");
        let piBlindIssue = blindissue::prove_compact(
            &mut transcript,
            blindissue::ProveAssignments {
                A,
                B,
                P: &P,
                X0: &self.invitation_pub.X[0],
                x0: &self.invitation_priv.x[0],
                x0tilde: &self.invitation_priv.x0tilde,
                b: &b,
                CommitInviteBlind: &CommitInviteSrv,
                BlindInviteQ: &BlindInviteQ,
            },
        )
        .0;

        Ok(Response {
            P,
            BlindInviteQ,
            server_id,
            piBlindIssue,
        })
    }
}

/// Handle the response to the request, producing the new Lox credential
/// if successful.
pub fn handle_response(
    state: State,
    resp: Response,
    invitation_pub: &IssuerPubKey,
) -> Result<cred::Invitation, ProofError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;
    let B: &RistrettoPoint = &CMZ_B;

    if resp.P.is_identity() {
        return Err(ProofError::VerificationFailure);
    }

    // Verify the proof
    let mut transcript = Transcript::new(b"issue updated invitation");
    blindissue::verify_compact(
        &resp.piBlindIssue,
        &mut transcript,
        blindissue::VerifyAssignments {
            A: &A.compress(),
            B: &B.compress(),
            P: &resp.P.compress(),
            X0: &invitation_pub.X[0].compress(),
            CommitInviteBlind: &(state.s * A
                + (state.inv_id_client * invitation_pub.X[1]
                    + resp.server_id * invitation_pub.X[1]
                    + state.date * invitation_pub.X[2]
                    + state.bucket * invitation_pub.X[3]
                    + state.blockages * invitation_pub.X[4]))
                .compress(),
            BlindInviteQ: &resp.BlindInviteQ.compress(),
        },
    )?;

    // Decrypt BlindLoxQ
    let mut rng = rand::rngs::OsRng;
    let r = Scalar::random(&mut rng);
    let Q = r * (resp.BlindInviteQ - state.s * resp.P);
    #[cfg(feature = "dump")]
    let duration = now.elapsed();
    #[cfg(feature = "dump")]
    let _dumper = if cfg!(feature = "dump") {
        dump(&format!(
            "update-invite client handle reply time {:#?}",
            duration
        ));
    };

    Ok(cred::Invitation {
        P: r * resp.P,
        Q,
        inv_id: state.inv_id_client + resp.server_id,
        date: state.date,
        bucket: state.bucket,
        blockages: state.blockages,
    })
}

#[cfg(all(test, feature = "bridgeauth"))]
mod tests {
    use crate::mock_auth::TestHarness;

    #[test]
    fn test_artifact_update_invite() {
        println!("\n----UPDATE-INVITE----\n");
        let mut th = TestHarness::new();
        let invite = th.bdb.invite().unwrap();
        let (_, lox_cred) = th.open_invite(&invite);
        let (_, mig_cred) = th.trust_promotion(lox_cred.0.clone());
        let (_, lox_cred) = th.migration(lox_cred.0.clone(), mig_cred.clone());
        let (_, lox_cred) = th.level_up(lox_cred.clone());
        let (_, (_, invitation)) = th.issue_invite(lox_cred.clone());
        let old_pub = th.ba.invitation_pub.clone();
        let (perf_stats, creds) = th.update_invite(invitation, old_pub);
        th.verify_invitation(&creds);
        th.print_test_results(perf_stats);
    }
}
