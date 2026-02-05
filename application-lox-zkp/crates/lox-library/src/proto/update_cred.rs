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
#[cfg(feature = "dump")]
use crate::dumper::dump;
use web_time::Instant;

use super::errors::CredentialError;

#[derive(Serialize, Clone, Deserialize)]
pub struct Request {
    // Fields for blind showing the Lox credential
    OldPubKey: IssuerPubKey,
    P: RistrettoPoint,
    id: Scalar,
    CBucket: RistrettoPoint,
    CLevel: RistrettoPoint,
    CSince: RistrettoPoint,
    CInvRemain: RistrettoPoint,
    CBlockages: RistrettoPoint,
    CQ: RistrettoPoint,
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
    since: Scalar,
    invremain: Scalar,
    blockages: Scalar,
}

#[derive(Serialize, Clone, Deserialize)]
pub struct Response {
    // The fields for the new Lox credential; the new invites_remaining
    // is one less than the old value, so we don't have to include it
    // here explicitly
    P: RistrettoPoint,
    BlindLoxQ: RistrettoPoint,
    server_id: Scalar,

    // The ZKP
    piBlindIssue: CompactProof,
}

define_proof! {
    requestproof,
    "Update Credential Key Request",
    (bucket, level, since, invremain, blockages, zbucket, zlevel,
     zsince, zinvremain, zblockages, negzQ,
     s, id_client
    ),
    (P, CBucket, CLevel, CSince, CInvRemain, CBlockages, V, Xid, Xbucket,
     Xlevel, Xsince, Xinvremain, Xblockages,
     CommitLoxBlind),
    (A):
    // Blind showing of the Lox credential
    CBucket = (bucket*P + zbucket*A),
    CLevel = (level*P + zlevel*A),
    CSince = (since*P + zsince*A),
    CInvRemain = (invremain*P + zinvremain*A),
    CBlockages = (blockages*P + zblockages*A),
    // User blinding of the Lox credential to be issued
    CommitLoxBlind = (s*A + id_client * Xid + bucket * Xbucket + level * Xlevel + since * Xsince + invremain * Xinvremain + blockages * Xblockages)
}

define_proof! {
    blindissue,
    "Issue updated cred",
    (x0, x0tilde, b),
    (P, BlindLoxQ, X0, CommitLoxBlind),
    (A,B):
    X0 = (x0*B + x0tilde*A),
    P = (b*A),
    BlindLoxQ = (b * CommitLoxBlind + x0 * P)
}

pub fn request(
    lox_cred: &cred::Lox,
    old_lox_pub: &IssuerPubKey,
    new_lox_pub: &IssuerPubKey,
) -> Result<(Request, State), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;
    let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

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
    let V = zbucket * old_lox_pub.X[2]
        + zlevel * old_lox_pub.X[3]
        + zsince * old_lox_pub.X[4]
        + zinvremain * old_lox_pub.X[5]
        + zblockages * old_lox_pub.X[6]
        + &negzQ * Atable;

    // User blinding for the Lox certificate to be issued
    // Pick a random client component of the id
    let id_client = Scalar::random(&mut rng);

    // Pick a scalar to randomize our commitment
    let s = Scalar::random(&mut rng);
    // Commit to the new credential values with sum(m_i*X_i) + s * A
    // where A is our generator
    let CommitLoxBlind = s * A
        + (id_client * new_lox_pub.X[1]
            + lox_cred.bucket * new_lox_pub.X[2]
            + lox_cred.trust_level * new_lox_pub.X[3]
            + lox_cred.level_since * new_lox_pub.X[4]
            + lox_cred.invites_remaining * new_lox_pub.X[5]
            + lox_cred.blockages * new_lox_pub.X[6]);

    // Construct the proof
    let mut transcript = Transcript::new(b"update credential key request");
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
            Xid: &new_lox_pub.X[1],
            Xbucket: &new_lox_pub.X[2],
            Xlevel: &new_lox_pub.X[3],
            Xsince: &new_lox_pub.X[4],
            Xinvremain: &new_lox_pub.X[5],
            Xblockages: &new_lox_pub.X[6],
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
            s: &s,
            id_client: &id_client,
            CommitLoxBlind: &CommitLoxBlind,
        },
    )
    .0;
    #[cfg(feature = "dump")]
    let duration = now.elapsed();
    #[cfg(feature = "dump")]
    let _dumper = if cfg!(feature = "dump") {
        dump(&format!("update-cred client request time {:#?}", duration));
    };

    Ok((
        Request {
            OldPubKey: old_lox_pub.clone(),
            P,
            id: lox_cred.id,
            CBucket,
            CLevel,
            CSince,
            CInvRemain,
            CBlockages,
            CQ,
            CommitLoxBlind,
            piUser,
        },
        State {
            s,
            id_client,
            bucket: lox_cred.bucket,
            level: lox_cred.trust_level,
            since: lox_cred.level_since,
            invremain: lox_cred.invites_remaining,
            blockages: lox_cred.blockages,
        },
    ))
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    /// Receive an issue invite request
    pub fn handle_update_cred(&mut self, req: Request) -> Result<Response, ProofError> {
        let A: &RistrettoPoint = &CMZ_A;
        let B: &RistrettoPoint = &CMZ_B;
        let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

        if req.P.is_identity() {
            return Err(ProofError::VerificationFailure);
        }

        // Both of these must be true and should be true after rotate_lox_keys is called
        if self.old_keys.lox_keys.is_empty() || self.old_filters.lox_filter.is_empty() {
            return Err(ProofError::VerificationFailure);
        }

        // calling this function will automatically use the most recent old private key for
        // verification and the new private key for issuing.

        // Recompute the "error factors" using knowledge of our own
        // (the issuer's) outdated private key instead of knowledge of the
        // hidden attributes
        let old_keys = match self
            .old_keys
            .lox_keys
            .iter()
            .find(|x| x.pub_key == req.OldPubKey)
        {
            Some(old_keys) => old_keys,
            None => return Err(ProofError::VerificationFailure),
        };
        let index = self
            .old_keys
            .lox_keys
            .iter()
            .position(|x| x.pub_key == old_keys.pub_key)
            .unwrap();

        let old_priv_key = old_keys.priv_key.clone();
        let Vprime = (old_priv_key.x[0] + old_priv_key.x[1] * req.id) * req.P
            + old_priv_key.x[2] * req.CBucket
            + old_priv_key.x[3] * req.CLevel
            + old_priv_key.x[4] * req.CSince
            + old_priv_key.x[5] * req.CInvRemain
            + old_priv_key.x[6] * req.CBlockages
            - req.CQ;

        // Verify the ZKP
        let mut transcript = Transcript::new(b"update credential key request");
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
                CommitLoxBlind: &req.CommitLoxBlind.compress(),
            },
        )?;

        // Check the old_lox_id_filter for the id.
        // Ensure the id has not been seen before, and add it to the
        // seen list.
        if self
            .old_filters
            .lox_filter
            .get_mut(index)
            .unwrap()
            .filter(&req.id)
            == SeenType::Seen
        {
            return Err(ProofError::VerificationFailure);
        }

        // Blind issuing of the new Lox credential using the new key

        let mut rng = rand::rngs::OsRng;

        // Compute the MAC on the visible attributes (none here)
        let b = Scalar::random(&mut rng);
        let P = &b * Atable;

        // Create server contribution of the Lox id
        let server_id = Scalar::random(&mut rng);

        // Append the server id to the client's commitment
        let CommitLoxSrv = req.CommitLoxBlind + (server_id * self.lox_pub.X[1]);

        let BlindLoxQ = b * CommitLoxSrv + self.lox_priv.x[0] * P;

        let mut transcript = Transcript::new(b"issue updated cred");
        let piBlindIssue = blindissue::prove_compact(
            &mut transcript,
            blindissue::ProveAssignments {
                A,
                B,
                P: &P,
                X0: &self.lox_pub.X[0],
                x0: &self.lox_priv.x[0],
                x0tilde: &self.lox_priv.x0tilde,
                b: &b,
                CommitLoxBlind: &CommitLoxSrv,
                BlindLoxQ: &BlindLoxQ,
            },
        )
        .0;

        Ok(Response {
            P,
            BlindLoxQ,
            server_id,
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
) -> Result<cred::Lox, ProofError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;
    let B: &RistrettoPoint = &CMZ_B;

    if resp.P.is_identity() {
        return Err(ProofError::VerificationFailure);
    }

    // Verify the proof
    let mut transcript = Transcript::new(b"issue updated cred");
    blindissue::verify_compact(
        &resp.piBlindIssue,
        &mut transcript,
        blindissue::VerifyAssignments {
            A: &A.compress(),
            B: &B.compress(),
            P: &resp.P.compress(),
            X0: &lox_pub.X[0].compress(),
            CommitLoxBlind: &(state.s * A
                + (state.id_client * lox_pub.X[1]
                    + resp.server_id * lox_pub.X[1]
                    + state.bucket * lox_pub.X[2]
                    + state.level * lox_pub.X[3]
                    + state.since * lox_pub.X[4]
                    + state.invremain * lox_pub.X[5]
                    + state.blockages * lox_pub.X[6]))
                .compress(),
            BlindLoxQ: &resp.BlindLoxQ.compress(),
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
        dump(&format!(
            "update-cred client handle reply time {:#?}",
            duration
        ));
    };

    Ok(cred::Lox {
        P: r * resp.P,
        Q,
        id: state.id_client + resp.server_id,
        bucket: state.bucket,
        trust_level: state.level,
        level_since: state.since,
        invites_remaining: state.invremain,
        blockages: state.blockages,
    })
}

#[cfg(all(test, feature = "bridgeauth"))]
mod tests {
    use crate::mock_auth::TestHarness;

    #[test]
    fn test_artifact_update_cred() {
        println!("\n----UPDATE-CRED----\n");
        let mut th = TestHarness::new();
        let invite = th.bdb.invite().unwrap();
        let (_, lox_cred) = th.open_invite(&invite);
        let old_pub = th.ba.lox_pub.clone();
        let (perf_stat, lox_cred) = th.update_cred(lox_cred.0.clone(), old_pub);
        th.verify_lox(&lox_cred);
        th.print_test_results(perf_stat);
    }
}
