/*! A module for the protocol for the user to redeem an open invitation
with the BA (bridge authority) to receive their initial Lox
credential.

The credential will have attributes:

- id: jointly chosen by the user and BA
- bucket: set by the BA
- trust_level: 0
- level_since: today
- invites_remaining: 0
- blockages: 0

*/

#[cfg(feature = "bridgeauth")]
use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;

use lox_zkp::CompactProof;
use lox_zkp::ProofError;
use lox_zkp::Transcript;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[cfg(feature = "bridgeauth")]
use super::super::bridge_table;
use super::super::bridge_table::BridgeLine;
use super::super::cred;
#[cfg(feature = "dump")]
use super::super::dumper::dump;
#[cfg(feature = "bridgeauth")]
use super::super::dup_filter::SeenType;
use super::super::IssuerPubKey;
use super::super::OPENINV_LENGTH;
#[cfg(feature = "bridgeauth")]
use super::super::{BridgeAuth, BridgeDb, CMZ_A_TABLE};
use super::super::{CMZ_A, CMZ_B};
#[cfg(feature = "dump")]
use web_time::Instant;

/// The request message for this protocol
#[serde_as]
#[derive(Serialize, Clone, Deserialize)]
pub struct Request {
    #[serde_as(as = "[_; OPENINV_LENGTH]")]
    invite: [u8; OPENINV_LENGTH],
    CommitLoxID: RistrettoPoint,
    piUserBlinding: CompactProof,
}

/// The client state for this protocol
#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    id_client: Scalar,
    s: Scalar,
}

/// The response message for this protocol
#[derive(Serialize, Clone, Deserialize)]
pub struct Response {
    P: RistrettoPoint,
    BlindLoxQ: RistrettoPoint,
    server_id: Scalar,
    bucket: Scalar,
    level_since: Scalar,
    piBlindIssue: CompactProof,
    bridge_line: BridgeLine,
}

// The userblinding ZKP
define_proof! {
    userblinding,
    "Open Invitation User Blinding",
    (s, id_client),
    (CommitLoxID),
    (A, Xid) :
    CommitLoxID = (s * A + id_client * Xid)
}

// The issuing ZKP
define_proof! {
    blindissue,
    "Open Invitation Blind Issuing",
    (x0, x0tilde, xbucket, xsince, b),
    (P, BlindLoxQ, X0, Xbucket, Xsince, Pbucket, Psince, CommitLoxID),
    (A, B) :
    Xbucket = (xbucket*A),
    Xsince = (xsince*A),
    X0 = (x0*B + x0tilde*A),
    P = (b*A),
    BlindLoxQ = (b*CommitLoxID + x0*P + xbucket*Pbucket + xsince*Psince)
}

/// Submit an open invitation issued by the BridgeDb to receive your
/// first Lox credential
pub fn request(invite: &[u8; OPENINV_LENGTH], lox_pub: &IssuerPubKey) -> (Request, State) {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;

    let mut rng = rand::rngs::OsRng;

    // Pick a random client component of the id
    let id_client = Scalar::random(&mut rng);

    // Pick a scalar to randomize our commitment
    let s = Scalar::random(&mut rng);
    // Commit to the new id with m_id*X_id + s * A
    // where A is our generator
    let CommitLoxID = s * A + id_client * lox_pub.X[1];

    // Construct the proof of correct user blinding
    let mut transcript = Transcript::new(b"open invite user blinding");
    let piUserBlinding = userblinding::prove_compact(
        &mut transcript,
        userblinding::ProveAssignments {
            A,
            s: &s,
            id_client: &id_client,
            CommitLoxID: &CommitLoxID,
            Xid: &lox_pub.X[1],
        },
    )
    .0;
    #[cfg(feature = "dump")]
    let duration = now.elapsed();
    #[cfg(feature = "dump")]
    let _dumper = if cfg!(feature = "dump") {
        dump(&format!("open-invite client request time {:#?}", duration));
    };
    (
        Request {
            invite: *invite,
            CommitLoxID,
            piUserBlinding,
        },
        State { id_client, s },
    )
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    /// Receive an open invitation issued by the BridgeDb and if it is
    /// valid and fresh, issue a Lox credential at trust level 0.
    pub fn handle_open_invite(&mut self, req: Request) -> Result<Response, ProofError> {
        // Check the signature on the open_invite, first with the old key, then with the new key.
        // We manually match here because we're changing the Err type from SignatureError
        // to ProofError
        let mut old_token: Option<((Scalar, u32), usize)> = Default::default();
        let invite_id: Scalar;
        let bucket_id: u32;
        // If there are old openinv keys, check them first
        for (i, old_openinv_key) in self.old_keys.bridgedb_key.iter().enumerate() {
            old_token = match BridgeDb::verify(req.invite, *old_openinv_key) {
                Ok(res) => Some((res, i)),
                Err(_) => None,
            };
        }

        // Check if verifying with the old key succeeded, if it did, check if it has been seen
        if let Some(token) = old_token {
            // Only proceed if the invite_id is fresh
            (invite_id, bucket_id) = token.0;
            if self
                .old_filters
                .openinv_filter
                .get_mut(token.1)
                .unwrap()
                .filter(&invite_id)
                == SeenType::Seen
            {
                return Err(ProofError::VerificationFailure);
            }
        // If it didn't, try verifying with the new key
        } else {
            (invite_id, bucket_id) = match BridgeDb::verify(req.invite, self.bridgedb_pub) {
                Ok(res) => res,
                // Also verify that the request doesn't match with an old openinv_key
                Err(_) => return Err(ProofError::VerificationFailure),
            };
            // Only proceed if the invite_id is fresh
            if self.bridgedb_pub_filter.filter(&invite_id) == SeenType::Seen {
                return Err(ProofError::VerificationFailure);
            }
        }

        // And also check that the bucket id is valid
        if !self.bridge_table.buckets.contains_key(&bucket_id) {
            return Err(ProofError::VerificationFailure);
        }

        let A: &RistrettoPoint = &CMZ_A;
        let B: &RistrettoPoint = &CMZ_B;
        let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

        // Next check the proof in the request
        let mut transcript = Transcript::new(b"open invite user blinding");
        userblinding::verify_compact(
            &req.piUserBlinding,
            &mut transcript,
            userblinding::VerifyAssignments {
                A: &A.compress(),
                CommitLoxID: &req.CommitLoxID.compress(),
                Xid: &self.lox_pub.X[1].compress(),
            },
        )?;

        // Choose a random server id component to add to the client's
        // (blinded) id component
        let mut rng = rand::rngs::OsRng;

        // Create the bucket attribute (Scalar), which is a combination
        // of the bucket id (u32) and the bucket's decryption key ([u8; 16])
        let bucket_key = self.bridge_table.keys.get(&bucket_id).unwrap();
        let bucket: Scalar = bridge_table::to_scalar(bucket_id, bucket_key);
        let bridge_lines = self.bridge_table.buckets.get(&bucket_id).unwrap();
        let bridge_line = bridge_lines[0];

        // Create the level_since attribute (Scalar), which is today's
        // Julian date
        let level_since: Scalar = self.today().into();

        // Compute the MAC on the visible attributes
        let b = Scalar::random(&mut rng);
        let P = &b * Atable;
        // trust_level = invites_remaining = blockages = 0

        // Create server contribution of the Lox id
        let server_id = Scalar::random(&mut rng);

        // Append the server id to the client's commitment
        let CommitLoxSrv = req.CommitLoxID + (server_id * self.lox_pub.X[1]);
        // Homomorphically compute the part the MAC with server selected attributes and
        // the blinded id attribute
        let BlindLoxQ = b * CommitLoxSrv
            + (self.lox_priv.x[0] + bucket * self.lox_priv.x[2] + level_since * self.lox_priv.x[4])
                * P;

        let mut transcript = Transcript::new(b"open invite issuing");
        let piBlindIssue = blindissue::prove_compact(
            &mut transcript,
            blindissue::ProveAssignments {
                x0: &self.lox_priv.x[0],
                x0tilde: &self.lox_priv.x0tilde,
                xbucket: &self.lox_priv.x[2],
                xsince: &self.lox_priv.x[4],
                b: &b,
                P: &P,
                BlindLoxQ: &BlindLoxQ,
                X0: &self.lox_pub.X[0],
                Xbucket: &self.lox_pub.X[2],
                Xsince: &self.lox_pub.X[4],
                Pbucket: &(bucket * P),
                Psince: &(level_since * P),
                CommitLoxID: &CommitLoxSrv,
                A,
                B,
            },
        )
        .0;

        Ok(Response {
            P,
            BlindLoxQ,
            server_id,
            bucket,
            level_since,
            piBlindIssue,
            bridge_line,
        })
    }
}

/// Handle the reponse to the request, producing the desired Lox
/// credential if successful.
pub fn handle_response(
    state: State,
    resp: Response,
    lox_pub: &IssuerPubKey,
) -> Result<(cred::Lox, BridgeLine), ProofError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;
    let B: &RistrettoPoint = &CMZ_B;

    if resp.P.is_identity() {
        return Err(ProofError::VerificationFailure);
    }

    // Verify the proof
    let mut transcript = Transcript::new(b"open invite issuing");
    blindissue::verify_compact(
        &resp.piBlindIssue,
        &mut transcript,
        blindissue::VerifyAssignments {
            BlindLoxQ: &resp.BlindLoxQ.compress(),
            X0: &lox_pub.X[0].compress(),
            Xbucket: &lox_pub.X[2].compress(),
            Xsince: &lox_pub.X[4].compress(),
            Pbucket: &(resp.bucket * resp.P).compress(),
            Psince: &(resp.level_since * resp.P).compress(),
            CommitLoxID: &(state.s * A
                + state.id_client * lox_pub.X[1]
                + resp.server_id * lox_pub.X[1])
                .compress(),
            A: &A.compress(),
            B: &B.compress(),
            P: &resp.P.compress(),
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
        dump(&format!("open-invite handle reply time {:#?}", duration));
    };

    Ok((
        cred::Lox {
            P: r * resp.P,
            Q,
            id: state.id_client + resp.server_id,
            bucket: resp.bucket,
            trust_level: Scalar::ZERO,
            level_since: resp.level_since,
            invites_remaining: Scalar::ZERO,
            blockages: Scalar::ZERO,
        },
        resp.bridge_line,
    ))
}

#[cfg(all(test, feature = "bridgeauth"))]
mod tests {
    use crate::mock_auth::TestHarness;

    #[test]
    fn test_artifact_open_invitation() {
        println!("\n----OPEN-INVITATION----\n");
        let mut th = TestHarness::new();
        let invite = th.bdb.invite().unwrap();
        let cred = th.open_invite(&invite);
        th.verify_lox(&cred.1 .0);
        th.print_test_results(cred.0)
    }
}
