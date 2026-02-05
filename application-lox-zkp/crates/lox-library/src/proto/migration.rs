/*! A module for the protocol for the user to migrate from one bucket to
another and change trust level from untrusted (trust level 0) to trusted
(trust level 1).

The user presents their current Lox credential:

- id: revealed
- bucket: blinded
- trust_level: revealed to be 0
- level_since: blinded
- invites_remaining: revealed to be 0
- blockages: revealed to be 0

and a Migration credential:

- id: revealed as the same as the Lox credential id above
- from_bucket: blinded, but proved in ZK that it's the same as the
  bucket in the Lox credential above
- to_bucket: blinded

and a new Lox credential to be issued:

- id: jointly chosen by the user and BA
- bucket: blinded, but proved in ZK that it's the same as the to_bucket
  in the Migration credential above
- trust_level: 1
- level_since: today
- invites_remaining: 0
- blockages: 0

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
#[cfg(feature = "dump")]
use web_time::Instant;

use super::errors::CredentialError;

#[derive(Serialize, Clone, Deserialize)]
pub struct Request {
    // Fields for blind showing the Lox credential
    // We don't need to include invites_remaining or blockages,
    // since they must be 0
    P_lox: RistrettoPoint,
    id: Scalar,
    CBucket: RistrettoPoint,
    trust_level: Scalar,
    CSince: RistrettoPoint,
    CQ_lox: RistrettoPoint,

    // Fields for blind showing the Migration credential
    P_mig: RistrettoPoint,
    CFromBucket: RistrettoPoint,
    CToBucket: RistrettoPoint,
    CQ_mig: RistrettoPoint,

    // Commitment to the Lox credential to be issued
    CommitLoxBlind: RistrettoPoint,

    // The combined ZKP
    piUser: CompactProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    s: Scalar,
    id_client: Scalar,
    to_bucket: Scalar,
}

#[derive(Serialize, Clone, Deserialize)]
pub struct Response {
    // The new attributes; trust_level = 1 is implicit
    level_since: Scalar,
    server_id: Scalar,
    // The fields for the new Lox credential
    P: RistrettoPoint,
    BlindLoxQ: RistrettoPoint,
    // The ZKP
    piBlindIssue: CompactProof,
}

define_proof! {
    requestproof,
    "Migration Request",
    (bucket, since, zbucket, zsince, negzQ_lox,
     tobucket, zfrombucket, ztobucket, negzQ_mig,
     s, id_client),
    (P_lox, CBucket, CSince, V_lox, Xid, Xbucket, Xsince,
     P_mig, CFromBucket, CToBucket, V_mig, Xfrombucket, Xtobucket,
     CommitLoxBlind),
    (A):
    // Blind showing of the Lox credential
    CBucket = (bucket*P_lox + zbucket*A),
    CSince = (since*P_lox + zsince*A),
    V_lox = (zbucket*Xbucket + zsince*Xsince + negzQ_lox*A),
    // Blind showing of the Migration credential; note the use of the
    // same "bucket" secret variable
    CFromBucket = (bucket*P_mig + zfrombucket*A),
    CToBucket = (tobucket*P_mig + ztobucket*A),
    V_mig = (zfrombucket*Xfrombucket + ztobucket*Xtobucket + negzQ_mig*A),
    // User blinding of the Lox credential to be issued; note the use of
    // the same "tobucket" secret variable
    // User blinding of the Lox credential to be issued
    CommitLoxBlind = (s*A + id_client * Xid + tobucket * Xbucket)
}

define_proof! {
    blindissue,
    "Migration Blind Issuing",
    (x0, x0tilde, xlevel, xsince, b),
    (P, BlindLoxQ, X0, Xlevel, Xsince, Plevel, Psince, CommitLoxBlind),
    (A, B):
    Xlevel = (xlevel*A),
    Xsince = (xsince*A),
    X0 = (x0*B + x0tilde*A),
    P = (b*A),
    BlindLoxQ = (b*CommitLoxBlind + x0 * P + xlevel * Plevel + xsince * Psince)
}

pub fn request(
    lox_cred: &cred::Lox,
    migration_cred: &cred::Migration,
    lox_pub: &IssuerPubKey,
    migration_pub: &IssuerPubKey,
) -> Result<(Request, State), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;
    let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

    // Ensure that the credenials can be correctly shown; that is, the
    // ids match and the Lox credential bucket matches the Migration
    // credential from_bucket
    if lox_cred.id != migration_cred.lox_id || lox_cred.bucket != migration_cred.from_bucket {
        return Err(CredentialError::CredentialMismatch);
    }

    // This protocol only allows migrating from trust level 0 to trust
    // level 1
    if lox_cred.trust_level != Scalar::ZERO {
        return Err(CredentialError::InvalidField(
            String::from("trust_level"),
            String::from("must be zero"),
        ));
    }

    // Blind showing the Lox credential

    // Reblind P and Q
    let mut rng = rand::rngs::OsRng;
    let t_lox = Scalar::random(&mut rng);
    let P_lox = t_lox * lox_cred.P;
    let Q_lox = t_lox * lox_cred.Q;

    // Form Pedersen commitments to the blinded attributes
    let zbucket = Scalar::random(&mut rng);
    let zsince = Scalar::random(&mut rng);
    let CBucket = lox_cred.bucket * P_lox + &zbucket * Atable;
    let CSince = lox_cred.level_since * P_lox + &zsince * Atable;

    // Form a Pedersen commitment to the MAC Q
    // We flip the sign of zQ from that of the Hyphae paper so that
    // the ZKP has a "+" instead of a "-", as that's what the zkp
    // macro supports.
    let negzQ_lox = Scalar::random(&mut rng);
    let CQ_lox = Q_lox - &negzQ_lox * Atable;

    // Compute the "error factor"
    let V_lox = zbucket * lox_pub.X[2] + zsince * lox_pub.X[4] + &negzQ_lox * Atable;

    // Blind showing the Migration credential

    // Reblind P and Q
    let t_mig = Scalar::random(&mut rng);
    let P_mig = t_mig * migration_cred.P;
    let Q_mig = t_mig * migration_cred.Q;

    // Form Pedersen commitments to the blinded attributes
    let zfrombucket = Scalar::random(&mut rng);
    let ztobucket = Scalar::random(&mut rng);
    let CFromBucket = migration_cred.from_bucket * P_mig + &zfrombucket * Atable;
    let CToBucket = migration_cred.to_bucket * P_mig + &ztobucket * Atable;

    // Form a Pedersen commitment to the MAC Q
    // We flip the sign of zQ from that of the Hyphae paper so that
    // the ZKP has a "+" instead of a "-", as that's what the zkp
    // macro supports.
    let negzQ_mig = Scalar::random(&mut rng);
    let CQ_mig = Q_mig - &negzQ_mig * Atable;

    // Compute the "error factor"
    let V_mig =
        zfrombucket * migration_pub.X[2] + ztobucket * migration_pub.X[3] + &negzQ_mig * Atable;

    // User blinding for the Lox certificate to be issued

    // Pick a random client component of the id
    let id_client = Scalar::random(&mut rng);

    // Pick a scalar to randomize our commitment
    let s = Scalar::random(&mut rng);

    // Commit to the new credential values with sum(m_i*X_i) + s * A
    // where A is our generator
    let CommitLoxBlind =
        s * A + (id_client * lox_pub.X[1] + migration_cred.to_bucket * lox_pub.X[2]);

    // Construct the proof
    let mut transcript = Transcript::new(b"migration request");
    let piUser = requestproof::prove_compact(
        &mut transcript,
        requestproof::ProveAssignments {
            A,
            P_lox: &P_lox,
            CBucket: &CBucket,
            CSince: &CSince,
            V_lox: &V_lox,
            Xid: &lox_pub.X[1],
            Xbucket: &lox_pub.X[2],
            Xsince: &lox_pub.X[4],
            P_mig: &P_mig,
            CFromBucket: &CFromBucket,
            CToBucket: &CToBucket,
            V_mig: &V_mig,
            Xfrombucket: &migration_pub.X[2],
            Xtobucket: &migration_pub.X[3],
            bucket: &lox_cred.bucket,
            since: &lox_cred.level_since,
            zbucket: &zbucket,
            zsince: &zsince,
            negzQ_lox: &negzQ_lox,
            tobucket: &migration_cred.to_bucket,
            zfrombucket: &zfrombucket,
            ztobucket: &ztobucket,
            negzQ_mig: &negzQ_mig,
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
        dump(&format!("migration client request time {:#?}", duration));
    };

    Ok((
        Request {
            P_lox,
            id: lox_cred.id,
            CBucket,
            trust_level: lox_cred.trust_level,
            CSince,
            CQ_lox,
            P_mig,
            CFromBucket,
            CToBucket,
            CQ_mig,
            CommitLoxBlind,
            piUser,
        },
        State {
            s,
            id_client,
            to_bucket: migration_cred.to_bucket,
        },
    ))
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    /// Receive a migration request
    pub fn handle_migration(&mut self, req: Request) -> Result<Response, ProofError> {
        let A: &RistrettoPoint = &CMZ_A;
        let B: &RistrettoPoint = &CMZ_B;
        let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

        if req.P_lox.is_identity() || req.P_mig.is_identity() {
            return Err(ProofError::VerificationFailure);
        }

        // We only currently support migrating from trust level 0
        if req.trust_level != Scalar::ZERO {
            return Err(ProofError::VerificationFailure);
        }

        // Recompute the "error factors" using knowledge of our own
        // (the issuer's) private key instead of knowledge of the
        // hidden attributes
        let Vprime_lox = (self.lox_priv.x[0]
            + self.lox_priv.x[1] * req.id
            + self.lox_priv.x[3] * req.trust_level)
            * req.P_lox
            + self.lox_priv.x[2] * req.CBucket
            + self.lox_priv.x[4] * req.CSince
            - req.CQ_lox;

        let Vprime_mig = (self.migration_priv.x[0] + self.migration_priv.x[1] * req.id) * req.P_mig
            + self.migration_priv.x[2] * req.CFromBucket
            + self.migration_priv.x[3] * req.CToBucket
            - req.CQ_mig;

        // Verify the ZKP
        let mut transcript = Transcript::new(b"migration request");
        requestproof::verify_compact(
            &req.piUser,
            &mut transcript,
            requestproof::VerifyAssignments {
                A: &A.compress(),
                P_lox: &req.P_lox.compress(),
                CBucket: &req.CBucket.compress(),
                CSince: &req.CSince.compress(),
                V_lox: &Vprime_lox.compress(),
                Xid: &self.lox_pub.X[1].compress(),
                Xbucket: &self.lox_pub.X[2].compress(),
                Xsince: &self.lox_pub.X[4].compress(),
                P_mig: &req.P_mig.compress(),
                CFromBucket: &req.CFromBucket.compress(),
                CToBucket: &req.CToBucket.compress(),
                V_mig: &Vprime_mig.compress(),
                Xfrombucket: &self.migration_pub.X[2].compress(),
                Xtobucket: &self.migration_pub.X[3].compress(),
                CommitLoxBlind: &req.CommitLoxBlind.compress(),
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
        // level 1
        let trust_level: Scalar = Scalar::ONE;

        // Create the level_since attribute (Scalar), which is today's
        // Julian date
        let level_since: Scalar = self.today().into();

        // The invitations_remaining and blockages attributes are 0 for
        // level 0 and level 1 Lox credentials, so we don't need to
        // explicitly create them.

        // Compute the MAC on the visible attributes
        let b = Scalar::random(&mut rng);
        let P = &b * Atable;

        // Create server contribution of the Lox id
        let server_id = Scalar::random(&mut rng);

        // Append the server id to the client's commitment
        let CommitLoxSrv = req.CommitLoxBlind + (server_id * self.lox_pub.X[1]);

        // invites_remaining = blockages = 0
        let BlindLoxQ = b * CommitLoxSrv
            + (self.lox_priv.x[0]
                + self.lox_priv.x[3] * trust_level
                + self.lox_priv.x[4] * level_since)
                * P;

        let mut transcript = Transcript::new(b"migration issuing");
        let piBlindIssue = blindissue::prove_compact(
            &mut transcript,
            blindissue::ProveAssignments {
                A,
                B,
                P: &P,
                X0: &self.lox_pub.X[0],
                Xlevel: &self.lox_pub.X[3],
                Xsince: &self.lox_pub.X[4],
                Plevel: &(trust_level * P),
                Psince: &(level_since * P),
                x0: &self.lox_priv.x[0],
                x0tilde: &self.lox_priv.x0tilde,
                xlevel: &self.lox_priv.x[3],
                xsince: &self.lox_priv.x[4],
                b: &b,
                BlindLoxQ: &BlindLoxQ,
                CommitLoxBlind: &CommitLoxSrv,
            },
        )
        .0;

        Ok(Response {
            level_since,
            server_id,
            P,
            BlindLoxQ,
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
    let mut transcript = Transcript::new(b"migration issuing");
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
            // The new trust level is 1
            Plevel: &(Scalar::ONE * resp.P).compress(),
            Psince: &(resp.level_since * resp.P).compress(),
            BlindLoxQ: &resp.BlindLoxQ.compress(),
            CommitLoxBlind: &(state.s * A
                + state.id_client * lox_pub.X[1]
                + resp.server_id * lox_pub.X[1]
                + state.to_bucket * lox_pub.X[2])
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
        dump(&format!(
            "migration client handle response time {:#?}",
            duration
        ));
    };

    Ok(cred::Lox {
        P: r * resp.P,
        Q,
        id: state.id_client + resp.server_id,
        bucket: state.to_bucket,
        trust_level: Scalar::ONE,
        level_since: resp.level_since,
        invites_remaining: Scalar::ZERO,
        blockages: Scalar::ZERO,
    })
}

#[cfg(all(test, feature = "bridgeauth"))]
mod tests {
    use crate::mock_auth::TestHarness;

    #[test]
    fn test_artifact_trust_migration() {
        println!("\n----TRUST-MIGRATION-0: 30 days----\n");
        let mut th = TestHarness::new();
        let invite = th.bdb.invite().unwrap();
        let (_, lox_cred) = th.open_invite(&invite);
        let (_, mig_cred) = th.trust_promotion(lox_cred.0.clone());
        let (perf_stat, new_lox) = th.migration(lox_cred.0.clone(), mig_cred.clone());
        th.verify_lox(&new_lox);
        th.print_test_results(perf_stat);
    }
}
