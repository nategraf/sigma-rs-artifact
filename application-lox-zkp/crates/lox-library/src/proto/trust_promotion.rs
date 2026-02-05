/*! A module for the protocol for the user to get promoted from
untrusted (trust level 0) to trusted (trust level 1).

They are allowed to do this as long as UNTRUSTED_INTERVAL days have
passed since they obtained their level 0 Lox credential, and their
bridge (level 0 users get put in a one-bridge bucket) has not been
blocked.  (Blocked bridges in one-bridge buckets will have their entries
removed from the bridge authority's migration table.)

The user presents their current Lox credential:
- id: revealed
- bucket: blinded
- trust_level: revealed to be 0
- level_since: blinded, but proved in ZK that it's at least
  UNTRUSTED_INTERVAL days ago
- invites_remaining: revealed to be 0
- blockages: revealed to be 0

They will receive in return the encrypted MAC (Pk, EncQk) for their
implicit Migration Key credential with attributes id and bucket,
along with a HashMap of encrypted Migration credentials.  For each
(from_i, to_i) in the BA's migration list, there will be an entry in
the HashMap with key H1(id, from_attr_i, Qk_i) and value
Enc_{H2(id, from_attr_i, Qk_i)}(to_attr_i, P_i, Q_i).  Here H1 and H2
are the first 16 bytes and the second 16 bytes respectively of the
SHA256 hash of the input, P_i and Q_i are a MAC on the Migration
credential with attributes id, from_attr_i, and to_attr_i. Qk_i is the
value EncQk would decrypt to if bucket were equal to from_attr_i. */

use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;

use lox_zkp::CompactProof;
use lox_zkp::ProofError;
use lox_zkp::Transcript;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use std::collections::HashMap;

use super::super::cred;
#[cfg(feature = "bridgeauth")]
use super::super::dup_filter::SeenType;
use super::super::migration_table;
#[cfg(feature = "bridgeauth")]
use super::super::pt_dbl;
#[cfg(feature = "bridgeauth")]
use super::super::BridgeAuth;
use super::super::IssuerPubKey;
use super::super::{scalar_dbl, scalar_u32};
use super::super::{CMZ_A, CMZ_A_TABLE};
#[cfg(feature = "dump")]
use crate::dumper::dump;
#[cfg(feature = "dump")]
use web_time::Instant;

use super::errors::CredentialError;

/// The minimum number of days a user has to be at trust level 0
/// (untrusted) with their (single) bridge unblocked before they can
/// move to level 1.
///
/// The implementation also puts an upper bound of UNTRUSTED_INTERVAL +
/// 511 days, which is not unreasonable; we want users to be engaging
/// with the system in order to move up trust levels.
pub const UNTRUSTED_INTERVAL: u32 = 30;

#[derive(Serialize, Clone, Deserialize)]
pub struct Request {
    // Fields for blind showing the Lox credential
    // We don't need to include trust_level, invites_remaining, or
    // blockages, since they must be 0
    P: RistrettoPoint,
    id: Scalar,
    CBucket: RistrettoPoint,
    CSince: RistrettoPoint,
    CQ: RistrettoPoint,

    // Fields for the inequality proof (level_since +
    // UNTRUSTED_INTERVAL <= today)
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

    // Commitment to the the Migration Key credential to be issued
    CommitMigKeyBlind: RistrettoPoint,

    // The combined ZKP
    piUser: CompactProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    s_mig: Scalar,
    id: Scalar,
    bucket: Scalar,
}

#[serde_as]
#[derive(Serialize, Clone, Deserialize, Debug)]
pub struct Response {
    // The encrypted MAC for the Migration Key credential
    Pk: RistrettoPoint,
    BlindMigKeyQk: RistrettoPoint,

    // A table of encrypted Migration credentials; the encryption keys
    // are formed from the possible values of Qk (the decrypted form of
    // EncQk)
    #[serde_as(as = "Vec<(_,[_; migration_table::ENC_MIGRATION_BYTES])>")]
    enc_migration_table: HashMap<[u8; 16], [u8; migration_table::ENC_MIGRATION_BYTES]>,
}

define_proof! {
    requestproof,
    "Trust Promotion Request",
    (bucket, since, zbucket, zsince, negzQ,
     s_mig,
     g0, g1, g2, g3, g4, g5, g6, g7, g8,
     zg0, zg1, zg2, zg3, zg4, zg5, zg6, zg7, zg8,
     wg0, wg1, wg2, wg3, wg4, wg5, wg6, wg7, wg8,
     yg0, yg1, yg2, yg3, yg4, yg5, yg6, yg7, yg8),
    (P, CBucket, CSince, V, Xbucket, Xsince, Xmig_bucket,
    CommitMigKeyBlind,
     CG0, CG1, CG2, CG3, CG4, CG5, CG6, CG7, CG8,
     CG0sq, CG1sq, CG2sq, CG3sq, CG4sq, CG5sq, CG6sq, CG7sq, CG8sq),
    (A):
    // Blind showing of the Lox credential
    CBucket = (bucket*P + zbucket*A),
    CSince = (since*P + zsince*A),
    V = (zbucket*Xbucket + zsince*Xsince + negzQ*A),
    // User blinding of the Migration Key credential
   CommitMigKeyBlind = (s_mig*A + bucket*Xmig_bucket),
    // Prove CSince encodes a value at least UNTRUSTED_INTERVAL
    // days ago (and technically at most UNTRUSTED_INTERVAL+511 days
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
    CG8 = (g8*P + zg8*A), CG8sq = (g8*CG8 + wg8*A), CG8sq = (g8*P + yg8*A)
    // Then we'll check that CSince + UNTRUSTED_INTERVAL*P + CG0 + 2*CG1
    // + 4*CG2 + 8*CG3 + ... + 256*CG8 = today*P by having the verifier
    // plug in today*P - (CSince + UNTRUSTED_INTERVAL*P + 2*CG1 + 4*CG2
    // + ... + 256*CG8) as its value of CG0.
}

pub fn request(
    lox_cred: &cred::Lox,
    lox_pub: &IssuerPubKey,
    migkey_pub: &IssuerPubKey,
    today: u32,
) -> Result<(Request, State), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;
    let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

    // Ensure the credential can be correctly shown: it must be the case
    // that level_since + UNTRUSTED_INTERVAL <= today.
    let level_since: u32 = match scalar_u32(&lox_cred.level_since) {
        Some(v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("level_since"),
                String::from("could not be converted to u32"),
            ))
        }
    };
    if level_since + UNTRUSTED_INTERVAL > today {
        return Err(CredentialError::TimeThresholdNotMet(
            level_since + UNTRUSTED_INTERVAL - today,
        ));
    }
    let diffdays = today - (level_since + UNTRUSTED_INTERVAL);
    if diffdays > 511 {
        return Err(CredentialError::CredentialExpired);
    }

    // Blind showing the Lox credential

    // Reblind P and Q
    let mut rng = rand::rngs::OsRng;
    let t = Scalar::random(&mut rng);
    let P = t * lox_cred.P;
    let Q = t * lox_cred.Q;

    // Form Pedersen commitments to the blinded attributes
    let zbucket = Scalar::random(&mut rng);
    let zsince = Scalar::random(&mut rng);
    let CBucket = lox_cred.bucket * P + &zbucket * Atable;
    let CSince = lox_cred.level_since * P + &zsince * Atable;

    // Form a Pedersen commitment to the MAC Q
    // We flip the sign of zQ from that of the Hyphae paper so that
    // the ZKP has a "+" instead of a "-", as that's what the zkp
    // macro supports.
    let negzQ = Scalar::random(&mut rng);
    let CQ = Q - &negzQ * Atable;

    // Compute the "error factor"
    let V = zbucket * lox_pub.X[2] + zsince * lox_pub.X[4] + &negzQ * Atable;

    // User blinding the Migration Key credential
    let s_mig = Scalar::random(&mut rng);

    // Commit to the migration key credential values with sum(m_i*X_i) + s * A
    // where A is our generator
    let CommitMigKeyBlind = s_mig * A + (lox_cred.bucket * migkey_pub.X[2]);

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

    // Construct the proof
    let mut transcript = Transcript::new(b"trust promotion request");
    let piUser = requestproof::prove_compact(
        &mut transcript,
        requestproof::ProveAssignments {
            A,
            P: &P,
            CBucket: &CBucket,
            CSince: &CSince,
            V: &V,
            Xbucket: &lox_pub.X[2],
            Xsince: &lox_pub.X[4],
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
            bucket: &lox_cred.bucket,
            since: &lox_cred.level_since,
            zbucket: &zbucket,
            zsince: &zsince,
            negzQ: &negzQ,
            s_mig: &s_mig,
            Xmig_bucket: &migkey_pub.X[2],
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
            CommitMigKeyBlind: &CommitMigKeyBlind,
        },
    )
    .0;
    #[cfg(feature = "dump")]
    let duration = now.elapsed();
    #[cfg(feature = "dump")]
    let _dumper = if cfg!(feature = "dump") {
        dump(&format!("trust-promo client request time {:#?}", duration));
    };
    Ok((
        Request {
            P,
            id: lox_cred.id,
            CBucket,
            CSince,
            CQ,
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
            CommitMigKeyBlind,
            piUser,
        },
        State {
            s_mig,
            id: lox_cred.id,
            bucket: lox_cred.bucket,
        },
    ))
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    /// Receive a trust promotion request
    pub fn handle_trust_promotion(&mut self, req: Request) -> Result<Response, ProofError> {
        let A: &RistrettoPoint = &CMZ_A;
        let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

        if req.P.is_identity() {
            return Err(ProofError::VerificationFailure);
        }

        // Recompute the "error factor" using knowledge of our own
        // (the issuer's) private key instead of knowledge of the
        // hidden attributes
        let Vprime = (self.lox_priv.x[0] + self.lox_priv.x[1] * req.id) * req.P
            + self.lox_priv.x[2] * req.CBucket
            + self.lox_priv.x[4] * req.CSince
            - req.CQ;

        // Recompute CG0 using Horner's method
        let today: Scalar = self.today().into();
        let unt: Scalar = UNTRUSTED_INTERVAL.into();
        let CG0prime = (today - unt) * req.P
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

        // Verify the ZKP
        let mut transcript = Transcript::new(b"trust promotion request");
        requestproof::verify_compact(
            &req.piUser,
            &mut transcript,
            requestproof::VerifyAssignments {
                A: &A.compress(),
                P: &req.P.compress(),
                CBucket: &req.CBucket.compress(),
                CSince: &req.CSince.compress(),
                V: &Vprime.compress(),
                Xbucket: &self.lox_pub.X[2].compress(),
                Xsince: &self.lox_pub.X[4].compress(),
                Xmig_bucket: &self.migrationkey_pub.X[2].compress(),
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
                CommitMigKeyBlind: &req.CommitMigKeyBlind.compress(),
            },
        )?;

        // Ensure the id has not been seen before, either in the general
        // id filter, or the filter specifically for trust promotion.
        // Add the id to the latter, but not the former.
        if self.id_filter.check(&req.id) == SeenType::Seen
            || self.trust_promotion_filter.filter(&req.id) == SeenType::Seen
        {
            return Err(ProofError::VerificationFailure);
        }

        // Compute the encrypted MAC (Pk, EncQk) for the Migration Key
        // credential.

        // Compute the MAC on the visible attributes
        let mut rng = rand::rngs::OsRng;
        let b = Scalar::random(&mut rng);
        let Pk = &b * Atable;
        let Pktable = RistrettoBasepointTable::create(&Pk);
        let Qid = &(self.migrationkey_priv.x[0] + self.migrationkey_priv.x[1] * req.id) * &Pktable;

        let BlindMigKeyQk = b * req.CommitMigKeyBlind + Qid;

        Ok(Response {
            Pk,
            BlindMigKeyQk,
            enc_migration_table: self.trustup_migration_table.encrypt_table(
                &req.id,
                &self.bridge_table,
                &Pktable,
                &self.migration_priv,
                &self.migrationkey_priv,
            ),
        })
    }
}

/// Handle the response to the request, producing a Migration credential
/// if successful.
///
/// The Migration credential can then be used in the migration protocol
/// to actually upgrade to trust level 1.
pub fn handle_response(state: State, resp: Response) -> Result<cred::Migration, ProofError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    if resp.Pk.is_identity() {
        return Err(ProofError::VerificationFailure);
    }

    // Decrypt MAC on BlindMigKeyQ
    let Qk = resp.BlindMigKeyQk - state.s_mig * resp.Pk;

    // Use Qk to locate and decrypt the Migration credential
    match migration_table::decrypt_cred(
        &Qk,
        &state.id,
        &state.bucket,
        migration_table::MigrationType::TrustUpgrade,
        &resp.enc_migration_table,
    ) {
        Some(m) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "trust-promo client handle reply time {:#?}",
                    duration
                ));
            };
            Ok(m)
        }
        None => Err(ProofError::VerificationFailure),
    }
}

#[cfg(all(test, feature = "bridgeauth"))]
mod tests {
    use crate::mock_auth::TestHarness;

    #[test]
    fn test_artifact_trust_promotion() {
        println!("\n----TRUST-PROMOTION-1: 30 days---\n");
        let mut th = TestHarness::new();
        let invite = th.bdb.invite().unwrap();
        let (_, lox_cred) = th.open_invite(&invite);
        let (perf_stat, mig_cred) = th.trust_promotion(lox_cred.0);
        th.verify_migration(&mig_cred);
        th.print_test_results(perf_stat);
    }
}
