/*! A module for the protocol for the user to check for the availability
of a migration credential they can use in order to move to a new bucket
if theirs has been blocked.

The user presents their current Lox credential:
- id: revealed
- bucket: blinded
- trust_level: revealed to be 3 or above
- level_since: blinded
- invites_remaining: blinded
- blockages: blinded

They are allowed to to this as long as they are level 3 or above.  If
they have too many blockages (but are level 3 or above), they will be
allowed to perform this migration, but will not be able to advance to
level 3 in their new bucket, so this will be their last allowed
migration without rejoining the system either with a new invitation or
an open invitation.

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

#[cfg(feature = "dump")]
use crate::dumper::dump;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
#[cfg(feature = "dump")]
use web_time::Instant;

use std::collections::HashMap;

use super::super::cred;
#[cfg(feature = "bridgeauth")]
use super::super::dup_filter::SeenType;
use super::super::migration_table;
use super::super::scalar_u32;
#[cfg(feature = "bridgeauth")]
use super::super::BridgeAuth;
use super::super::IssuerPubKey;
use super::super::{CMZ_A, CMZ_A_TABLE};

use super::errors::CredentialError;

/// The minimum trust level a Lox credential must have to be allowed to
/// perform this protocol.
pub const MIN_TRUST_LEVEL: u32 = 3;

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

    // Commitment to the the Migration Key credential to be issued
    CommitMigKeyBlind: RistrettoPoint,

    // The combined lox_zkp
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
    // BlindMigKeyQk)
    #[serde_as(as = "Vec<(_,[_; migration_table::ENC_MIGRATION_BYTES])>")]
    enc_migration_table: HashMap<[u8; 16], [u8; migration_table::ENC_MIGRATION_BYTES]>,
}

define_proof! {
    requestproof,
    "Check Blockage Request",
    (bucket, since, invremain, blockages, zbucket, zsince, zinvremain,
     zblockages, negzQ, s_mig),
    (P, CBucket, CSince, CInvRemain, CBlockages, V, Xbucket, Xsince,
     Xinvremain, Xblockages, Xmig_bucket, CommitMigKeyBlind),
    (A):
    // Blind showing of the Lox credential
    CBucket = (bucket*P + zbucket*A),
    CSince = (since*P + zsince*A),
    CInvRemain = (invremain*P + zinvremain*A),
    CBlockages = (blockages*P + zblockages*A),
    V = (zbucket*Xbucket + zsince*Xsince + zinvremain*Xinvremain
        + zblockages*Xblockages + negzQ*A),
    // User blinding of the Migration Key credential
    CommitMigKeyBlind = (s_mig*A + bucket*Xmig_bucket)
}

pub fn request(
    lox_cred: &cred::Lox,
    lox_pub: &IssuerPubKey,
    migkey_pub: &IssuerPubKey,
) -> Result<(Request, State), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let A: &RistrettoPoint = &CMZ_A;
    let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

    // Ensure the credential can be correctly shown: it must be the case
    // that trust_level >= MIN_TRUST_LEVEL
    let level: u32 = match scalar_u32(&lox_cred.trust_level) {
        Some(v) => v,
        None => {
            return Err(CredentialError::InvalidField(
                String::from("trust_level"),
                String::from("could not be converted to u32"),
            ))
        }
    };
    if level < MIN_TRUST_LEVEL {
        return Err(CredentialError::InvalidField(
            String::from("trust_level"),
            format!("level {level} not in range"),
        ));
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
    let zinvremain = Scalar::random(&mut rng);
    let zblockages = Scalar::random(&mut rng);
    let CBucket = lox_cred.bucket * P + &zbucket * Atable;
    let CSince = lox_cred.level_since * P + &zsince * Atable;
    let CInvRemain = lox_cred.invites_remaining * P + &zinvremain * Atable;
    let CBlockages = lox_cred.blockages * P + &zblockages * Atable;

    // Form a Pedersen commitment to the MAC Q
    // We flip the sign of zQ from that of the Hyphae paper so that
    // the lox_zkp has a "+" instead of a "-", as that's what the lox_zkp
    // macro supports.
    let negzQ = Scalar::random(&mut rng);
    let CQ = Q - &negzQ * Atable;

    // Compute the "error factor"
    let V = zbucket * lox_pub.X[2]
        + zsince * lox_pub.X[4]
        + zinvremain * lox_pub.X[5]
        + zblockages * lox_pub.X[6]
        + &negzQ * Atable;

    // User blinding the Migration Key credential

    // Pick a scalar to randomize our commitment to the migration key credential
    let s_mig = Scalar::random(&mut rng);

    // Commit to the migration key credential values with sum(m_i*X_i) + s * A
    // where A is our generator
    let CommitMigKeyBlind = s_mig * A + (lox_cred.bucket * migkey_pub.X[2]);

    // Construct the proof
    let mut transcript = Transcript::new(b"check blockage request");
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
            bucket: &lox_cred.bucket,
            since: &lox_cred.level_since,
            invremain: &lox_cred.invites_remaining,
            blockages: &lox_cred.blockages,
            zbucket: &zbucket,
            zsince: &zsince,
            zinvremain: &zinvremain,
            zblockages: &zblockages,
            negzQ: &negzQ,
            s_mig: &s_mig,
            Xmig_bucket: &migkey_pub.X[2],
            CommitMigKeyBlind: &CommitMigKeyBlind,
        },
    )
    .0;
    #[cfg(feature = "dump")]
    let duration = now.elapsed();
    #[cfg(feature = "dump")]
    let _dumper = if cfg!(feature = "dump") {
        dump(&format!(
            "check-blockage client request time {:#?}",
            duration
        ));
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
    /// Receive a check blockage request
    pub fn handle_check_blockage(&mut self, req: Request) -> Result<Response, ProofError> {
        let A: &RistrettoPoint = &CMZ_A;
        let Atable: &RistrettoBasepointTable = &CMZ_A_TABLE;

        let level: u32 = match scalar_u32(&req.level) {
            Some(v) => v,
            None => return Err(ProofError::VerificationFailure),
        };

        if req.P.is_identity() || level < MIN_TRUST_LEVEL {
            return Err(ProofError::VerificationFailure);
        }

        // Recompute the "error factor" using knowledge of our own
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

        // Verify the zkp
        let mut transcript = Transcript::new(b"check blockage request");
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
                Xbucket: &self.lox_pub.X[2].compress(),
                Xsince: &self.lox_pub.X[4].compress(),
                Xinvremain: &self.lox_pub.X[5].compress(),
                Xblockages: &self.lox_pub.X[6].compress(),
                Xmig_bucket: &self.migrationkey_pub.X[2].compress(),
                CommitMigKeyBlind: &req.CommitMigKeyBlind.compress(),
            },
        )?;

        // Ensure the id has not been seen before in the general id
        // filter, but do not add it, so that the user can potentially
        // run this protocol multiple times.
        if self.id_filter.check(&req.id) == SeenType::Seen {
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
            enc_migration_table: self.blockage_migration_table.encrypt_table(
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
/// to actually change buckets
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
        migration_table::MigrationType::Blockage,
        &resp.enc_migration_table,
    ) {
        Some(m) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "check-blockage client handle reply time {:#?}",
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
    fn test_artifact_check_blockage() {
        println!("\n----CHECK-BLOCKAGE----\n");
        let mut th = TestHarness::new();
        let invite = th.bdb.invite().unwrap();
        let (_, lox_cred) = th.open_invite(&invite);
        let (_, mig_cred) = th.trust_promotion(lox_cred.0.clone());
        let (_, lox_cred) = th.migration(lox_cred.0.clone(), mig_cred.clone());
        let (_, lox_cred_1) = th.level_up(lox_cred.clone());
        let (_, lox_cred_2) = th.level_up(lox_cred_1.clone());
        let (_, lox_cred_3) = th.level_up(lox_cred_2.clone());
        th.block_bridges(lox_cred_3.clone());
        let (perf_stat, mig_cred1) = th.check_blockage(lox_cred_3.clone());
        println!("Migration cred: {:?}", mig_cred);
        th.verify_migration(&mig_cred1);
        th.print_test_results(perf_stat)
    }
}
