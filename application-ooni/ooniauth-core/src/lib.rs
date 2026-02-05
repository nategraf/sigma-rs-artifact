// We want Scalars to be lowercase letters, and Points and credentials
// to be capital letters
#![allow(non_snake_case)]

use cmz::*;
use curve25519_dalek::ristretto::RistrettoPoint as G;
use group::Group;
type Scalar = <G as Group>::Scalar;
use rand::{CryptoRng, RngCore};
use registration::UserAuthCredential;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use subtle::ConstantTimeEq;
pub mod errors;
pub mod registration;
pub mod submit;
pub mod update;
pub mod user_registration;
pub mod user_submit;

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerState {
    /// The private key for the main User Auth credential
    sk: SecretKey,
    pp: PublicParameters,
}

pub type PublicParameters = CMZPubkey<G>;
pub type SecretKey = CMZPrivkey<G>;

pub struct UserState {
    /// The public parameters for the client
    pub pp: PublicParameters,
    pub(crate) credential: Option<UserAuthCredential>,
}

impl ServerState {
    pub fn new(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        // Initialization
        cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));
        // Create the private key and public parameters for each of the types of
        // credential with 'true' to indicate uCMZ
        let (sk, pp) = UserAuthCredential::gen_keys(rng, true);
        Self { sk, pp }
    }

    pub fn secret_key_ref(&self) -> &SecretKey {
        &self.sk
    }

    pub fn public_parameters_ref(&self) -> &PublicParameters {
        &self.pp
    }

    pub fn from_creds(sk: SecretKey, pp: PublicParameters) -> Self {
        Self { sk, pp }
    }

    /// Get the public parameters for credential operations
    pub fn public_parameters(&self) -> PublicParameters {
        self.pp.clone()
    }

    /// Get today's (real or simulated) date as u32
    pub fn today() -> u32 {
        // We will not encounter negative Julian dates (~6700 years ago)
        // or ones larger than 32 bits
        (time::OffsetDateTime::now_utc().date())
            .to_julian_day()
            .try_into()
            .unwrap()
    }
}

impl UserState {
    pub fn new(pp: CMZPubkey<G>) -> Self {
        cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

        Self {
            pp,
            credential: None,
        }
    }

    /// Get a reference to the current credential
    pub fn get_credential(&self) -> Option<&UserAuthCredential> {
        self.credential.as_ref()
    }
}

// Try to extract a u32 from a Scalar
#[inline]
pub fn scalar_u32(s: &Scalar) -> Option<u32> {
    // Check that the top 28 bytes of the Scalar are 0
    let sbytes: &[u8; 32] = s.as_bytes();
    if sbytes[4..].ct_eq(&[0u8; 28]).unwrap_u8() == 0 {
        return None;
    }
    Some(u32::from_le_bytes(sbytes[..4].try_into().unwrap()))
}
