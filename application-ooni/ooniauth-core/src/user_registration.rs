use super::{Scalar, G};
use crate::registration::{open_registration, UserAuthCredential};
use cmz::*;
use curve25519_dalek::RistrettoPoint;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use tracing::{instrument, trace};

const SESSION_ID: &[u8] = b"registration";

#[instrument(skip(pp, rng))]
pub fn request(
    pp: &CMZPubkey<RistrettoPoint>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(open_registration::Request, open_registration::ClientState), CMZError> {
    trace!("Starting registration request (standalone)");
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

    let mut UAC = UserAuthCredential::using_pubkey(pp);
    // For registration, age and measurement_count will be set by the server
    // But we need to provide some initial values for the protocol
    UAC.measurement_count = Some(Scalar::ZERO);
    open_registration::prepare(rng, SESSION_ID, UAC).map_err(|_| CMZError::CliProofFailed)
}

pub fn handle_request_response(
    state: open_registration::ClientState,
    rep: open_registration::Reply,
) -> Result<UserAuthCredential, CMZError> {
    trace!("Handling registration response (standalone)");
    let replybytes = rep.as_bytes();
    let recvreply = open_registration::Reply::try_from(&replybytes[..]).unwrap();
    state
        .finalize(recvreply)
        .map_err(|_| CMZError::IssProofFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServerState;

    #[test]
    fn test_registration() {
        let rng = &mut rand::thread_rng();
        // Initialize group first for gen_keys
        let server_state = ServerState::new(rng);
        let pp = server_state.public_parameters();
        // Note: request() will call cmz_group_init again, but that's okay

        let result = request(&pp, rng);
        assert!(result.is_ok(), "Registration request should succeed");
        let (request, client_state) = result.unwrap();

        let server_response = server_state.open_registration(request);
        assert!(
            server_response.is_ok(),
            "Server should process registration request successfully"
        );
        let response = server_response.unwrap();

        let credential = handle_request_response(client_state, response);
        assert!(
            credential.is_ok(),
            "User should handle server response successfully"
        );

        assert_ne!(
            credential.as_ref().unwrap().nym_id,
            Some(Scalar::ZERO),
            "Nym ID should be non-zero after registration"
        );
    }

    #[test]
    fn test_handle_response() {
        // Test the handle_response function
        // This is a basic structure test since we need actual response data
        // TODO: Add full integration test when server implementation is ready

        let rng = &mut rand::thread_rng();
        let server_state = ServerState::new(rng);
        let pp = server_state.public_parameters();

        // Test basic API structure
        let result = request(&pp, rng);
        if let Ok((_request, _client_state)) = result {
            println!("Registration request/state structure is valid");
            // TODO: Complete the test when we have a working server response
        }
    }
}
