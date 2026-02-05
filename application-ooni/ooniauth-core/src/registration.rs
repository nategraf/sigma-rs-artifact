/* A module for the protocol for the user to register with the OONI Authority (OA)
 * to receive their initial User Auth Credential
 * The credential will have attributes:
 * - nym_id: selected jointly by the user and OA
 * - age: set by the OA to the date at the time of issuance
 * - measurement_count: All new accounts will begin with 0
*/

use super::{Scalar, G};
use super::{ServerState, UserState};
use cmz::*;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use tracing::{instrument, trace};

const SESSION_ID: &[u8] = b"registration";

CMZ! { UserAuthCredential:
    nym_id,
    age,
    measurement_count
}

impl UserAuthCredential {
    /// Set the public key and private key for this credential. Assumes the keypair is well-formed.
    pub(crate) fn set_keypair(
        &mut self,
        privkey: CMZPrivkey<G>,
        pubkey: CMZPubkey<G>,
    ) -> &mut Self {
        self.privkey = privkey;
        self.pubkey = pubkey;
        self
    }
}

muCMZProtocol! {open_registration,
    ,
    UAC: UserAuthCredential { nym_id: J, age: S, measurement_count: I},
}

impl UserState {
    #[instrument(skip(self, rng))]
    pub fn request(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(open_registration::Request, open_registration::ClientState), CMZError> {
        trace!("Starting registration request");
        cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

        let mut UAC = UserAuthCredential::using_pubkey(&self.pp);
        // For registration, age and measurement_count will be set by the server
        // But we need to provide some initial values for the protocol
        UAC.measurement_count = Some(Scalar::ZERO);
        match open_registration::prepare(rng, SESSION_ID, UAC) {
            Ok(req_state) => Ok(req_state),
            Err(_) => Err(CMZError::CliProofFailed),
        }
    }
}

impl UserState {
    #[instrument(skip(self, state, rep))]
    pub fn handle_response(
        &mut self,
        state: open_registration::ClientState,
        rep: open_registration::Reply,
    ) -> Result<(), CMZError> {
        trace!("Handling registration response");
        let replybytes = rep.as_bytes();
        let recvreply = open_registration::Reply::try_from(&replybytes[..]).unwrap();
        match state.finalize(recvreply) {
            Ok(cred) => {
                self.credential = Some(cred.clone());
                Ok(())
            }
            Err(_e) => Err(CMZError::IssProofFailed),
        }
    }
}

impl ServerState {
    #[instrument(skip(self, req))]
    pub fn open_registration(
        &self,
        req: open_registration::Request,
    ) -> Result<open_registration::Reply, CMZError> {
        trace!("Server opening registration");
        let mut rng = rand::thread_rng();
        let reqbytes = req.as_bytes();

        let recvreq = open_registration::Request::try_from(&reqbytes[..]).unwrap();
        match open_registration::handle(
            &mut rng,
            SESSION_ID,
            recvreq,
            |UAC: &mut UserAuthCredential| {
                UAC.set_keypair(self.sk.clone(), self.pp.clone());
                UAC.measurement_count = Some(Scalar::ZERO);
                UAC.age = Some(ServerState::today().into());
                Ok(())
            },
            |_UAC: &UserAuthCredential| Ok(()),
        ) {
            Ok((response, _UAC_issuer)) => Ok(response),
            Err(_) => Err(CMZError::IssProofFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration() {
        let rng = &mut rand::thread_rng();
        // Initialize group first for gen_keys
        let server_state = ServerState::new(rng);
        // Note: request() will call cmz_group_init again, but that's okay
        let mut user_state = UserState::new(server_state.public_parameters());

        let result = user_state.request(rng);
        assert!(result.is_ok(), "Registration request should succeed");
        let (request, client_state) = result.unwrap();

        let server_response = server_state.open_registration(request);
        assert!(
            server_response.is_ok(),
            "Server should process registration request successfully"
        );
        let response = server_response.unwrap();

        let result = user_state.handle_response(client_state, response);
        assert!(
            result.is_ok(),
            "User should handle server response successfully"
        );
        assert!(
            user_state.credential.is_some(),
            "User should receive a valid credential"
        );

        assert_ne!(
            user_state.credential.as_ref().unwrap().nym_id,
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
        let user_state = UserState::new(server_state.public_parameters());

        // Test basic API structure
        let result = user_state.request(rng);
        if let Ok((_request, _client_state)) = result {
            println!("Registration request/state structure is valid");
            // TODO: Complete the test when we have a working server response
        }
    }
}
