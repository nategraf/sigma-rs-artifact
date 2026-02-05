use super::{scalar_u32, ServerState, UserState, G};
use crate::errors::CredentialError;
use crate::registration::UserAuthCredential;
use cmz::*;
use curve25519_dalek::RistrettoPoint;
use group::{Group, GroupEncoding};
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use tracing::{debug, instrument, trace};

const SESSION_ID: &[u8] = b"submit";

muCMZProtocol!(submit<min_age_today, max_age, min_measurement_count,
        max_measurement_count, @DOMAIN, @NYM>,
    Old: UserAuthCredential { nym_id: H, age: H, measurement_count: H},
    New: UserAuthCredential { nym_id: H, age: H, measurement_count: H},
    Old.nym_id = New.nym_id,
    Old.age = New.age,
    New.measurement_count = Old.measurement_count + 1,
    NYM = Old.nym_id * DOMAIN,
    (min_age_today..=max_age).contains(Old.age),
    (min_measurement_count..=max_measurement_count).contains(Old.measurement_count)
);

impl UserState {
    #[instrument(skip(self, rng))]
    pub fn submit_request(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        probe_cc: String,
        probe_asn: String,
        age_range: std::ops::Range<u32>,
        measurement_count_range: std::ops::Range<u32>,
    ) -> Result<((submit::Request, submit::ClientState), [u8; 32]), CredentialError> {
        trace!("Starting submit request");
        debug!(
            "Age range: {:?}, Measurement count range: {:?}",
            age_range, measurement_count_range
        );
        cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

        // Get the current credential
        let Old = self
            .credential
            .as_ref()
            .ok_or(CredentialError::InvalidField(
                String::from("credential"),
                String::from("No credential available"),
            ))?;

        // Domain-specific generator and NYM computation
        let domain_str = format!("ooni.org/{}/{}", probe_cc, probe_asn);
        trace!("Computing DOMAIN for: {}", domain_str);
        let DOMAIN = G::hash_from_bytes::<Sha512>(domain_str.as_bytes());
        let NYM = Old.nym_id.unwrap() * DOMAIN;
        debug!("NYM computed successfully");

        // Ensure the credential timestamp is within the allowed range
        let age: u32 = match scalar_u32(&Old.age.unwrap()) {
            Some(v) => v,
            None => {
                return Err(CredentialError::InvalidField(
                    String::from("age"),
                    String::from("could not be converted to u32"),
                ))
            }
        };

        // Check if credential timestamp is within the allowed range
        // age_range represents the valid timestamp range (min_timestamp..max_timestamp)

        // Check if credential is too old (timestamp too early)
        if age < age_range.start {
            return Err(CredentialError::CredentialExpired);
        }

        // Check if credential is too new (timestamp too recent)
        if age >= age_range.end {
            return Err(CredentialError::TimeThresholdNotMet(age - age_range.end));
        }

        // The measurement count has to be within the allowed range
        let measurement_count: u32 = match scalar_u32(&Old.measurement_count.unwrap()) {
            Some(v) => v,
            None => {
                return Err(CredentialError::InvalidField(
                    String::from("measurement_count"),
                    String::from("could not be converted to u32"),
                ))
            }
        };
        if measurement_count < measurement_count_range.start {
            return Err(CredentialError::InvalidField(
                String::from("measurement_count"),
                format!(
                    "measurement_count {} is below minimum {}",
                    measurement_count, measurement_count_range.start
                ),
            ));
        }
        if measurement_count >= measurement_count_range.end {
            return Err(CredentialError::InvalidField(
                String::from("measurement_count"),
                format!(
                    "measurement_count {} is at or above maximum {}",
                    measurement_count, measurement_count_range.end
                ),
            ));
        }

        //let NYM = PRF(nym_id, nym_scope.format(probe_cc, probe_asn))
        let mut New = UserAuthCredential::using_pubkey(&self.pp);
        New.nym_id = Old.nym_id;
        New.age = Old.age;
        New.measurement_count = Some((measurement_count + 1).into());
        let params = submit::Params {
            min_age_today: age_range.start.into(),
            max_age: age_range.end.into(),
            min_measurement_count: measurement_count_range.start.into(),
            max_measurement_count: measurement_count_range.end.into(),
            DOMAIN,
            NYM,
        };

        trace!("Preparing submit proof with params");
        match submit::prepare(rng, SESSION_ID, Old, New, &params) {
            Ok(req_state) => {
                debug!("Submit request prepared successfully");
                Ok((req_state, NYM.compress().to_bytes()))
            }
            Err(_) => {
                debug!("Failed to prepare submit request");
                Err(CredentialError::CMZError(CMZError::CliProofFailed))
            }
        }
    }

    pub fn handle_submit_response(
        &mut self,
        state: submit::ClientState,
        rep: submit::Reply,
    ) -> Result<(), CMZError> {
        let replybytes = rep.as_bytes();
        let recvreply = submit::Reply::try_from(&replybytes[..]).unwrap();
        match state.finalize(recvreply) {
            Ok(cred) => {
                self.credential = Some(cred);
                Ok(())
            }
            Err(_e) => Err(CMZError::IssProofFailed),
        }
    }
}

impl ServerState {
    #[instrument(skip(self, rng, req))]
    #[allow(clippy::too_many_arguments)]
    pub fn handle_submit(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        req: submit::Request,
        nym: &[u8; 32],
        probe_cc: &str,
        probe_asn: &str,
        age_range: std::ops::Range<u32>,
        measurement_count_range: std::ops::Range<u32>,
    ) -> Result<submit::Reply, CMZError> {
        trace!("Server handling submit request");
        debug!(
            "Age range: {:?}, Measurement count range: {:?}",
            age_range, measurement_count_range
        );
        let reqbytes = req.as_bytes();

        let recvreq = submit::Request::try_from(&reqbytes[..]).unwrap();
        let domain_str = format!("ooni.org/{}/{}", probe_cc, probe_asn);
        let DOMAIN = G::hash_from_bytes::<Sha512>(domain_str.as_bytes());

        // Parse the NYM bytes back to RistrettoPoint
        let nym_point = RistrettoPoint::from_bytes(nym)
            .into_option()
            .ok_or(CMZError::IssProofFailed)?;

        let params = submit::Params {
            min_age_today: age_range.start.into(),
            max_age: age_range.end.into(),
            min_measurement_count: measurement_count_range.start.into(),
            max_measurement_count: measurement_count_range.end.into(),
            DOMAIN,
            NYM: nym_point,
        };

        let server_sk = self.sk.clone();
        let server_pp = self.pp.clone();
        match submit::handle(
            rng,
            SESSION_ID,
            recvreq,
            move |Old: &mut UserAuthCredential, New: &mut UserAuthCredential| {
                // Set the private key for the credentials - this is essential for the protocol
                Old.set_keypair(server_sk.clone(), server_pp.clone());
                New.set_keypair(server_sk.clone(), server_pp.clone());

                // The protocol should populate Old and New from the client's proof
                // We don't set the values here - they come from the client's proof
                // We just return the parameters to validate against
                Ok(params)
            },
            |_Old: &UserAuthCredential, _New: &UserAuthCredential| {
                // Additional validation callback
                Ok(())
            },
        ) {
            Ok((response, (_old_cred, _new_cred))) => {
                debug!("Submit request verified successfully");
                Ok(response)
            }
            Err(e) => {
                debug!("Submit request verification failed: {:?}", e);
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Scalar, ServerState, UserState, G};
    use sha2::Sha512;

    #[test]
    fn test_domain_nym_computation() {
        // Test the DOMAIN and NYM computation logic that will be used
        // when group element equations are supported in the macro

        let probe_cc = "US";
        let probe_asn = "AS1234";
        let domain_str = format!("ooni.org/{}/{}", probe_cc, probe_asn);
        let domain = G::hash_from_bytes::<Sha512>(domain_str.as_bytes());

        // Test with a known nym_id
        let nym_id = Scalar::from(42u32);
        let nym = nym_id * domain;

        // Different domain should produce different NYM
        let different_domain_str = format!("ooni.org/{}/{}", "UK", "AS5678");
        let different_domain = G::hash_from_bytes::<Sha512>(different_domain_str.as_bytes());
        let different_nym = nym_id * different_domain;

        assert_ne!(
            nym, different_nym,
            "Different domains should produce different NYMs"
        );
    }

    #[test]
    fn test_submit_request() {
        let rng = &mut rand::thread_rng();

        // Setup server and user
        let server_state = ServerState::new(rng);
        let mut user_state = UserState::new(server_state.public_parameters());

        // First do registration to get a credential
        let result = user_state.request(rng);
        assert!(result.is_ok(), "Registration request should succeed");
        let (reg_request, reg_client_state) = result.unwrap();

        let server_response = server_state.open_registration(reg_request);
        assert!(
            server_response.is_ok(),
            "Server should process registration request successfully"
        );
        let reg_response = server_response.unwrap();

        let result = user_state.handle_response(reg_client_state, reg_response);
        assert!(
            result.is_ok(),
            "User should handle server response successfully"
        );
        assert!(
            user_state.credential.is_some(),
            "User should receive a valid credential"
        );

        // Test submit request with valid parameters
        let probe_cc = "US".to_string();
        let probe_asn = "AS1234".to_string();
        let today = ServerState::today();
        let age_range = (today - 30)..(today + 1); // Credential valid for 30 days
        let measurement_count_range = 0..100;

        let result = user_state.submit_request(
            rng,
            probe_cc.clone(),
            probe_asn.clone(),
            age_range.clone(),
            measurement_count_range.clone(),
        );

        assert!(
            result.is_ok(),
            "Submit request should succeed with valid credential"
        );
        let ((request, client_state), nym) = result.unwrap();

        // Verify the request is valid
        assert!(
            !request.as_bytes().is_empty(),
            "Request should have content"
        );

        // Verify NYM is computed (check it's not all zeros)
        assert_ne!(&nym, &[0u8; 32], "NYM should not be all zeros");

        // Test server handling of submit request
        let server_result = server_state.handle_submit(
            rng,
            request,
            &nym,
            &probe_cc,
            &probe_asn,
            age_range,
            measurement_count_range,
        );
        assert!(
            server_result.is_ok(),
            "Server should handle submit request successfully"
        );
        let response = server_result.unwrap();

        // Test user handling of server response
        let handle_result = user_state.handle_submit_response(client_state, response);
        assert!(
            handle_result.is_ok(),
            "User should handle submit response successfully"
        );

        // Verify credential was updated
        assert!(
            user_state.credential.is_some(),
            "User should still have credential"
        );
        let updated_cred = user_state.credential.as_ref().unwrap();

        // Verify measurement count was incremented
        let new_count = scalar_u32(&updated_cred.measurement_count.unwrap()).unwrap();
        assert_eq!(new_count, 1, "Measurement count should be incremented to 1");
    }
}
