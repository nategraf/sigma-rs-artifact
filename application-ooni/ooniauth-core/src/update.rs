use super::{PublicParameters, SecretKey, ServerState, UserState, G};
use crate::errors::CredentialError;
use crate::registration::UserAuthCredential;
use cmz::*;
use group::Group;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;

const SESSION_ID: &[u8] = b"update";

muCMZProtocol!(update,
    Old: UserAuthCredential { nym_id: H, age: H, measurement_count: H},
    New: UserAuthCredential { nym_id: H, age: H, measurement_count: H},
    Old.nym_id = New.nym_id,
    Old.age = New.age,
    Old.measurement_count = New.measurement_count
);

impl UserState {
    pub fn update_request(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(update::Request, update::ClientState), CredentialError> {
        cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

        let old = self
            .credential
            .as_ref()
            .ok_or(CredentialError::InvalidField(
                String::from("credential"),
                String::from("No credential available"),
            ))?;

        let mut new = UserAuthCredential::using_pubkey(&self.pp);
        new.nym_id = old.nym_id;
        new.age = old.age;
        new.measurement_count = old.measurement_count;

        update::prepare(rng, SESSION_ID, old, new)
            .map_err(|_| CredentialError::CMZError(CMZError::CliProofFailed))
    }

    pub fn handle_update_response(
        &mut self,
        state: update::ClientState,
        rep: update::Reply,
    ) -> Result<(), CMZError> {
        let replybytes = rep.as_bytes();
        let recvreply = update::Reply::try_from(&replybytes[..]).unwrap();
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
    pub fn handle_update(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        req: update::Request,
        old_sk: &SecretKey,
        old_pp: &PublicParameters,
    ) -> Result<update::Reply, CMZError> {
        let reqbytes = req.as_bytes();
        let recvreq = update::Request::try_from(&reqbytes[..]).unwrap();
        let server_sk = self.sk.clone();
        let server_pp = self.pp.clone();
        let old_sk = old_sk.clone();
        let old_pp = old_pp.clone();

        match update::handle(
            rng,
            SESSION_ID,
            recvreq,
            move |Old: &mut UserAuthCredential, New: &mut UserAuthCredential| {
                Old.set_keypair(old_sk.clone(), old_pp.clone());
                New.set_keypair(server_sk.clone(), server_pp.clone());
                Ok(())
            },
            |_Old: &UserAuthCredential, _New: &UserAuthCredential| Ok(()),
        ) {
            Ok((response, (_old_cred, _new_cred))) => Ok(response),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServerState;

    #[test]
    fn test_update() {
        let rng = &mut rand::thread_rng();

        // Issue an initial credential under the old key material.
        let old_server_state = ServerState::new(rng);
        let mut user_state = UserState::new(old_server_state.public_parameters());

        let (reg_request, reg_client_state) = user_state.request(rng).unwrap();
        let reg_reply = old_server_state.open_registration(reg_request).unwrap();
        user_state
            .handle_response(reg_client_state, reg_reply)
            .unwrap();

        let old_credential = user_state.credential.clone().unwrap();
        old_credential
            .verify_MAC(old_server_state.secret_key_ref())
            .unwrap();

        // Rotate server keys and request an update using the old credential.
        let new_server_state = ServerState::new(rng);
        user_state.pp = new_server_state.public_parameters();

        let (update_request, update_client_state) = user_state.update_request(rng).unwrap();
        let update_reply = new_server_state
            .handle_update(
                rng,
                update_request,
                old_server_state.secret_key_ref(),
                old_server_state.public_parameters_ref(),
            )
            .unwrap();
        user_state
            .handle_update_response(update_client_state, update_reply)
            .unwrap();

        let updated_credential = user_state.credential.as_ref().unwrap();

        // Attributes are preserved.
        assert_eq!(updated_credential.nym_id, old_credential.nym_id);
        assert_eq!(updated_credential.age, old_credential.age);
        assert_eq!(
            updated_credential.measurement_count,
            old_credential.measurement_count
        );

        // New credential validates under the new key material.
        updated_credential
            .verify_MAC(new_server_state.secret_key_ref())
            .unwrap();
    }
}
