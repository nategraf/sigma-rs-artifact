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

#[cfg(feature = "dump")]
use super::super::dumper::dump;
#[cfg(feature = "bridgeauth")]
use super::super::{
    bridge_table::{self, BridgeLine},
    dup_filter::SeenType,
    BridgeAuth, BridgeDb, OPENINV_LENGTH,
};
use super::super::{Scalar, G};
use super::errors::CredentialError;
use crate::lox_creds::Lox;
use cmz::*;
use rand::{CryptoRng, RngCore};
use sha2::Sha512;
use web_time::Instant;

const SESSION_ID: &[u8] = b"open_invite";
muCMZProtocol! { open_invitation,
    ,
    L: Lox {id: J, bucket: S, trust_level: I, level_since: S, invites_remaining: I, blockages: I },
}

/// Prepare the open invitation request to send to the Lox Authority
/// Note that preparing the request does not require an open invitation, but an invitation
/// must be sent along with the prepared open_inivtation::Request to the Lox authority
pub fn request(
    rng: &mut (impl CryptoRng + RngCore),
    pubkeys: CMZPubkey<G>,
) -> Result<(open_invitation::Request, open_invitation::ClientState), CredentialError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    cmz_group_init(G::hash_from_bytes::<Sha512>(b"CMZ Generator A"));

    let mut L = Lox::using_pubkey(&pubkeys);
    L.trust_level = Some(Scalar::ZERO);
    L.invites_remaining = Some(Scalar::ZERO);
    L.blockages = Some(Scalar::ZERO);
    match open_invitation::prepare(rng, SESSION_ID, L) {
        Ok(req_state) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!("open-invite client request time {:#?}", duration));
            };
            Ok(req_state)
        }
        Err(e) => Err(CredentialError::CMZError(e)),
    }
}

#[cfg(feature = "bridgeauth")]
impl BridgeAuth {
    pub fn open_invitation(
        &mut self,
        req: open_invitation::Request,
        invite: &[u8; OPENINV_LENGTH],
    ) -> Result<(open_invitation::Reply, BridgeLine), CredentialError> {
        let now = Instant::now();
        // Check the signature on the open_invite, first with the old key, then with the new key.
        // We manually match here because we're changing the Err type from SignatureError
        // to ProofError
        let mut rng = rand::thread_rng();
        let mut old_token: Option<((Scalar, u32), usize)> = Default::default();
        let invite_id: Scalar;
        let bucket_id: u32;
        // If there are old openinv keys, check them first
        for (i, old_openinv_key) in self.old_keys.bridgedb_key.iter().enumerate() {
            old_token = match BridgeDb::verify(*invite, *old_openinv_key) {
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
                return Err(CredentialError::CredentialExpired);
            }
        // If it didn't, try verifying with the new key
        } else {
            (invite_id, bucket_id) = match BridgeDb::verify(*invite, self.bridgedb_pub) {
                Ok(res) => res,
                // Also verify that the request doesn't match with an old openinv_key
                Err(_) => {
                    return Err(CredentialError::InvalidField(
                        "invitation".to_string(),
                        "pubkey".to_string(),
                    ))
                }
            };
            // Only proceed if the invite_id is fresh
            if self.bridgedb_pub_filter.filter(&invite_id) == SeenType::Seen {
                return Err(CredentialError::CredentialExpired);
            }
        }

        // And also check that the bucket id is valid
        if !self.bridge_table.buckets.contains_key(&bucket_id) {
            return Err(CredentialError::InvalidField(
                "invitation".to_string(),
                "bucket".to_string(),
            ));
        }

        let reqbytes = req.as_bytes();
        // Create the bucket attribute (Scalar), which is a combination
        // of the bucket id (u32) and the bucket's decryption key ([u8; 16])
        let bucket_key = self.bridge_table.keys.get(&bucket_id).unwrap();
        let bucket: Scalar = bridge_table::to_scalar(bucket_id, bucket_key);
        let bridge_lines = self.bridge_table.buckets.get(&bucket_id).unwrap();
        let bridge_line = bridge_lines[0];

        let recvreq = open_invitation::Request::try_from(&reqbytes[..]).unwrap();
        match open_invitation::handle(
            &mut rng,
            SESSION_ID,
            recvreq,
            |L: &mut Lox| {
                L.set_privkey(&self.lox_priv);
                L.bucket = Some(bucket);
                L.trust_level = Some(Scalar::ZERO);
                L.level_since = Some(self.today().into());
                L.invites_remaining = Some(Scalar::ZERO);
                L.blockages = Some(Scalar::ZERO);
                Ok(())
            },
            |_L: &Lox| Ok(()),
        ) {
            Ok((response, _L_issuer)) => {
                println!(
                    "open-invite reply size: {:?}",
                    bincode::serialize(&(response.clone(), bridge_line))
                        .unwrap()
                        .len()
                );
                let duration = now.elapsed();
                println!("open-invite reply time: {:?}", duration);
                Ok((response, bridge_line))
            }
            Err(e) => Err(CredentialError::CMZError(e)),
        }
    }
}

pub fn handle_response(
    state: open_invitation::ClientState,
    rep: open_invitation::Reply,
) -> Result<Lox, CMZError> {
    #[cfg(feature = "dump")]
    let now = Instant::now();
    let replybytes = rep.as_bytes();
    let recvreply = open_invitation::Reply::try_from(&replybytes[..]).unwrap();
    match state.finalize(recvreply) {
        Ok(cred) => {
            #[cfg(feature = "dump")]
            let duration = now.elapsed();
            #[cfg(feature = "dump")]
            let _dumper = if cfg!(feature = "dump") {
                dump(&format!(
                    "open-invite client handle reply time {:#?}",
                    duration
                ));
            };
            Ok(cred)
        }
        Err(_e) => Err(CMZError::Unknown),
    }
}

#[cfg(all(test, feature = "bridgeauth"))]
mod tests {
    use crate::mock_auth::TestHarness;

    #[test]
    fn test_open_invitation() {
        println!("\n----OPEN-INVITATION----\n");
        let mut th = TestHarness::new();
        let rng = &mut rand::thread_rng();
        let invite = th.bdb.invite().unwrap();
        let cred = th.open_invite(rng, &invite);
        th.verify_lox(&cred.1);
        th.print_test_results(cred.0)
    }
}
