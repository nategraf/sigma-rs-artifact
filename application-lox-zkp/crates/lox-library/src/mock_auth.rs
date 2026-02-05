#[cfg(all(test, feature = "bridgeauth"))]
use serde::{Deserialize, Serialize};

#[cfg(all(test, feature = "bridgeauth"))]
use super::proto::{
    blockage_migration, check_blockage, issue_invite,
    level_up::{self, LEVEL_INTERVAL},
    migration, open_invite, redeem_invite,
    trust_promotion::{self, UNTRUSTED_INTERVAL},
    update_cred, update_invite,
};
#[cfg(all(test, feature = "bridgeauth"))]
use super::*;

#[cfg(all(test, feature = "bridgeauth"))]
use super::cred::{BucketReachability, Invitation, Lox, Migration};

#[cfg(all(test, feature = "bridgeauth"))]
use crate::bridge_table::BridgeLine;

#[cfg(all(test, feature = "bridgeauth"))]
use rand::RngCore;

#[cfg(all(test, feature = "bridgeauth"))]
#[allow(unused_imports)]
use base64::{engine::general_purpose, Engine as _};

#[cfg(all(test, feature = "bridgeauth"))]
use std::time::{Duration, Instant};
#[cfg(all(test, feature = "bridgeauth"))]
pub struct TestHarness {
    pub bdb: BridgeDb,
    pub ba: BridgeAuth,
}

#[cfg(all(test, feature = "bridgeauth"))]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct OpenInvite([u8; OPENINV_LENGTH]);

#[cfg(all(test, feature = "bridgeauth"))]
impl From<OpenInvite> for Vec<u8> {
    fn from(e: OpenInvite) -> Vec<u8> {
        e.0.into()
    }
}

#[cfg(all(test, feature = "bridgeauth"))]
#[derive(thiserror::Error, Debug)]
#[error("wrong slice length")]
pub struct WrongSliceLengthError;

#[cfg(all(test, feature = "bridgeauth"))]
impl TryFrom<Vec<u8>> for OpenInvite {
    type Error = WrongSliceLengthError;
    fn try_from(v: Vec<u8>) -> Result<OpenInvite, Self::Error> {
        Ok(OpenInvite(
            *Box::<[u8; OPENINV_LENGTH]>::try_from(v).map_err(|_| WrongSliceLengthError)?,
        ))
    }
}

#[derive(Clone)]
#[cfg(all(test, feature = "bridgeauth"))]
pub struct PerfStat {
    // Report performance metrics for each test
    req_len: usize,
    resp_len: usize,
    req_t: Duration,
    resp_t: Duration,
    resp_handle_t: Duration,
}

#[cfg(all(test, feature = "bridgeauth"))]
impl TestHarness {
    pub fn new() -> Self {
        TestHarness::new_buckets(5, 5)
    }

    pub fn new_buckets(num_buckets: u16, hot_spare: u16) -> Self {
        // Create a BridegDb
        let mut bdb = BridgeDb::new();
        // Create a BridgeAuth
        let mut ba = BridgeAuth::new(bdb.pubkey.clone());

        // Make 3 x num_buckets open invitation bridges, in sets of 3
        for _ in 0..num_buckets {
            let bucket = [random(), random(), random()];
            let _ = ba.add_openinv_bridges(bucket, &mut bdb);
        }
        // Add hot_spare more hot spare buckets
        for _ in 0..hot_spare {
            let bucket = [random(), random(), random()];
            let _ = ba.add_spare_bucket(bucket, &mut bdb);
        }
        // Create the encrypted bridge table
        ba.enc_bridge_table();

        Self { bdb, ba }
    }

    pub fn advance_days(&mut self, days: u32) {
        if days > 0 {
            self.ba.time_offset += time::Duration::days(days.into());
        }
    }

    /// Verify the two MACs on a Lox credential
    pub fn verify_lox(&self, cred: &Lox) {
        assert!(self.ba.verify_lox(&cred), "Lox cred's MAC should verify");
    }

    /// Verify the MAC on a Migration credential
    pub fn verify_migration(&self, cred: &Migration) {
        assert!(
            self.ba.verify_migration(&cred),
            "Migration cred's MAC should verify"
        );
    }

    /// Verify the MAC on a Bucket Reachability credential
    pub fn verify_reachability(&self, cred: &BucketReachability) {
        assert!(
            self.ba.verify_reachability(&cred),
            "Reachability cred's MAC should verify"
        );
    }

    /// Verify the MAC on a Invitation credential
    pub fn verify_invitation(&mut self, cred: &Invitation) {
        assert!(
            self.ba.verify_invitation(&cred),
            "Invitation cred's MAC should verify"
        );
    }

    pub fn open_invite(&mut self, invite: &[u8; OPENINV_LENGTH]) -> (PerfStat, (Lox, BridgeLine)) {
        let req_start = Instant::now();
        let (request, client_state) = open_invite::request(invite, &self.ba.lox_pub.clone());
        let req_t = req_start.elapsed();
        let encoded: Vec<u8> = bincode::serialize(&request.clone()).unwrap();
        let req_len = encoded.len();
        let resp_start = Instant::now();
        let open_invitation_response = self.ba.handle_open_invite(request);
        let resp_t = resp_start.elapsed();
        assert!(
            open_invitation_response.is_ok(),
            "Open invitation response from server should succeed"
        );
        let reply = open_invitation_response.unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&reply).unwrap();
        let resp_len = encoded_resp.len();
        let resp_handle_start = Instant::now();
        let lox_cred = open_invite::handle_response(client_state, reply, &self.ba.lox_pub.clone());
        let resp_handle_t = resp_handle_start.elapsed();
        assert!(lox_cred.is_ok(), "Handle response should succeed");
        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            lox_cred.unwrap(),
        )
    }

    pub fn trust_promotion(&mut self, cred: Lox) -> (PerfStat, Migration) {
        self.advance_days((UNTRUSTED_INTERVAL + 1).try_into().unwrap());
        let req_start = Instant::now();
        let trust_promo_request = trust_promotion::request(
            &cred,
            &self.ba.lox_pub.clone(),
            &self.ba.migrationkey_pub.clone(),
            self.ba.today(),
        );
        let req_t = req_start.elapsed();
        assert!(
            trust_promo_request.is_ok(),
            "Trust Promotion request should succeed"
        );
        let (tp_request, tp_client_state) = trust_promo_request.unwrap();
        let encoded: Vec<u8> = bincode::serialize(&tp_request.clone()).unwrap();
        let req_len = encoded.len();
        let resp_start: Instant = Instant::now();
        let trust_promo_response = self.ba.handle_trust_promotion(tp_request);
        let resp_t: Duration = resp_start.elapsed();
        assert!(
            trust_promo_response.is_ok(),
            "Trust promotion response from server should succeed"
        );
        let response = trust_promo_response.unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&response.clone()).unwrap();
        let resp_len: usize = encoded_resp.len();
        let resp_handle_start: Instant = Instant::now();
        let mig_cred = trust_promotion::handle_response(tp_client_state, response);
        let resp_handle_t = resp_handle_start.elapsed();
        assert!(mig_cred.is_ok(), "Handle response should succeed");
        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            mig_cred.unwrap(),
        )
    }

    pub fn migration(&mut self, cred: Lox, mig_cred: Migration) -> (PerfStat, Lox) {
        let req_start = Instant::now();
        let migration_request = migration::request(
            &cred,
            &mig_cred,
            &self.ba.lox_pub.clone(),
            &self.ba.migration_pub.clone(),
        );
        let req_t = req_start.elapsed();
        assert!(
            migration_request.is_ok(),
            "Migration request should succeed"
        );
        let (mig_request, mig_client_state) = migration_request.unwrap();
        let encoded: Vec<u8> = bincode::serialize(&mig_request.clone()).unwrap();
        let req_len = encoded.len();
        let resp_start: Instant = Instant::now();
        let migration_response = self.ba.handle_migration(mig_request);
        let resp_t: Duration = resp_start.elapsed();
        assert!(
            migration_response.is_ok(),
            "Migration response from server should succeed"
        );
        let response = migration_response.unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&response).unwrap();
        let resp_len: usize = encoded_resp.len();
        let resp_handle_start: Instant = Instant::now();
        let new_cred =
            migration::handle_response(mig_client_state, response, &self.ba.lox_pub.clone());
        let resp_handle_t = resp_handle_start.elapsed();
        assert!(new_cred.is_ok(), "Handle response should succeed");
        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            new_cred.unwrap(),
        )
    }

    fn reach_cred(&mut self, cred: Lox) -> BucketReachability {
        let (id, key) = bridge_table::from_scalar(cred.bucket).unwrap();
        let encbuckets = self.ba.enc_bridge_table().clone();
        let bucket =
            bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap())
                .unwrap();
        bucket.1.unwrap()
    }

    pub fn level_up(&mut self, cred: Lox) -> (PerfStat, Lox) {
        let trust_level: u32 = scalar_u32(&cred.trust_level).unwrap();
        self.advance_days(LEVEL_INTERVAL[trust_level as usize] + 1);
        let reachcred = self.reach_cred(cred.clone());
        let req_start = Instant::now();
        let level_up_request = level_up::request(
            &cred.clone(),
            &reachcred,
            &self.ba.lox_pub.clone(),
            &self.ba.reachability_pub.clone(),
            self.ba.today(),
        );
        let req_t = req_start.elapsed();
        assert!(level_up_request.is_ok(), "Level up request should succeed");
        let (level_up_request, level_up_client_state) = level_up_request.unwrap();
        let encoded: Vec<u8> = bincode::serialize(&level_up_request.clone()).unwrap();
        let req_len = encoded.len();
        let resp_start: Instant = Instant::now();
        let level_up_response = self.ba.handle_level_up(level_up_request);
        let resp_t: Duration = resp_start.elapsed();
        assert!(
            level_up_response.is_ok(),
            "Level up response from server should succeed"
        );
        let response = level_up_response.unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&response).unwrap();
        let resp_len: usize = encoded_resp.len();
        let resp_handle_start: Instant = Instant::now();
        let new_cred =
            level_up::handle_response(level_up_client_state, response, &self.ba.lox_pub.clone());
        let resp_handle_t = resp_handle_start.elapsed();
        assert!(new_cred.is_ok(), "Handle response should succeed");
        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            new_cred.unwrap(),
        )
    }

    pub fn issue_invite(&mut self, cred: Lox) -> (PerfStat, (Lox, Invitation)) {
        let reachcred = self.reach_cred(cred.clone());
        let req_start = Instant::now();
        let issue_invite_request = issue_invite::request(
            &cred.clone(),
            &reachcred,
            &self.ba.lox_pub.clone(),
            &self.ba.reachability_pub.clone(),
            &self.ba.invitation_pub.clone(),
            self.ba.today(),
        );
        let req_t = req_start.elapsed();
        let (issue_invite_request, issue_invite_client_state) = issue_invite_request.unwrap();
        let encoded: Vec<u8> = bincode::serialize(&issue_invite_request.clone()).unwrap();
        let req_len = encoded.len();
        let resp_start: Instant = Instant::now();
        let issue_invite_response = self.ba.handle_issue_invite(issue_invite_request);
        let resp_t: Duration = resp_start.elapsed();
        assert!(
            issue_invite_response.is_ok(),
            "Issue Invite response from server should succeed"
        );
        let response = issue_invite_response.unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&response).unwrap();
        let resp_len: usize = encoded_resp.len();
        let resp_handle_start: Instant = Instant::now();
        let i_cred = issue_invite::handle_response(
            issue_invite_client_state,
            response,
            &self.ba.lox_pub.clone(),
            &self.ba.invitation_pub.clone(),
        );
        let resp_handle_t = resp_handle_start.elapsed();
        assert!(i_cred.is_ok(), "Handle response should succeed");
        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            i_cred.unwrap(),
        )
    }

    pub fn redeem_invite(&mut self, cred: Invitation) -> (PerfStat, Lox) {
        let req_start = Instant::now();
        let redeem_invite_request = redeem_invite::request(
            &cred,
            &self.ba.lox_pub.clone(),
            &self.ba.invitation_pub,
            self.ba.today(),
        );
        let req_t = req_start.elapsed();
        let (redeem_invite_request, redeem_invite_client_state) = redeem_invite_request.unwrap();
        let encoded: Vec<u8> = bincode::serialize(&redeem_invite_request.clone()).unwrap();
        let req_len = encoded.len();
        let resp_start: Instant = Instant::now();
        let redeem_invite_response = self.ba.handle_redeem_invite(redeem_invite_request);
        let resp_t: Duration = resp_start.elapsed();
        assert!(
            redeem_invite_response.is_ok(),
            "Redeem Invite response from server should succeed"
        );
        let response = redeem_invite_response.unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&response.clone()).unwrap();
        let resp_len: usize = encoded_resp.len();
        let resp_handle_start: Instant = Instant::now();
        let i_cred = redeem_invite::handle_response(
            redeem_invite_client_state,
            response,
            &self.ba.lox_pub.clone(),
        );
        let resp_handle_t = resp_handle_start.elapsed();
        assert!(i_cred.is_ok(), "Handle response should succeed");
        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            i_cred.unwrap(),
        )
    }

    pub fn block_bridges(&mut self, cred: Lox) {
        // Get our bridges
        let (id, key) = bridge_table::from_scalar(cred.bucket).unwrap();
        let encbuckets = self.ba.enc_bridge_table().clone();
        let bucket =
            bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap())
                .unwrap();
        // We should have a Bridge Reachability credential
        assert!(bucket.1.is_some());
        // Oh, no!  Two of our bridges are blocked!
        self.ba.bridge_blocked(&bucket.0[0], &mut self.bdb);
        self.ba.bridge_blocked(&bucket.0[2], &mut self.bdb);
        self.advance_days(1);
    }

    pub fn check_blockage(&mut self, cred: Lox) -> (PerfStat, Migration) {
        let req_start = Instant::now();
        let check_blockage_request = check_blockage::request(
            &cred,
            &self.ba.lox_pub.clone(),
            &self.ba.migrationkey_pub.clone(),
        );
        let req_t = req_start.elapsed();
        assert!(
            check_blockage_request.is_ok(),
            "Check blockage request should succeed"
        );
        let (check_blockage_request, check_blockage_client_state) = check_blockage_request.unwrap();
        let encoded: Vec<u8> = bincode::serialize(&check_blockage_request.clone()).unwrap();
        let req_len = encoded.len();
        let resp_start: Instant = Instant::now();
        let check_blockage_response = self.ba.handle_check_blockage(check_blockage_request);
        let resp_t: Duration = resp_start.elapsed();
        assert!(
            check_blockage_response.is_ok(),
            "Check blockage response from server should succeed"
        );
        let response = check_blockage_response.unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&response.clone()).unwrap();
        let resp_len: usize = encoded_resp.len();
        let resp_handle_start: Instant = Instant::now();
        let mig_cred = check_blockage::handle_response(check_blockage_client_state, response);
        let resp_handle_t = resp_handle_start.elapsed();
        assert!(mig_cred.is_ok(), "Handle response should succeed");
        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            mig_cred.unwrap(),
        )
    }

    pub fn blockage_migration(&mut self, cred: Lox, mig_cred: Migration) -> (PerfStat, Lox) {
        let req_start = Instant::now();
        let migration_request = blockage_migration::request(
            &cred,
            &mig_cred,
            &self.ba.lox_pub.clone(),
            &self.ba.migration_pub.clone(),
        );
        let req_t = req_start.elapsed();
        assert!(
            migration_request.is_ok(),
            "Migration request should succeed"
        );
        let (mig_request, mig_client_state) = migration_request.unwrap();
        let encoded: Vec<u8> = bincode::serialize(&mig_request.clone()).unwrap();
        let req_len = encoded.len();
        let resp_start: Instant = Instant::now();
        let migration_response = self.ba.handle_blockage_migration(mig_request);
        let resp_t: Duration = resp_start.elapsed();
        assert!(
            migration_response.is_ok(),
            "Migration response from server should succeed"
        );
        let response = migration_response.unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&response.clone()).unwrap();
        let resp_len: usize = encoded_resp.len();
        let resp_handle_start: Instant = Instant::now();
        let new_cred = blockage_migration::handle_response(
            mig_client_state,
            response,
            &self.ba.lox_pub.clone(),
        );
        let resp_handle_t = resp_handle_start.elapsed();
        assert!(new_cred.is_ok(), "Handle response should succeed");
        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            new_cred.unwrap(),
        )
    }

    pub fn update_cred(&mut self, cred: Lox, old_key: IssuerPubKey) -> (PerfStat, Lox) {
        self.ba.rotate_lox_keys();
        let req_start = Instant::now();
        let key = old_key.clone();
        let update_cred_request =
            update_cred::request(&cred, &key.clone(), &self.ba.lox_pub.clone());
        let req_t = req_start.elapsed();
        assert!(
            update_cred_request.is_ok(),
            "Update cred request should succeed"
        );
        let (update_request, update_state) = update_cred_request.unwrap();
        let encoded: Vec<u8> = bincode::serialize(&update_request.clone()).unwrap();
        let req_len = encoded.len();
        let resp_start: Instant = Instant::now();
        let update_response = self.ba.handle_update_cred(update_request);
        let resp_t: Duration = resp_start.elapsed();
        assert!(
            update_response.is_ok(),
            "Update cred response from server should succeed"
        );
        let response = update_response.unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&response.clone()).unwrap();
        let resp_len: usize = encoded_resp.len();
        let resp_handle_start: Instant = Instant::now();
        let new_cred =
            update_cred::handle_response(update_state, response, &self.ba.lox_pub.clone());
        let resp_handle_t = resp_handle_start.elapsed();
        assert!(new_cred.is_ok(), "Handle response should succeed");
        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            new_cred.unwrap(),
        )
    }

    pub fn update_invite(
        &mut self,
        cred: Invitation,
        old_key: IssuerPubKey,
    ) -> (PerfStat, Invitation) {
        self.ba.rotate_invitation_keys();
        let req_start = Instant::now();
        let update_invite_request =
            update_invite::request(&cred, &old_key.clone(), &self.ba.invitation_pub.clone());
        let req_t = req_start.elapsed();
        assert!(
            update_invite_request.is_ok(),
            "Update invite request should succeed"
        );
        let (update_request, update_state) = update_invite_request.unwrap();
        let encoded: Vec<u8> = bincode::serialize(&update_request.clone()).unwrap();
        let req_len = encoded.len();
        let resp_start: Instant = Instant::now();
        let update_response = self.ba.handle_update_invite(update_request);
        let resp_t: Duration = resp_start.elapsed();
        assert!(
            update_response.is_ok(),
            "Update invite response from server should succeed"
        );
        let response = update_response.unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&response.clone()).unwrap();
        let resp_len: usize = encoded_resp.len();
        let resp_handle_start: Instant = Instant::now();
        let new_cred =
            update_invite::handle_response(update_state, response, &self.ba.invitation_pub.clone());
        let resp_handle_t = resp_handle_start.elapsed();
        assert!(new_cred.is_ok(), "Handle response should succeed");
        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            new_cred.unwrap(),
        )
    }

    pub fn print_test_results(&self, perf_stat: PerfStat) {
        println!("Request size = {:?} bytes", perf_stat.req_len);
        println!("Request time = {:?}", perf_stat.req_t);
        println!("Response size = {:?} bytes", perf_stat.resp_len);
        println!("Response time = {:?}", perf_stat.resp_t);
        println!("Response handle time = {:?}", perf_stat.resp_handle_t);
    }
}

/// Create a random BridgeLine for testing
#[cfg(all(test, feature = "bridgeauth"))]
pub fn random() -> BridgeLine {
    let mut rng = rand::rngs::OsRng;
    let mut res: BridgeLine = Default::default();
    // Pick a random 4-byte address
    let mut addr: [u8; 4] = [0; 4];
    rng.fill_bytes(&mut addr);
    // If the leading byte is 224 or more, that's not a valid IPv4
    // address.  Choose an IPv6 address instead (but don't worry too
    // much about it being well formed).
    if addr[0] >= 224 {
        rng.fill_bytes(&mut res.addr);
    } else {
        // Store an IPv4 address as a v4-mapped IPv6 address
        res.addr[10] = 255;
        res.addr[11] = 255;
        res.addr[12..16].copy_from_slice(&addr);
    };
    let ports: [u16; 4] = [443, 4433, 8080, 43079];
    let portidx = (rng.next_u32() % 4) as usize;
    res.port = ports[portidx];
    res.uid_fingerprint = rng.next_u64();
    let mut cert: [u8; 52] = [0; 52];
    rng.fill_bytes(&mut cert);
    let infostr: String = format!(
        "obfs4 cert={}, iat-mode=0",
        general_purpose::STANDARD_NO_PAD.encode(cert)
    );
    res.info[..infostr.len()].copy_from_slice(infostr.as_bytes());
    res
}
