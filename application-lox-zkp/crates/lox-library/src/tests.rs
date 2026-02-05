/*! Unit tests that require access to the testing-only function
BridgeLine::random() or private fields */

use super::bridge_table::{BridgeLine, BRIDGE_BYTES};
use super::proto::*;
use super::*;

use rand::Rng;

use std::time::{Duration, Instant};

struct PerfStat {
    // Report performance metrics for each test
    req_len: usize,
    resp_len: usize,
    req_t: Duration,
    resp_t: Duration,
    resp_handle_t: Duration,
}

struct TestHarness {
    bdb: BridgeDb,
    pub ba: BridgeAuth,
}

impl TestHarness {
    fn new() -> Self {
        TestHarness::new_buckets(5, 5)
    }

    fn new_buckets(num_buckets: u16, hot_spare: u16) -> Self {
        // Create a BridegDb
        let mut bdb = BridgeDb::new();
        // Create a BridgeAuth
        let mut ba = BridgeAuth::new(bdb.pubkey);

        // Make 3 x num_buckets open invitation bridges, in sets of 3
        for _ in 0..num_buckets {
            let bucket = [
                BridgeLine::random(),
                BridgeLine::random(),
                BridgeLine::random(),
            ];
            let _ = ba.add_openinv_bridges(bucket, &mut bdb);
        }
        // Add hot_spare more hot spare buckets
        for _ in 0..hot_spare {
            let bucket = [
                BridgeLine::random(),
                BridgeLine::random(),
                BridgeLine::random(),
            ];
            let _ = ba.add_spare_bucket(bucket, &mut bdb);
        }
        // Create the encrypted bridge table
        ba.enc_bridge_table();

        Self { bdb, ba }
    }

    fn advance_days(&mut self, days: u16) {
        self.ba.advance_days(days);
    }

    fn open_invite(&mut self) -> (PerfStat, (cred::Lox, bridge_table::BridgeLine)) {
        // Issue an open invitation
        let inv = self.bdb.invite().unwrap();

        let req_start = Instant::now();
        // Use it to get a Lox credential
        let (req, state) = open_invite::request(&inv, &self.ba.lox_pub);
        let encoded: Vec<u8> = bincode::serialize(&req).unwrap();
        let req_t = req_start.elapsed();
        let req_len = encoded.len();

        let resp_start = Instant::now();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        let resp = self.ba.handle_open_invite(decoded).unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&resp).unwrap();
        let resp_t = resp_start.elapsed();
        let resp_len = encoded_resp.len();

        let resp_handle_start = Instant::now();
        let decode_resp = bincode::deserialize(&encoded_resp[..]).unwrap();
        let (cred, bridgeline) =
            open_invite::handle_response(state, decode_resp, &self.ba.lox_pub).unwrap();
        let resp_handle_t = resp_handle_start.elapsed();

        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            (cred, bridgeline),
        )
    }

    fn update_cred(&mut self, cred: &cred::Lox) -> (PerfStat, cred::Lox) {
        let req_start = Instant::now();
        let (req, state) = update_cred::request(
            cred,
            &self.ba.old_keys.lox_keys.clone().last().unwrap().pub_key,
            &self.ba.lox_pub,
        )
        .unwrap();
        let encoded: Vec<u8> = bincode::serialize(&req).unwrap();
        let req_t = req_start.elapsed();
        let req_len = encoded.len();

        let resp_start = Instant::now();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        let resp = self.ba.handle_update_cred(decoded).unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&resp).unwrap();
        let resp_t = resp_start.elapsed();
        let resp_len = encoded_resp.len();

        let resp_handle_start = Instant::now();
        let decode_resp = bincode::deserialize(&encoded_resp[..]).unwrap();
        let cred = update_cred::handle_response(state, decode_resp, &self.ba.lox_pub).unwrap();
        let resp_handle_t = resp_handle_start.elapsed();

        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            cred,
        )
    }

    fn update_invitation(&mut self, cred: &cred::Invitation) -> (PerfStat, cred::Invitation) {
        let req_start = Instant::now();
        let (req, state) = update_invite::request(
            cred,
            &self
                .ba
                .old_keys
                .invitation_keys
                .clone()
                .last()
                .unwrap()
                .pub_key,
            &self.ba.invitation_pub,
        )
        .unwrap();
        let encoded: Vec<u8> = bincode::serialize(&req).unwrap();
        let req_t = req_start.elapsed();
        let req_len = encoded.len();

        let resp_start = Instant::now();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        let resp = self.ba.handle_update_invite(decoded).unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&resp).unwrap();
        let resp_t = resp_start.elapsed();
        let resp_len = encoded_resp.len();
        let resp_handle_start = Instant::now();
        let decode_resp = bincode::deserialize(&encoded_resp[..]).unwrap();
        let cred =
            update_invite::handle_response(state, decode_resp, &self.ba.invitation_pub).unwrap();
        let resp_handle_t = resp_handle_start.elapsed();

        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            cred,
        )
    }

    fn trust_promotion(&mut self, cred: &cred::Lox) -> (PerfStat, cred::Migration) {
        let req_start = Instant::now();
        let (promreq, promstate) = trust_promotion::request(
            cred,
            &self.ba.lox_pub,
            &&self.ba.migrationkey_pub,
            self.ba.today(),
        )
        .unwrap();
        let encoded: Vec<u8> = bincode::serialize(&promreq).unwrap();
        let req_t = req_start.elapsed();
        let req_len = encoded.len();

        let resp_start = Instant::now();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        let promresp = self.ba.handle_trust_promotion(decoded).unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&promresp).unwrap();
        let resp_t = resp_start.elapsed();
        let resp_len = encoded_resp.len();

        let resp_handle_start = Instant::now();
        let decode_resp = bincode::deserialize(&encoded_resp[..]).unwrap();
        let migcred = trust_promotion::handle_response(promstate, decode_resp).unwrap();
        let resp_handle_t = resp_handle_start.elapsed();

        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            migcred,
        )
    }

    fn level0_migration(
        &mut self,
        loxcred: &cred::Lox,
        migcred: &cred::Migration,
    ) -> (PerfStat, cred::Lox) {
        let req_start = Instant::now();
        let (migreq, migstate) =
            migration::request(loxcred, migcred, &self.ba.lox_pub, &self.ba.migration_pub).unwrap();
        let encoded: Vec<u8> = bincode::serialize(&migreq).unwrap();
        let req_t = req_start.elapsed();
        let req_len = encoded.len();

        let resp_start = Instant::now();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        let migresp = self.ba.handle_migration(decoded).unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&migresp).unwrap();
        let resp_t = resp_start.elapsed();
        let resp_len = encoded_resp.len();

        let resp_handle_start = Instant::now();
        let decode_resp: migration::Response = bincode::deserialize(&encoded_resp[..]).unwrap();
        let cred = migration::handle_response(migstate, decode_resp, &self.ba.lox_pub).unwrap();
        let resp_handle_t = resp_handle_start.elapsed();

        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            cred,
        )
    }

    fn level_up(&mut self, cred: &cred::Lox) -> (PerfStat, cred::Lox) {
        // Read the bucket in the credential to get today's Bucket
        // Reachability credential

        let (id, key) = bridge_table::from_scalar(cred.bucket).unwrap();
        let encbuckets = self.ba.enc_bridge_table();
        let bucket =
            bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap())
                .unwrap();

        let reachcred = bucket.1.unwrap();

        // Use the Bucket Reachability credential to advance to the next
        // level
        let req_start = Instant::now();
        let (req, state) = level_up::request(
            cred,
            &reachcred,
            &self.ba.lox_pub,
            &self.ba.reachability_pub,
            self.ba.today(),
        )
        .unwrap();
        let encoded: Vec<u8> = bincode::serialize(&req).unwrap();
        let req_t = req_start.elapsed();
        let req_len = encoded.len();

        let resp_start = Instant::now();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        let resp = self.ba.handle_level_up(decoded).unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&resp).unwrap();
        let resp_t = resp_start.elapsed();
        let resp_len = encoded_resp.len();

        let resp_handle_start = Instant::now();
        let decode_resp = bincode::deserialize(&encoded_resp[..]).unwrap();
        let cred = level_up::handle_response(state, decode_resp, &self.ba.lox_pub).unwrap();
        let resp_handle_t = resp_handle_start.elapsed();

        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            cred,
        )
    }

    fn issue_invite(&mut self, cred: &cred::Lox) -> (PerfStat, (cred::Lox, cred::Invitation)) {
        // Read the bucket in the credential to get today's Bucket
        // Reachability credential
        let (id, key) = bridge_table::from_scalar(cred.bucket).unwrap();
        let encbuckets = self.ba.enc_bridge_table();
        let bucket =
            bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap())
                .unwrap();
        let reachcred = bucket.1.unwrap();

        let req_start = Instant::now();
        let (req, state) = issue_invite::request(
            cred,
            &reachcred,
            &self.ba.lox_pub,
            &self.ba.reachability_pub,
            &self.ba.invitation_pub,
            self.ba.today(),
        )
        .unwrap();
        let encoded: Vec<u8> = bincode::serialize(&req).unwrap();
        let req_t = req_start.elapsed();
        let req_len = encoded.len();

        let resp_start = Instant::now();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        let resp = self.ba.handle_issue_invite(decoded).unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&resp).unwrap();
        let resp_t = resp_start.elapsed();
        let resp_len = encoded_resp.len();

        let resp_handle_start = Instant::now();
        let decode_resp = bincode::deserialize(&encoded_resp[..]).unwrap();
        let (cred, invite) = issue_invite::handle_response(
            state,
            decode_resp,
            &self.ba.lox_pub,
            &self.ba.invitation_pub,
        )
        .unwrap();
        let resp_handle_t = resp_handle_start.elapsed();

        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            (cred, invite),
        )
    }

    fn redeem_invite(&mut self, inv: &cred::Invitation) -> (PerfStat, cred::Lox) {
        let req_start = Instant::now();
        let (req, state) = redeem_invite::request(
            inv,
            &self.ba.lox_pub,
            &self.ba.invitation_pub,
            self.ba.today(),
        )
        .unwrap();
        let encoded: Vec<u8> = bincode::serialize(&req).unwrap();
        let req_t = req_start.elapsed();
        let req_len = encoded.len();

        let resp_start = Instant::now();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        let resp = self.ba.handle_redeem_invite(decoded).unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&resp).unwrap();
        let resp_t = resp_start.elapsed();
        let resp_len = encoded_resp.len();

        let resp_handle_start = Instant::now();
        let decode_resp = bincode::deserialize(&encoded_resp[..]).unwrap();
        let cred = redeem_invite::handle_response(state, decode_resp, &self.ba.lox_pub).unwrap();
        let resp_handle_t = resp_handle_start.elapsed();

        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            cred,
        )
    }

    fn check_blockage(&mut self, cred: &cred::Lox) -> (PerfStat, cred::Migration) {
        let req_start = Instant::now();
        let (req, state) =
            check_blockage::request(cred, &self.ba.lox_pub, &self.ba.migrationkey_pub).unwrap();
        let encoded: Vec<u8> = bincode::serialize(&req).unwrap();
        let req_t = req_start.elapsed();
        let req_len = encoded.len();

        let resp_start = Instant::now();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        let resp = self.ba.handle_check_blockage(decoded).unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&resp).unwrap();
        let resp_t = resp_start.elapsed();
        let resp_len = encoded_resp.len();

        let resp_handle_start = Instant::now();
        let decode_resp = bincode::deserialize(&encoded_resp[..]).unwrap();
        let migcred = check_blockage::handle_response(state, decode_resp).unwrap();
        let resp_handle_t = resp_handle_start.elapsed();

        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            migcred,
        )
    }

    fn blockage_migration(
        &mut self,
        cred: &cred::Lox,
        mig: &cred::Migration,
    ) -> (PerfStat, cred::Lox) {
        let req_start = Instant::now();
        let (req, state) =
            blockage_migration::request(cred, mig, &self.ba.lox_pub, &self.ba.migration_pub)
                .unwrap();
        let encoded: Vec<u8> = bincode::serialize(&req).unwrap();
        let req_t = req_start.elapsed();
        let req_len = encoded.len();

        let resp_start = Instant::now();
        let decoded = bincode::deserialize(&encoded[..]).unwrap();
        let resp = self.ba.handle_blockage_migration(decoded).unwrap();
        let encoded_resp: Vec<u8> = bincode::serialize(&resp).unwrap();
        let resp_t = resp_start.elapsed();
        let resp_len = encoded_resp.len();

        let resp_handle_start = Instant::now();
        let decode_resp: blockage_migration::Response =
            bincode::deserialize(&encoded_resp[..]).unwrap();
        let cred =
            blockage_migration::handle_response(state, decode_resp, &self.ba.lox_pub).unwrap();
        let resp_handle_t = resp_handle_start.elapsed();

        (
            PerfStat {
                req_len,
                resp_len,
                req_t,
                resp_t,
                resp_handle_t,
            },
            cred,
        )
    }
}

#[test]
fn test_rotate_lox_keys() {
    let mut th = TestHarness::new();
    let old_private = th.ba.lox_priv.clone();
    let old_pub = th.ba.lox_pub.clone();
    assert!(
        th.ba.old_keys.lox_keys.is_empty(),
        "Outdated secret keys were not empty"
    );
    assert!(
        th.ba.old_filters.lox_filter.is_empty(),
        "Old id filter is not empty"
    );
    th.ba.rotate_lox_keys();
    assert!(
        !th.ba.old_keys.lox_keys.is_empty(),
        "No outdated secret keys after rotation"
    );
    assert!(
        th.ba.old_keys.lox_keys.clone().last().unwrap().priv_key == old_private
            && th.ba.old_keys.lox_keys.clone().last().unwrap().pub_key == old_pub,
        "Outdated keys do not match old Lox keys"
    );
    assert!(
        th.ba.lox_priv != old_private && th.ba.lox_pub != old_pub,
        "Lox keys not successfully rotated"
    );
    assert!(
        !th.ba.old_filters.lox_filter.is_empty(),
        "No old id filter after rotation"
    );
}

#[test]
fn test_rotate_invitation_keys() {
    let mut th = TestHarness::new();
    let old_private = th.ba.invitation_priv.clone();
    let old_pub = th.ba.invitation_pub.clone();
    assert!(
        th.ba.old_keys.invitation_keys.is_empty(),
        "Outdated secret keys were not empty"
    );
    assert!(
        th.ba.old_filters.invitation_filter.is_empty(),
        "Old id filter is not empty"
    );
    th.ba.rotate_invitation_keys();
    assert!(
        !th.ba.old_keys.invitation_keys.is_empty(),
        "No outdated secret keys after rotation"
    );
    assert!(
        th.ba
            .old_keys
            .invitation_keys
            .clone()
            .last()
            .unwrap()
            .priv_key
            == old_private
            && th
                .ba
                .old_keys
                .invitation_keys
                .clone()
                .last()
                .unwrap()
                .pub_key
                == old_pub,
        "Outdated keys do not match old invitation keys"
    );
    assert!(
        th.ba.invitation_priv != old_private && th.ba.invitation_pub != old_pub,
        "invitation keys not successfully rotated"
    );
    assert!(
        !th.ba.old_filters.invitation_filter.is_empty(),
        "No old id filter after rotation"
    );
}

#[test]
fn test_open_invite() {
    let mut th = TestHarness::new();

    // Join an untrusted user
    let (perf_stat, (cred, bridgeline)) = th.open_invite();

    // Check that we can use the credential to read a bucket
    let (id, key) = bridge_table::from_scalar(cred.bucket).unwrap();
    let encbuckets = th.ba.enc_bridge_table();
    let bucket =
        bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap()).unwrap();
    print_test_results(perf_stat);
    println!("cred = {:?}", cred);
    println!("bucket = {:?}", bucket);
    println!("bridgeline = {:?}", bridgeline);
    assert!(bucket.1.is_none());
    assert!(th.ba.verify_lox(&cred));
    assert!(bridgeline == bucket.0[0]);
}

#[test]
fn test_update_open_invite_and_key_rotation() {
    let mut th = TestHarness::new();
    // Issue an open invitation
    let bdb_key = th.ba.bridgedb_pub.clone();
    assert!(
        th.ba.old_filters.openinv_filter.is_empty(),
        "OpenInv filter should not be initialized before key rotation"
    );
    assert!(
        th.ba.old_keys.bridgedb_key.is_empty(),
        "OpenInv key should not be initialized before key rotation"
    );

    let new_bdb_pubkey = th.bdb.rotate_open_inv_keys();
    th.ba.rotate_bridgedb_keys(new_bdb_pubkey);
    assert!(
        !th.ba.old_filters.openinv_filter.is_empty(),
        "OpenInv filter should be initialized after key rotation"
    );
    assert!(
        !th.ba.old_keys.bridgedb_key.is_empty(),
        "OpenInv key should be initialized after key rotation"
    );
    let new_inv = th.bdb.invite().unwrap();
    assert!(
        bdb_key != th.ba.bridgedb_pub,
        "Bridgedb public keys should differ after key rotation"
    );

    // Use it to get a Lox credential
    let (req, state) = open_invite::request(&new_inv, &th.ba.lox_pub);
    let encoded: Vec<u8> = bincode::serialize(&req).unwrap();
    let decoded = bincode::deserialize(&encoded[..]).unwrap();
    let resp = th.ba.handle_open_invite(decoded).unwrap();
    let encoded_resp: Vec<u8> = bincode::serialize(&resp).unwrap();

    let decode_resp = bincode::deserialize(&encoded_resp[..]).unwrap();
    let result = open_invite::handle_response(state, decode_resp, &th.ba.lox_pub);
    assert!(result.is_ok(), "Handle response should be Ok");
}

#[test]
fn test_k_invites() {
    let mut th = TestHarness::new();
    for i in 0..25 {
        let _ = th.open_invite();
        if (i + 1) % OPENINV_K != 0 {
            assert!(
                th.bdb.current_k == (i + 1) % OPENINV_K,
                "the current_k should be (i+1)%OPENINV_K"
            );
        } else {
            assert!(
                th.bdb.current_k == OPENINV_K,
                "the current_k should be OPENINV_K"
            );
        }
    }
}

#[test]
fn test_trust_promotion() {
    let mut th = TestHarness::new();

    let cred = th.open_invite().1 .0;
    assert!(th.ba.verify_lox(&cred));

    // Time passes
    th.advance_days(47);

    let (perf_stat, migcred) = th.trust_promotion(&cred);
    assert!(th.ba.verify_migration(&migcred));

    // Check that we can use the to_bucket in the Migration credenital
    // to read a bucket
    let (id, key) = bridge_table::from_scalar(migcred.to_bucket).unwrap();
    let encbuckets = th.ba.enc_bridge_table();
    let bucket =
        bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap()).unwrap();
    print_test_results(perf_stat);
    println!("bucket = {:?}", bucket);
    assert!(th.ba.verify_reachability(&bucket.1.unwrap()));
}

#[test]
fn test_level0_migration() {
    let mut th = TestHarness::new();

    let cred = th.open_invite().1 .0;
    assert!(th.ba.verify_lox(&cred));

    // Time passes
    th.advance_days(47);

    let (perf_stat, migcred) = th.trust_promotion(&cred);
    assert!(th.ba.verify_migration(&migcred));
    println!("--Trust Promotion to 1--\n");
    print_test_results(perf_stat);

    let (mperf_stat, newloxcred) = th.level0_migration(&cred, &migcred);

    println!("--Level 0 migration--\n");
    print_test_results(mperf_stat);

    assert!(th.ba.verify_lox(&newloxcred));
    println!("newloxcred = {:?}", newloxcred);
    // Check that we can use the credenital to read a bucket
    let (id, key) = bridge_table::from_scalar(newloxcred.bucket).unwrap();
    let encbuckets = th.ba.enc_bridge_table();
    let bucket =
        bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap()).unwrap();
    println!("bucket = {:?}", bucket);
    assert!(th.ba.verify_reachability(&bucket.1.unwrap()));
}

#[test]
fn test_level_up() {
    let mut th = TestHarness::new();

    // Join an untrusted user
    let cred = th.open_invite().1 .0;

    // Time passes
    th.advance_days(47);

    // Go up to level 1
    let (perf_stat, migcred) = th.trust_promotion(&cred);

    println!("--Trust Promotion to 1--\n");
    print_test_results(perf_stat);

    let (mperf_stat, cred1) = th.level0_migration(&cred, &migcred);

    println!("--New Level 1 Credential--\n");
    print_test_results(mperf_stat);

    assert!(scalar_u32(&cred1.trust_level).unwrap() == 1);

    // Time passes
    th.advance_days(20);

    let (two_perf_stat, cred2) = th.level_up(&cred1);
    assert!(scalar_u32(&cred2.trust_level).unwrap() == 2);

    println!("--Upgrade to Level 2--\n");
    print_test_results(two_perf_stat);
    println!("cred2 = {:?}", cred2);
    assert!(th.ba.verify_lox(&cred2));

    // Time passes
    th.advance_days(30);

    let (three_perf_stat, cred3) = th.level_up(&cred2);
    assert!(scalar_u32(&cred3.trust_level).unwrap() == 3);
    println!("--Upgrade to Level 3--\n");
    print_test_results(three_perf_stat);
    println!("cred3 = {:?}", cred3);
    assert!(th.ba.verify_lox(&cred3));

    // Time passes
    th.advance_days(60);

    let (four_perf_stat, cred4) = th.level_up(&cred3);
    assert!(scalar_u32(&cred3.trust_level).unwrap() == 3);
    println!("--Upgrade to Level 4--\n");
    print_test_results(four_perf_stat);
    println!("cred4 = {:?}", cred4);
    assert!(th.ba.verify_lox(&cred4));
}

#[test]
fn test_issue_invite() {
    let mut th = TestHarness::new();

    // Join an untrusted user
    let cred = th.open_invite().1 .0;

    // Time passes
    th.advance_days(47);

    // Go up to level 1
    let (perf_stat, migcred) = th.trust_promotion(&cred);
    println!("--Trust Promotion to 1--\n");
    print_test_results(perf_stat);
    let (mperf_stat, cred1) = th.level0_migration(&cred, &migcred);
    println!("--New Level 1 Credential--\n");
    print_test_results(mperf_stat);
    assert!(scalar_u32(&cred1.trust_level).unwrap() == 1);

    // Time passes
    th.advance_days(20);

    // Go up to level 2
    let (two_perf_stat, cred2) = th.level_up(&cred1);
    println!("--Upgrade to Level 2--\n");
    print_test_results(two_perf_stat);
    assert!(scalar_u32(&cred2.trust_level).unwrap() == 2);
    println!("cred2 = {:?}", cred2);
    assert!(th.ba.verify_lox(&cred2));

    // Issue an invitation
    let (invite_perf_stat, (cred2a, invite)) = th.issue_invite(&cred2);
    println!("--Issue Invitation--\n");
    print_test_results(invite_perf_stat);
    assert!(th.ba.verify_lox(&cred2a));
    assert!(th.ba.verify_invitation(&invite));
    println!("cred2a = {:?}", cred2a);
    println!("invite = {:?}", invite);
}

#[test]
fn test_update_cred() {
    let mut th = TestHarness::new();

    // Get open invite credential
    let cred = th.open_invite().1 .0;

    // Attempt to update credential with new keys before next request
    let (up_req, _upstate) = update_cred::request(&cred, &th.ba.lox_pub, &th.ba.lox_pub).unwrap();
    let encoded: Vec<u8> = bincode::serialize(&up_req).unwrap();
    let decoded = bincode::deserialize(&encoded[..]).unwrap();
    let promresp = th.ba.handle_update_cred(decoded);
    assert!(
        promresp.is_err(),
        "Before key rotation credential update requests should fail"
    );

    // Time passes
    th.advance_days(47);

    let mut old_key = th.ba.lox_pub.clone();

    // Rotate Keys
    th.ba.rotate_lox_keys();

    // Attempt trust promotion with incorrect keys
    let (promreq, _promstate) = trust_promotion::request(
        &cred,
        &th.ba.lox_pub,
        &&th.ba.migrationkey_pub,
        th.ba.today(),
    )
    .unwrap();
    let encoded: Vec<u8> = bincode::serialize(&promreq).unwrap();
    let decoded = bincode::deserialize(&encoded[..]).unwrap();
    let promresp = th.ba.handle_trust_promotion(decoded);
    assert!(
        promresp.is_err(),
        "After key rotation old credentials must be updated before they will verify"
    );

    // Update credential with new keys before next request
    let (_, up_cred) = th.update_cred(&cred);

    // Attempt Update credential with used credential
    let (upreq, _upstate) = update_cred::request(&cred, &old_key, &th.ba.lox_pub).unwrap();
    let encoded: Vec<u8> = bincode::serialize(&upreq).unwrap();
    let decoded = bincode::deserialize(&encoded[..]).unwrap();
    let promresp = th.ba.handle_update_cred(decoded);
    assert!(
        promresp.is_err(),
        "A previously used credential should not be reusable"
    );

    // Successfully go up to level 1 with updated credential
    let (_, migcred) = th.trust_promotion(&up_cred);
    println!("--Trust Promotion to 1--\n");

    let (_perf_stat, cred1) = th.level0_migration(&up_cred, &migcred);
    println!("--New Level 1 Credential--\n");
    assert!(scalar_u32(&cred1.trust_level).unwrap() == 1);

    // Attempt to update credential with new keys before next request
    let (up_req, _upstate) = update_cred::request(&cred1, &old_key, &th.ba.lox_pub).unwrap();
    let encoded: Vec<u8> = bincode::serialize(&up_req).unwrap();
    let mut decoded = bincode::deserialize(&encoded[..]).unwrap();
    let mut promresp = th.ba.handle_update_cred(decoded);
    assert!(promresp.is_err(), "Before another key rotation, credential update requests should fail due to verification with wrong pubkey");

    old_key = th.ba.lox_pub.clone();
    // Rotate Keys
    th.ba.rotate_lox_keys();
    decoded = bincode::deserialize(&encoded[..]).unwrap();
    promresp = th.ba.handle_update_cred(decoded);
    assert!(
        promresp.is_err(),
        "An updated credential prepared before the key rotation shouldn't work after the key rotation"
    );

    // Updated request should once again work
    let (up_req, _upstate) = update_cred::request(&cred1, &old_key, &th.ba.lox_pub).unwrap();
    let encoded: Vec<u8> = bincode::serialize(&up_req).unwrap();
    decoded = bincode::deserialize(&encoded[..]).unwrap();
    promresp = th.ba.handle_update_cred(decoded);
    assert!(
        promresp.is_ok(),
        "After key rotation, update cred should verify with correct keys"
    );
}

#[test]
fn test_redeem_invite() {
    let mut th = TestHarness::new();

    // Join an untrusted user
    let cred = th.open_invite().1 .0;

    // Time passes
    th.advance_days(47);

    // Go up to level 1
    let (perf_stat, migcred) = th.trust_promotion(&cred);
    println!("--Trust Promotion to 1--\n");
    print_test_results(perf_stat);
    let (mperf_stat, cred1) = th.level0_migration(&cred, &migcred);
    println!("--New Level 1 Credential--\n");
    print_test_results(mperf_stat);
    assert!(scalar_u32(&cred1.trust_level).unwrap() == 1);

    // Time passes
    th.advance_days(20);

    // Go up to level 2
    let (two_perf_stat, cred2) = th.level_up(&cred1);
    println!("--Upgrade to Level 2--\n");
    print_test_results(two_perf_stat);
    assert!(scalar_u32(&cred2.trust_level).unwrap() == 2);
    println!("cred2 = {:?}", cred2);
    assert!(th.ba.verify_lox(&cred2));

    // Issue an invitation to Bob
    let (invite_perf_stat, (cred2a, bob_invite)) = th.issue_invite(&cred2);
    println!("--Issue Invitation--\n");
    print_test_results(invite_perf_stat);
    assert!(th.ba.verify_lox(&cred2a));
    assert!(th.ba.verify_invitation(&bob_invite));
    println!("cred2a = {:?}", cred2a);
    println!("bob_invite = {:?}", bob_invite);

    // Time passes
    th.advance_days(12);

    // Bob joins the system
    let (bob_perf_stat, bob_cred) = th.redeem_invite(&bob_invite);
    println!("--Bob joins the system--\n");
    print_test_results(bob_perf_stat);
    assert!(th.ba.verify_lox(&bob_cred));
    println!("bob_cred = {:?}", bob_cred);
}

#[test]
fn test_update_invitation() {
    let mut th = TestHarness::new();

    // Join an untrusted user
    let cred = th.open_invite().1 .0;

    // Time passes
    th.advance_days(47);

    // Go up to level 1
    let (_, migcred) = th.trust_promotion(&cred);
    let (_, cred1) = th.level0_migration(&cred, &migcred);
    assert!(scalar_u32(&cred1.trust_level).unwrap() == 1);

    // Time passes
    th.advance_days(20);

    // Go up to level 2
    let (_, cred2) = th.level_up(&cred1);
    assert!(scalar_u32(&cred2.trust_level).unwrap() == 2);
    assert!(th.ba.verify_lox(&cred2));

    // Issue an invitation to Bob
    let (_, (cred2a, bob_invite)) = th.issue_invite(&cred2);
    println!("--Issue Invitation--\n");
    assert!(th.ba.verify_lox(&cred2a));
    assert!(th.ba.verify_invitation(&bob_invite));

    // Time passes
    th.advance_days(12);

    // Attempt to update invitation with old keys before next request
    let (up_req, _upstate) =
        update_invite::request(&bob_invite, &th.ba.invitation_pub, &th.ba.invitation_pub).unwrap();
    let encoded: Vec<u8> = bincode::serialize(&up_req).unwrap();
    let decoded = bincode::deserialize(&encoded[..]).unwrap();
    let promresp = th.ba.handle_update_invite(decoded);
    assert!(
        promresp.is_err(),
        "Before key rotation invitation update requests should fail"
    );

    let old_keys = th.ba.invitation_pub.clone();

    // Rotate Keys
    th.ba.rotate_invitation_keys();

    // Attempt update invitation with incorrect keys
    let (up_req, _upstate) = update_invite::request(&bob_invite, &old_keys, &old_keys).unwrap();
    let encoded: Vec<u8> = bincode::serialize(&up_req).unwrap();
    let decoded = bincode::deserialize(&encoded[..]).unwrap();
    let promresp = th.ba.handle_update_invite(decoded);
    assert!(
        promresp.is_err(),
        "After key rotation old credentials must be updated before they will verify"
    );

    // Update credential with new keys before next request
    let (perf_stat, up_cred) = th.update_invitation(&bob_invite);

    // Attempt to reissue a spent invitation
    let (upreq, _upstate) =
        update_invite::request(&bob_invite, &old_keys, &th.ba.invitation_pub).unwrap();
    let encoded: Vec<u8> = bincode::serialize(&upreq).unwrap();
    let decoded = bincode::deserialize(&encoded[..]).unwrap();
    let promresp = th.ba.handle_update_invite(decoded);
    assert!(
        promresp.is_err(),
        "A spent invitation should not be successfully reissued."
    );

    // Successfully redeem invite
    let result = th.redeem_invite(&up_cred);
    assert!(
        result.1.bucket == bob_invite.bucket,
        "Updated invitation should be redeemable for a Lox credential with the same bucket"
    );

    println!("--Update Invitation--\n");
    print_test_results(perf_stat);
}

#[test]
fn test_clean_up_blocked() {
    let num_open_buckets = 5;
    let num_spare_buckets = 5;
    let mut th = TestHarness::new_buckets(num_open_buckets, num_spare_buckets);
    // add users so that some blocked bridges were distributed
    for _ in 0..2 {
        let cred = th.open_invite().1 .0;
        th.advance_days(30);
        let (_, migcred) = th.trust_promotion(&cred);
        let (_, cred1) = th.level0_migration(&cred, &migcred);
        th.advance_days(14);
        let (_, cred2) = th.level_up(&cred1);
        let (_, (cred2a, invite)) = th.issue_invite(&cred2);
        let (_, bob_cred) = th.redeem_invite(&invite);
        th.advance_days(28);
        let (_, _) = th.level_up(&bob_cred);
        let (_, _cred3) = th.level_up(&cred2a);
    }
    let num_blocked = 5;
    block_bridges(&mut th, num_blocked);
    assert!(
        num_blocked == th.ba.bridge_table.blocked_keys.len(),
        "Number of blocked keys was {}, should be {}",
        th.ba.bridge_table.blocked_keys.len(),
        num_blocked
    );
    assert!(th.ba.bridge_table.recycleable_keys.is_empty(), "");
    // Each open invitation bucket creates 4 buckets
    assert!(
        th.ba.bridge_table.counter == (4 * num_open_buckets + num_spare_buckets) as u32,
        "Number of buckets was {}, should be {}",
        th.ba.bridge_table.counter,
        4 * num_open_buckets + num_spare_buckets
    );
    // Advance beyond the time that blocked buckets expire
    th.advance_days((EXPIRY_DATE + 1).try_into().unwrap());
    th.ba.clean_up_blocked();
    assert!(
        th.ba.bridge_table.blocked_keys.is_empty(),
        "No fresh blocks, blocked keys should be empty"
    );
    assert!(
        th.ba.bridge_table.recycleable_keys.len() == num_blocked,
        "Recycleable keys was {}, should be {}",
        th.ba.bridge_table.recycleable_keys.len(),
        num_blocked
    );
    assert!(
        th.ba.bridge_table.counter == (4 * num_open_buckets + num_spare_buckets) as u32,
        "Number of buckets should be {}, was {}",
        th.ba.bridge_table.counter,
        4 * num_open_buckets + num_spare_buckets
    );
}

#[test]
fn test_clean_up_open_entry() {
    let num_open_buckets = 5;
    let num_spare_buckets = 5;
    let mut th = TestHarness::new_buckets(num_open_buckets, num_spare_buckets);
    let mut credentials: Vec<cred::Lox> = Vec::new();
    let mut level_1_credentials: Vec<cred::Lox> = Vec::new();
    // Users
    for _ in 0..2 {
        let cred = th.open_invite().1 .0;
        credentials.push(cred);
    }
    assert!(
        th.ba.trustup_migration_table.table.len() == 3 * num_open_buckets as usize,
        "Number of trustup migrations should be {}, was {}",
        3 * num_open_buckets,
        th.ba.trustup_migration_table.table.len()
    );
    th.advance_days(30);
    for cred in credentials {
        let (_, migcred) = th.trust_promotion(&cred);
        let (_, cred1) = th.level0_migration(&cred, &migcred);
        level_1_credentials.push(cred1);
    }
    th.advance_days((EXPIRY_DATE + 1).try_into().unwrap());
    assert!(
        th.ba.bridge_table.open_inv_keys.len() == 3 * num_open_buckets as usize,
        "Number of open invitation keys should be {}, was {}",
        3 * num_open_buckets,
        th.ba.bridge_table.open_inv_keys.len()
    );
    assert!(th.ba.bridge_table.recycleable_keys.is_empty(), "");
    th.ba.clean_up_open_entry(&mut th.bdb);
    assert!(
        th.ba.bridge_table.open_inv_keys.is_empty(),
        "Number open entry keys should be {}, was {}",
        0,
        th.ba.bridge_table.open_inv_keys.len()
    );
    assert!(
        th.ba.trustup_migration_table.table.is_empty(),
        "There should be no remaining eligible trust up migrations"
    );
    assert!(
        th.ba.bridge_table.recycleable_keys.len() == 3 * num_open_buckets as usize,
        "Number recycleable keys should be {}, was {}",
        3 * num_open_buckets,
        th.ba.bridge_table.open_inv_keys.len()
    );
    // Each open invitation bucket creates 4 buckets
    assert!(
        th.ba.bridge_table.counter == (4 * num_open_buckets + num_spare_buckets) as u32,
        "Number of buckets should be {}, was {}",
        4 * num_open_buckets + num_spare_buckets,
        th.ba.bridge_table.counter
    );
}

#[test]
fn test_find_next_available_key() {
    let mut th = TestHarness::new_buckets(50, 50);
    let mut credentials: Vec<cred::Lox> = Vec::new();
    // Users
    for _ in 0..25 {
        let cred = th.open_invite().1 .0;
        credentials.push(cred);
    }
    assert!(
        th.ba.bridge_table.counter == 250,
        "There should be 50*3 openinv buckets + 50 superset buckets +50 spare buckets"
    );
    assert!(
        th.ba.bridge_table.recycleable_keys.is_empty(),
        "There should be no recyclable keys"
    );
    assert!(
        th.ba.bridge_table.blocked_keys.is_empty(),
        "There should be no blocked keys"
    );
    assert!(
        th.ba.bridge_table.open_inv_keys.len() == 150,
        "There should be 150 open inv keys"
    );
    block_bridges(&mut th, 45);
    assert!(
        th.ba.bridge_table.counter == 250,
        "There should be 50*3 openinv buckets + 50 superset buckets +50 spare buckets"
    );
    assert!(
        th.ba.bridge_table.blocked_keys.len() == 45,
        "Blocked keys should be 45"
    );
    assert!(
        th.ba.bridge_table.recycleable_keys.is_empty(),
        "There should be no recyclable keys"
    );
    let bucket = [
        BridgeLine::random(),
        BridgeLine::random(),
        BridgeLine::random(),
    ];
    // Add new bucket to trigger bucket cleanup and find_next_available_key
    let _ = th.ba.add_spare_bucket(bucket, &mut th.bdb);
    // No recyclable keys yet so counter should increase
    assert!(
        th.ba.bridge_table.counter == 251,
        "There should be 50*3 openinv buckets + 50 superset buckets +50 spare buckets"
    );
    assert!(
        th.ba.bridge_table.recycleable_keys.is_empty(),
        "There should be no recyclable keys"
    );
    assert!(
        th.ba.bridge_table.blocked_keys.len() == 45,
        "There should still be 45 blocked keys"
    );
    assert!(
        th.ba.bridge_table.open_inv_keys.len() == 150,
        "There should still be 150 open inv keys"
    );
    // Advance to all open inv and blocked bridges being expired
    th.advance_days(512);
    let bucket = [
        BridgeLine::random(),
        BridgeLine::random(),
        BridgeLine::random(),
    ];
    // Add new bridges to trigger bucket cleanup
    let _ = th.ba.add_spare_bucket(bucket, &mut th.bdb);
    // Now all keys should be cleaned up so the counter won't move
    assert!(
        th.ba.bridge_table.counter == 251,
        "There should be 50*3 openinv buckets + 50 superset buckets +50 spare buckets"
    );
    // This should be equal to the previous keys - 1 for the new spare bucket
    assert!(
        th.ba.bridge_table.recycleable_keys.len() == 45 + 150 - 1,
        "There should be no recyclable keys"
    );
    assert!(
        th.ba.bridge_table.blocked_keys.is_empty(),
        "There should be no blocked keys"
    );
    assert!(
        th.ba.bridge_table.open_inv_keys.is_empty(),
        "There should be 150 open inv keys"
    );
}

/// Blocks a percentage of the bridges for the passed Test Harness
/// excluding the hot spare buckets as they will not have been handed out.
/// The logic assumes hot spare buckets are appended to the end of the bridge_table
/// bucket list.

fn block_bridges(th: &mut TestHarness, to_block: usize) {
    let blockable_range = th.ba.bridge_table.buckets.len() - th.ba.bridge_table.spares.len();
    let mut block_index: HashSet<usize> = HashSet::new();
    let mut rng = rand::rngs::OsRng;

    while block_index.len() < to_block {
        let rand_num = rng.gen_range(1..blockable_range);
        if !th.bdb.openinv_buckets.contains(&(rand_num as u32))
            && !th.bdb.distributed_buckets.contains(&(rand_num as u32))
            && !block_index.contains(&rand_num)
        {
            block_index.insert(rand_num);
        }
    }

    for index in block_index {
        let ba_clone = th.ba.bridge_table.buckets.clone();
        if let Some(bridgelines) = ba_clone.get(&u32::try_from(index).unwrap()) {
            for bridgeline in bridgelines {
                th.ba.bridge_blocked(bridgeline, &mut th.bdb);
            }
        }
    }
}

#[test]
fn test_allocate_bridges() {
    let mut th = TestHarness::new();
    let distributor_bridges: &mut Vec<BridgeLine> = &mut Vec::new();
    let table_size = th.ba.bridge_table.buckets.len();
    for _ in 0..3 {
        distributor_bridges.push(BridgeLine::random());
    }
    assert!(
        !distributor_bridges.is_empty(),
        "No BridgeLines in distributor_bridges"
    );
    th.ba.allocate_bridges(distributor_bridges, &mut th.bdb);
    assert!(
        distributor_bridges.is_empty(),
        "BridgeLines in distributor_bridges were not allocated"
    );
    assert!(
        th.ba.bridge_table.buckets.len() > table_size,
        "Size of bridge table did not increase"
    );
    let table_size = th.ba.bridge_table.buckets.len();
    for _ in 0..2 {
        distributor_bridges.push(BridgeLine::random());
        th.ba
            .bridge_table
            .unallocated_bridges
            .push(BridgeLine::random());
    }
    assert!(
        !th.ba.bridge_table.unallocated_bridges.is_empty(),
        "No BridgeLines in unallocated bridges"
    );
    assert!(
        !distributor_bridges.is_empty(),
        "No BridgeLines in distributor_bridges"
    );
    th.ba.allocate_bridges(distributor_bridges, &mut th.bdb);
    assert!(
        th.ba.bridge_table.unallocated_bridges.len() == 1,
        "Incorrect number of bridges remain unallocated"
    );
    assert!(
        distributor_bridges.is_empty(),
        "BridgeLines in distributor_bridges were not allocated"
    );
    assert!(
        th.ba.bridge_table.buckets.len() > table_size,
        "Size of bridge table did not increase"
    );
}

#[test]
fn test_update_bridge() {
    let mut th = TestHarness::new();
    // Add new bridge to table with known values,
    // check that I can find and update the values and that everything else stays the same

    // Create 3 bridges to test harness
    let bucket = [
        BridgeLine::random(),
        BridgeLine::random(),
        BridgeLine::random(),
    ];
    // Store first bridgeline to update later
    let bridgeline_to_update = bucket[0];
    // Create changed info for bridgeline to be updated to
    let infostr: String = format!(
        "type={} blocked_in={:?} protocol={} distribution={}",
        "obfs2 test bridge",
        {},
        "obfs2",
        "moat",
    );
    let mut updated_info_bytes: [u8; BRIDGE_BYTES - 26] = [0; BRIDGE_BYTES - 26];

    updated_info_bytes[..infostr.len()].copy_from_slice(infostr.as_bytes());

    let updated_bridgeline = BridgeLine {
        addr: bridgeline_to_update.addr,
        port: bridgeline_to_update.port,
        uid_fingerprint: bridgeline_to_update.uid_fingerprint,
        info: updated_info_bytes,
    };

    assert!(
        updated_bridgeline.uid_fingerprint == bridgeline_to_update.uid_fingerprint,
        "Bridge entering the bridgepool {:?} did not have the same fingerprint as the updating bridge {:?}",
        bridgeline_to_update,
        updated_bridgeline.uid_fingerprint
    );
    assert!(updated_bridgeline.info != bridgeline_to_update.info);
    println!(
        "Bridge entering the bridgepool {:?} has different info than the updating bridge {:?}",
        bridgeline_to_update.info, updated_bridgeline.info
    );
    assert!(updated_bridgeline != bridgeline_to_update);
    println!("The two bridgelines are not equal before the update");

    // Add 3 bridges to test harness
    let _ = th.ba.add_openinv_bridges(bucket, &mut th.bdb);

    println!("Before update spares = {:?}", th.ba.bridge_table.spares);
    println!(
        "Before update tmig = {:?}",
        th.ba.trustup_migration_table.table
    );
    println!(
        "Before update bmig = {:?}",
        th.ba.blockage_migration_table.table
    );
    println!("Before update openinv = {:?}\n", th.bdb.openinv_buckets);

    // Update the info of a bridge with matching IP and Port to a bridge in the bridge table
    let result = th.ba.bridge_update(&updated_bridgeline);
    assert!(result, "Bridge failed to update successfully!!");
    let found_bridge = th
        .ba
        .bridge_table
        .reachable
        .get_key_value(&updated_bridgeline);
    assert!(*found_bridge.unwrap().0 != bridgeline_to_update);
    assert!(*found_bridge.unwrap().0 == updated_bridgeline);
    println!("After update spares = {:?}", th.ba.bridge_table.spares);
    println!(
        "After update tmig = {:?}",
        th.ba.trustup_migration_table.table
    );
    println!(
        "After update bmig = {:?}",
        th.ba.blockage_migration_table.table
    );
    println!("After update openinv = {:?}\n", th.bdb.openinv_buckets);
}

#[test]
fn test_bridge_replace() {
    // Create 3 open invitation buckets and 3 spare buckets
    let cases = vec![
        "not found",
        "available",
        "unallocated",
        "use_spare",
        "remove_spare",
        "failed",
    ];
    let num_buckets = 5;
    let hot_spare = 0;
    for case in cases {
        let table_size: usize;
        let mut th: TestHarness;
        match case {
            "failed" => {
                th = TestHarness::new_buckets(num_buckets, hot_spare);
                table_size = th.ba.bridge_table.buckets.len();
            }
            "remove_spare" => {
                th = TestHarness::new_buckets(0, 5);
                table_size = th.ba.bridge_table.buckets.len();
            }
            _ => {
                th = TestHarness::new();
                // Ensure that a randomly selected bucket isn't taken from the set of spare bridges
                table_size = th.ba.bridge_table.buckets.len() - 5;
            }
        }

        // Randomly select a bridge to replace
        let mut num = 100000;
        while !th.ba.bridge_table.buckets.contains_key(&num) {
            num = rand::rngs::OsRng.gen_range(0..table_size as u32);
        }
        println!("chosen num is: {:?}", num);
        let replaceable_bucket = *th.ba.bridge_table.buckets.get(&num).unwrap();
        let replacement_bridge = &replaceable_bucket[0];
        assert!(
            th.ba
                .bridge_table
                .reachable
                .contains_key(replacement_bridge),
            "Random bridge to replace not in reachable bridges"
        );

        match case {
            "not found" => {
                // Case zero: bridge to be replaced is not in the bridgetable
                let random_bridgeline = BridgeLine::random();
                assert!(
                    !th.ba
                        .bridge_table
                        .reachable
                        .contains_key(&random_bridgeline),
                    "Random bridgeline happens to be in the bridge_table (and should not be)"
                );
                assert!(
                    th.ba
                        .bridge_replace(&random_bridgeline, Some(random_bridgeline))
                        == ReplaceSuccess::NotFound,
                    "Bridge should be marked as NotFound"
                );
            }
            "available" => {
                // Case one: available_bridge != null
                let random_bridgeline = BridgeLine::random();
                let unallocated_bridgeline = &BridgeLine::random();
                th.ba
                    .bridge_table
                    .unallocated_bridges
                    .push(*unallocated_bridgeline);
                assert!(
                    th.ba
                        .bridge_table
                        .reachable
                        .get(&random_bridgeline)
                        .is_none(),
                    "Random bridge already in table"
                );
                assert!(
                    th.ba
                        .bridge_replace(replacement_bridge, Some(random_bridgeline))
                        == ReplaceSuccess::Replaced,
                    "Bridge was not replaced with available bridge"
                );
                assert!(
                    th.ba
                        .bridge_table
                        .reachable
                        .get(&random_bridgeline)
                        .is_some(),
                    "Replacement bridge not added to reachable bridges"
                );
                println!("Table Size {:?}", table_size);
                println!("Bucket length {:?}", th.ba.bridge_table.buckets.len() - 5);
                assert!(
                    table_size == th.ba.bridge_table.buckets.len() - 5,
                    "Number of buckets changed size"
                );
                assert!(
                    th.ba.bridge_table.unallocated_bridges.len() == 1,
                    "Extra bridge added to unallocated bridges"
                );
                println!("Successfully added passed bridgeline");
            }
            // Case two: available_bridge == null and unallocated_bridges !=null
            "unallocated" => {
                let unallocated_bridgeline = &BridgeLine::random();
                th.ba
                    .bridge_table
                    .unallocated_bridges
                    .push(*unallocated_bridgeline);
                assert!(
                    th.ba.bridge_table.unallocated_bridges.len() == 1,
                    "Not enough bridges in unallocated bridges"
                );
                assert!(
                    th.ba
                        .bridge_table
                        .reachable
                        .get(unallocated_bridgeline)
                        .is_none(),
                    "Unallocated bridge already marked as reachable"
                );
                assert!(
                    th.ba.bridge_replace(replacement_bridge, None) == ReplaceSuccess::Replaced,
                    "Bridge was not replaced with available bridge"
                );
                assert!(
                    th.ba
                        .bridge_table
                        .reachable
                        .get(unallocated_bridgeline)
                        .is_some(),
                    "Replacement bridge not added to reachable bridges"
                );
                assert!(
                    table_size == th.ba.bridge_table.buckets.len() - 5,
                    "Number of buckets changed size"
                );
                assert!(
                    th.ba.bridge_table.unallocated_bridges.is_empty(),
                    "Allocated bridge still in unallocated bridges"
                );

                println!("Successfully added unallocated bridgeline");
            }
            "use_spare" => {
                // Case three: available_bridge == null and unallocated_bridges == null
                assert!(
                    th.ba.bridge_table.unallocated_bridges.is_empty(),
                    "Unallocated bridges should have a length of 0"
                );
                assert!(
                    th.ba.bridge_replace(replacement_bridge, None) == ReplaceSuccess::Replaced,
                    "Bridge was not replaced with available spare bridge"
                );
                assert!(
                    th.ba
                        .bridge_table
                        .reachable
                        .get(replacement_bridge)
                        .is_none(),
                    "Replacement bridge still marked as reachable"
                );
                // Remove a spare bucket to replace bridge, buckets decrease by 1
                assert!(
                    (table_size - 1) == th.ba.bridge_table.buckets.len() - 5,
                    "Number of buckets changed size"
                );
                assert!(
                    th.ba.bridge_table.unallocated_bridges.len() == 2,
                    "Extra spare bridges not added to unallocated bridges"
                );

                println!("Successfully added bridgeline from spare");
            }
            "remove_spare" => {
                // Case three: available_bridge == null and unallocated_bridges == null
                assert!(
                    th.ba.bridge_table.unallocated_bridges.is_empty(),
                    "Unallocated bridges should have a length of 0"
                );
                assert!(
                    th.ba.bridge_replace(replacement_bridge, None) == ReplaceSuccess::Removed,
                    "Bridge was replaced with available spare, instead of being removed"
                );
                assert!(
                    th.ba.bridge_table.unallocated_bridges.len() == 2,
                    "Unallocated bridges should have a length of 2"
                );
                assert!(
                    th.ba
                        .bridge_table
                        .reachable
                        .get(replacement_bridge)
                        .is_none(),
                    "Replacement bridge still marked as reachable"
                );
                // Remove a spare bucket to replace bridge, buckets decrease by 1
                assert!(
                    (table_size - 1) == th.ba.bridge_table.buckets.len(),
                    "Number of buckets changed size"
                );
                assert!(
                    th.ba.bridge_table.unallocated_bridges.len() == 2,
                    "Extra spare bridges not added to unallocated bridges"
                );

                println!("Successfully removed a spare bridgeline marked to be replaced");
            }
            "failed" => {
                // Case four: available_bridge == None and unallocated_bridges == None and spare buckets == None
                assert!(
                    th.ba.bridge_table.unallocated_bridges.is_empty(),
                    "Unallocated bridges should have a length of 0"
                );
                assert!(
                    th.ba.bridge_replace(replacement_bridge, None) == ReplaceSuccess::NotReplaced,
                    "Bridge was somehow marked as replaced despite no replaceable bridges"
                );
                assert!(
                    th.ba
                        .bridge_table
                        .reachable
                        .get(replacement_bridge)
                        .is_some(),
                    "Replacement bridge marked as unreachable despite not being replaced"
                );
                assert!(
                    table_size == th.ba.bridge_table.buckets.len(),
                    "Number of buckets changed size"
                );
                assert!(
                    th.ba.bridge_table.unallocated_bridges.is_empty(),
                    "Unallocated bridges changed size"
                );
                println!("No bridges available to replace bridge so replacement gracefully failed");
            }
            _ => {}
        }
    }
}

#[test]
fn test_mark_unreachable() {
    let mut th = TestHarness::new();

    println!("spares = {:?}", th.ba.bridge_table.spares);
    println!("tmig = {:?}", th.ba.trustup_migration_table.table);
    println!("bmig = {:?}", th.ba.blockage_migration_table.table);
    println!("openinv = {:?}\n", th.bdb.openinv_buckets);

    // Mark a bridge in an untrusted bucket as unreachable
    let bucket6 = th.ba.bridge_table.buckets.get(&6u32).unwrap();
    let b6 = bucket6[0];
    th.ba.bridge_blocked(&b6, &mut th.bdb);

    println!("spares = {:?}", th.ba.bridge_table.spares);
    println!("tmig = {:?}", th.ba.trustup_migration_table.table);
    println!("bmig = {:?}", th.ba.blockage_migration_table.table);
    println!("openinv = {:?}\n", th.bdb.openinv_buckets);

    // Mark another bridge grouped to the same trusted bucket as
    // unreachable
    let bucket7 = th.ba.bridge_table.buckets.get(&7u32).unwrap();
    let b7 = bucket7[0];
    th.ba.bridge_blocked(&b7, &mut th.bdb);

    println!("spares = {:?}", th.ba.bridge_table.spares);
    println!("tmig = {:?}", th.ba.trustup_migration_table.table);
    println!("bmig = {:?}", th.ba.blockage_migration_table.table);
    println!("openinv = {:?}\n", th.bdb.openinv_buckets);

    // That will have introduced a blockage migration.  Get the target
    let target: u32 = *th
        .ba
        .blockage_migration_table
        .table
        .iter()
        .next()
        .unwrap()
        .1;

    // Block two of the bridges in that target bucket
    let bucket1 = th.ba.bridge_table.buckets.get(&target).unwrap();
    let bt1 = bucket1[1];
    let bucket2 = th.ba.bridge_table.buckets.get(&target).unwrap();
    let bt2 = bucket2[2];
    th.ba.bridge_blocked(&bt1, &mut th.bdb);
    th.ba.bridge_blocked(&bt2, &mut th.bdb);

    println!("spares = {:?}", th.ba.bridge_table.spares);
    println!("tmig = {:?}", th.ba.trustup_migration_table.table);
    println!("bmig = {:?}", th.ba.blockage_migration_table.table);
    println!("openinv = {:?}\n", th.bdb.openinv_buckets);
}

#[test]
fn test_blockage_migration() {
    let mut th = TestHarness::new();

    // Join an untrusted user
    let cred = th.open_invite().1 .0;

    // Time passes
    th.advance_days(47);

    // Go up to level 1
    let (_mperf_stat, migcred) = th.trust_promotion(&cred);
    let (_perf_stat, cred1) = th.level0_migration(&cred, &migcred);
    assert!(scalar_u32(&cred1.trust_level).unwrap() == 1);

    // Time passes
    th.advance_days(20);

    // Go up to level 2
    let (_two_perf_stat, cred2) = th.level_up(&cred1);
    assert!(scalar_u32(&cred2.trust_level).unwrap() == 2);
    println!("cred2 = {:?}", cred2);
    assert!(th.ba.verify_lox(&cred2));

    // Time passes
    th.advance_days(29);

    // Go up to level 3
    let (_three_perf_stat, cred3) = th.level_up(&cred2);
    assert!(scalar_u32(&cred3.trust_level).unwrap() == 3);
    println!("cred3 = {:?}", cred3);
    assert!(th.ba.verify_lox(&cred3));

    // Time passes
    th.advance_days(56);

    // Go up to level 4
    let (_four_perf_stat, cred4) = th.level_up(&cred3);
    assert!(scalar_u32(&cred4.trust_level).unwrap() == 4);
    println!("cred4 = {:?}", cred4);
    assert!(th.ba.verify_lox(&cred4));

    // Get our bridges
    let (id, key) = bridge_table::from_scalar(cred4.bucket).unwrap();
    let encbuckets = th.ba.enc_bridge_table();
    let bucket =
        bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap()).unwrap();
    // We should have a Bridge Reachability credential
    assert!(bucket.1.is_some());

    // Oh, no!  Two of our bridges are blocked!
    th.ba.bridge_blocked(&bucket.0[0], &mut th.bdb);
    th.ba.bridge_blocked(&bucket.0[2], &mut th.bdb);

    println!("spares = {:?}", th.ba.bridge_table.spares);
    println!("tmig = {:?}", th.ba.trustup_migration_table.table);
    println!("bmig = {:?}", th.ba.blockage_migration_table.table);
    println!("openinv = {:?}\n", th.bdb.openinv_buckets);

    // Time passes
    th.advance_days(1);
    let encbuckets2 = th.ba.enc_bridge_table();
    let bucket2 =
        bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets2.get(&id).unwrap()).unwrap();
    // We should no longer have a Bridge Reachability credential
    assert!(bucket2.1.is_none());

    // See about getting a Migration credential for the blockage
    let (_block_perf_stat, migration) = th.check_blockage(&cred4);

    println!("migration = {:?}", migration);

    // Migrate
    let (_five_perf_stat, cred5) = th.blockage_migration(&cred4, &migration);

    assert!(scalar_u32(&cred5.trust_level).unwrap() == 2);
    println!("cred5 = {:?}", cred5);
    assert!(th.ba.verify_lox(&cred5));

    // Time passes
    th.advance_days(29);

    // Go up to level 3
    let (_six_perf_stat, cred6) = th.level_up(&cred5);
    assert!(scalar_u32(&cred6.trust_level).unwrap() == 3);
    println!("cred6 = {:?}", cred6);
    assert!(th.ba.verify_lox(&cred6));

    // Get our bridges
    let (id, key) = bridge_table::from_scalar(cred6.bucket).unwrap();
    let encbuckets = th.ba.enc_bridge_table();
    let bucket =
        bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap()).unwrap();
    // We should have a Bridge Reachability credential
    assert!(bucket.1.is_some());

    // Oh, no!  Two of our bridges are blocked!
    th.ba.bridge_blocked(&bucket.0[1], &mut th.bdb);
    th.ba.bridge_blocked(&bucket.0[2], &mut th.bdb);

    println!("spares = {:?}", th.ba.bridge_table.spares);
    println!("tmig = {:?}", th.ba.trustup_migration_table.table);
    println!("bmig = {:?}", th.ba.blockage_migration_table.table);
    println!("openinv = {:?}\n", th.bdb.openinv_buckets);

    // Time passes
    th.advance_days(1);
    let encbuckets2 = th.ba.enc_bridge_table();
    let bucket2 =
        bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets2.get(&id).unwrap()).unwrap();
    // We should no longer have a Bridge Reachability credential
    assert!(bucket2.1.is_none());

    // See about getting a Migration credential for the blockage
    let (_block_perf_stat, migration) = th.check_blockage(&cred6);

    println!("migration = {:?}", migration);

    // Migrate
    let (_seven_perf_stat, cred7) = th.blockage_migration(&cred6, &migration);

    assert!(scalar_u32(&cred7.trust_level).unwrap() == 1);
    println!("cred7 = {:?}", cred7);
    assert!(th.ba.verify_lox(&cred7));
}

fn print_test_results(perf_stat: PerfStat) {
    println!("Request size = {:?} bytes", perf_stat.req_len);
    println!("Request time = {:?}", perf_stat.req_t);
    println!("Response size = {:?} bytes", perf_stat.resp_len);
    println!("Response time = {:?}", perf_stat.resp_t);
    println!("Response handle time = {:?}", perf_stat.resp_handle_t);
}
