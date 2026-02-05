use crate::lox_context::LoxServerContext;
use crate::metrics::Metrics;

use super::*;
use cmz::CMZPubkey;
use curve25519_dalek::ristretto::RistrettoPoint as G;
use lox_extensions::{bridge_table, BridgeAuth, BridgeDb};
use std::sync::{Arc, Mutex};

pub struct TestHarness {
    pub context: LoxServerContext,
}

impl TestHarness {
    pub fn new() -> Self {
        let rng = &mut rand::thread_rng();
        let mut bridgedb = BridgeDb::new();
        let mut lox_auth = BridgeAuth::new(bridgedb.pubkey, rng);

        // Make 3 x num_buckets open invitation bridges, in sets of 3
        for _ in 0..5 {
            let bucket = [
                lox_utils::random(),
                lox_utils::random(),
                lox_utils::random(),
            ];
            let _ = lox_auth.add_openinv_bridges(bucket, &mut bridgedb);
        }

        // Add hot_spare more hot spare buckets
        for _ in 0..5 {
            let bucket = [
                lox_utils::random(),
                lox_utils::random(),
                lox_utils::random(),
            ];
            let _ = lox_auth.add_spare_bucket(bucket, &mut bridgedb);
        }
        // Create the encrypted bridge table
        lox_auth.enc_bridge_table();
        let context = lox_context::LoxServerContext {
            db: Arc::new(Mutex::new(bridgedb)),
            ba: Arc::new(Mutex::new(lox_auth)),
            extra_bridges: Arc::new(Mutex::new(Vec::new())),
            metrics: Metrics::default(),
        };
        Self { context }
    }

    pub fn advance_days(&mut self, days: u16) {
        // For testing only: manually advance the day by the given number
        // of days.
        let mut ba_obj = self.context.ba.lock().unwrap();
        ba_obj.advance_days(days); // FOR TESTING ONLY
        println!("Today's date according to server: {}", ba_obj.today());
    }

    pub fn rotate_lox_keys(&mut self) {
        let rng = &mut rand::thread_rng();
        self.context.ba.lock().unwrap().rotate_lox_keys(rng);
    }

    pub fn rotate_invitation_keys(&mut self) {
        let rng = &mut rand::thread_rng();
        self.context.ba.lock().unwrap().rotate_invitation_keys(rng);
    }

    pub fn simulate_blocking(
        &mut self,
        cred: lox_extensions::lox_creds::Lox,
        reach_pub: CMZPubkey<G>,
    ) -> (u32, [u8; 16]) {
        let (id, key) = bridge_table::from_scalar(cred.bucket.unwrap()).unwrap();
        let mut bdb = self.context.db.lock().unwrap();
        let mut lox_auth = self.context.ba.lock().unwrap();
        let encbucket = lox_auth.enc_bridge_table().get(&id).unwrap();
        let bucket =
            bridge_table::BridgeTable::decrypt_bucket(id, &key, encbucket, &reach_pub).unwrap();
        assert!(bucket.1.is_some());
        // Block two of our bridges
        lox_auth.bridge_blocked(&bucket.0[0], &mut bdb);
        lox_auth.bridge_blocked(&bucket.0[2], &mut bdb);

        (id, key)
    }

    pub fn prep_next_day(&mut self, id: u32, key: [u8; 16], reach_pub: CMZPubkey<G>) {
        let mut lox_auth = self.context.ba.lock().unwrap();
        let encbuckets2 = lox_auth.enc_bridge_table();
        let bucket2 = bridge_table::BridgeTable::decrypt_bucket(
            id,
            &key,
            encbuckets2.get(&id).unwrap(),
            &reach_pub,
        )
        .unwrap();
        // We should no longer have a Bridge Reachability credential
        assert!(bucket2.1.is_none());
    }
}
