use bytes::Bytes;
#[cfg(feature = "test-branch")]
use http_body_util::Empty;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    header::{HeaderValue, ACCEPT},
    Response,
};
use lox_extensions::{
    bridge_table::{BridgeLine, EncryptedBucket, MAX_BRIDGES_PER_BUCKET},
    migration_table::EncMigrationTable,
    proto::{
        blockage_migration, check_blockage, errors::CredentialError, issue_invite, level_up,
        migration, open_invite, redeem_invite, trust_promotion, update_cred, update_invite,
    },
    BridgeAuth, BridgeDb, OpenInvitationError,
};

use rdsys_backend::proto::{Resource, ResourceState};
use serde::{Deserialize, Serialize};

use cmz::CMZPubkey;
use curve25519_dalek::ristretto::RistrettoPoint as G;
use serde_json::json;
use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use crate::metrics::Metrics;
use crate::resource_parser::{parse_into_bridgelines, sort_for_parsing};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoxServerContext {
    pub db: Arc<Mutex<BridgeDb>>,
    pub ba: Arc<Mutex<BridgeAuth>>,
    pub extra_bridges: Arc<Mutex<Vec<BridgeLine>>>,

    #[serde(skip)]
    pub metrics: Metrics,
}

impl LoxServerContext {
    pub fn bridgetable_is_empty(&self) -> bool {
        self.ba.lock().unwrap().is_empty()
    }

    // Populate an empty bridgetable for the first time
    pub fn populate_bridgetable(
        &self,
        buckets: Vec<[BridgeLine; MAX_BRIDGES_PER_BUCKET]>,
        percent_spares: i32,
    ) {
        let mut partition: i32 = 0;
        if percent_spares != 0 {
            partition = buckets.len() as i32 * percent_spares / 100;
        }
        let (spares, open_invitations) = buckets.split_at(partition as usize);
        for bucket in spares {
            self.add_spare_bucket(*bucket)
        }

        for bucket in open_invitations {
            self.add_openinv_bucket(*bucket)
        }
    }

    pub fn handle_working_resources(
        &self,
        watched_blockages: Vec<String>,
        working_resources: Vec<Resource>,
    ) -> Vec<u64> {
        let mut accounted_for_bridges: Vec<u64> = Vec::new();
        let (bridgelines, blocked_bridgelines) =
            parse_into_bridgelines(watched_blockages, working_resources);
        for bridge in blocked_bridgelines {
            let res = self.mark_blocked(bridge);
            if res {
                println!(
                    "BridgeLine {:?} successfully marked unreachable",
                    bridge.uid_fingerprint
                );
                self.metrics.blocked_bridges.inc();
            } else {
                println!(
                    "BridgeLine {:?} NOT marked unreachable, not found in bridgetable!",
                    bridge.uid_fingerprint
                );
            }
        }
        for bridge in bridgelines {
            let res = self.update_bridge(bridge);
            if res {
                println!(
                    "BridgeLine {:?} successfully updated.",
                    bridge.uid_fingerprint
                );
                accounted_for_bridges.push(bridge.uid_fingerprint);
                self.metrics.existing_or_updated_bridges.inc();
                // Assume non-failing bridges that are not found in the bridge table are new bridges and save them for later
            } else {
                println!("BridgeLine: {:?} not found in Lox's Bridgetable. Save it as a new resource for now!", bridge.uid_fingerprint);
                self.append_extra_bridges(bridge);
                self.metrics.new_bridges.inc();
            }
        }

        accounted_for_bridges
    }

    // When syncing resources with rdsys, handle the non-working resources
    // Those that are blocked in the target region are marked as unreachable/blocked
    // All others are matched by fingerprint and if they are still in the grace period, they are updated
    // otherwise they are replaced with new bridges
    pub fn handle_not_working_resources(
        &self,
        watched_blockages: Vec<String>,
        not_working_resources: Vec<Resource>,
        mut accounted_for_bridges: Vec<u64>,
    ) -> Vec<u64> {
        let (grace_period, failing, blocked) =
            sort_for_parsing(watched_blockages, not_working_resources);
        for bridge in blocked {
            let res = self.mark_blocked(bridge);
            if res {
                println!(
                    "Blocked BridgeLine {:?} successfully marked unreachable",
                    bridge.uid_fingerprint
                );
                self.metrics.blocked_bridges.inc();
            } else {
                println!(
                    "Blocked BridgeLine {:?} NOT marked unreachable, not found in bridgetable!",
                    bridge.uid_fingerprint
                );
            }
        }
        // Update bridges in the bridge table that are failing but within the grace period
        for bridge in grace_period {
            let res = self.update_bridge(bridge);
            if res {
                println!(
                    "Grace period BridgeLine {:?} successfully updated.",
                    bridge.uid_fingerprint
                );
                accounted_for_bridges.push(bridge.uid_fingerprint);
                self.metrics.existing_or_updated_bridges.inc();
            } else {
                println!("Grace period BridgeLine: {:?} not found in Lox's Bridgetable. Wait until it is working to update/add it!", bridge.uid_fingerprint);
            }
        }
        // Next, handle the failing bridges. If resource last passed tests >= ACCEPTED_HOURS_OF_FAILURE ago,
        // it should be replaced with a working resource and be removed from the bridgetable.
        for bridge in failing {
            match self.replace_with_new(bridge) {
                lox_extensions::ReplaceSuccess::Replaced => {
                    println!(
                        "Failing BridgeLine {:?} successfully replaced.",
                        bridge.uid_fingerprint
                    );
                    accounted_for_bridges.push(bridge.uid_fingerprint);
                    self.metrics.removed_bridges.inc();
                }
                lox_extensions::ReplaceSuccess::NotReplaced => {
                    // Add the bridge to the list of to_be_replaced bridges in the Lox context and try
                    // again to replace at the next update (nothing changes in the Lox Authority)
                    println!(
                        "Failing BridgeLine {:?} NOT replaced, saved for next update!",
                        bridge.uid_fingerprint
                    );
                    self.metrics.existing_or_updated_bridges.inc();
                    accounted_for_bridges.push(bridge.uid_fingerprint);
                }
                lox_extensions::ReplaceSuccess::Removed => {
                    println!(
                        "Failing BridgeLine {:?} successfully removed.",
                        bridge.uid_fingerprint
                    );
                    accounted_for_bridges.push(bridge.uid_fingerprint);
                    self.metrics.removed_bridges.inc();
                }
                lox_extensions::ReplaceSuccess::NotFound => println!(
                    "Failing BridgeLine {:?} not found in bridge table.",
                    bridge.uid_fingerprint
                ),
            }
        }
        accounted_for_bridges
    }

    // Sync resources received from rdsys with the Lox bridgetable
    pub fn sync_with_bridgetable(
        &self,
        watched_blockages: Vec<String>,
        percent_spares: i32,
        resources: ResourceState,
    ) {
        // Check if each resource is already in the Lox bridgetable. If it is, it's probably fine
        // to replace the existing resource with the incoming one to account for changes
        // save a list of accounted for bridges and deal with the unaccounted for bridges at the end
        let mut accounted_for_bridges: Vec<u64> = Vec::new();
        // ensure all working resources are updated and accounted for
        if let Some(working_resources) = resources.working {
            accounted_for_bridges =
                self.handle_working_resources(watched_blockages.clone(), working_resources);
        }
        if let Some(not_working_resources) = resources.not_working {
            accounted_for_bridges = self.handle_not_working_resources(
                watched_blockages,
                not_working_resources,
                accounted_for_bridges,
            );
        }

        let unaccounted_for = self
            .ba
            .lock()
            .unwrap()
            .find_and_remove_unaccounted_for_bridges(accounted_for_bridges);
        for bridgeline in unaccounted_for {
            match self.replace_with_new(bridgeline) {
                lox_extensions::ReplaceSuccess::Replaced => {
                    println!(
                        "BridgeLine {:?} not found in rdsys update was successfully replaced.",
                        bridgeline.uid_fingerprint
                    );
                    self.metrics.removed_bridges.inc();
                }
                lox_extensions::ReplaceSuccess::Removed => {
                    println!("BridgeLine {:?} not found in rdsys update was not distributed to a bucket so was removed", bridgeline.uid_fingerprint);
                    self.metrics.removed_bridges.inc();
                }
                lox_extensions::ReplaceSuccess::NotReplaced => {
                    // Try again to replace at the next update (nothing changes in the Lox Authority)
                    println!("BridgeLine {:?} not found in rdsys update NOT replaced, saved for next update!",
                            bridgeline.uid_fingerprint);
                    self.metrics.existing_or_updated_bridges.inc();
                }
                lox_extensions::ReplaceSuccess::NotFound => println!(
                    "BridgeLine {:?} no longer in reachable bridges.",
                    bridgeline.uid_fingerprint
                ),
            }
        }
        // Finally, assign any extra_bridges to new buckets if there are enough
        while self.extra_bridges.lock().unwrap().len() >= MAX_BRIDGES_PER_BUCKET {
            let bucket = self.remove_extra_bridges();
            // TODO: Decide the circumstances under which a bridge is allocated to an open_inv or spare bucket,
            // eventually also do some more fancy grouping of new resources, i.e., by type or region
            let mut db_obj = self.db.lock().unwrap();
            // check number of available open invitation buckets
            let open_inv_num = self.ba.lock().unwrap().openinv_length(&mut db_obj);
            // check number of spares
            let spares_num = self.ba.lock().unwrap().spares_length();

            if open_inv_num != 0 && (spares_num / open_inv_num * 100) < percent_spares as usize {
                match self
                    .ba
                    .lock()
                    .unwrap()
                    .add_spare_bucket(bucket, &mut db_obj)
                {
                    Ok(_) => (),
                    Err(e) => {
                        println!("Error: {e:?}");
                        for bridge in bucket {
                            self.append_extra_bridges(bridge);
                        }
                    }
                }
            } else {
                match self
                    .ba
                    .lock()
                    .unwrap()
                    .add_openinv_bridges(bucket, &mut db_obj)
                {
                    Ok(_) => (),
                    Err(e) => {
                        println!("Error: {e:?}");
                        for bridge in bucket {
                            self.append_extra_bridges(bridge);
                        }
                    }
                }
            }
        }

        // Regenerate tables for verifying TP reports
        //  self.generate_tp_bridge_infos();

        // Any remaining extra bridges should be cleared from the Lox Context after each sync
        // Currently bridgetable updating behaviour does not occur without receiving a resource list
        // from rdsys so if the extra bridge is still working, it can be added to the table later
        self.extra_bridges.lock().unwrap().clear();
    }

    pub fn append_extra_bridges(&self, bridge: BridgeLine) {
        let mut extra_bridges = self.extra_bridges.lock().unwrap();
        extra_bridges.push(bridge);
    }

    pub fn remove_extra_bridges(&self) -> [BridgeLine; MAX_BRIDGES_PER_BUCKET] {
        let mut extra_bridges = self.extra_bridges.lock().unwrap();
        let mut return_bridges = [BridgeLine::default(); MAX_BRIDGES_PER_BUCKET];
        for bridge in return_bridges.iter_mut() {
            if let Some(extra) = extra_bridges.pop() {
                *bridge = extra
            }
        }
        return_bridges
    }

    // Add extra_bridges to the Lox bridge table as open invitation bridges
    // TODO: Add some consideration for whether or not bridges should be sorted as
    // open invitation buckets or hot spare buckets
    pub fn allocate_leftover_bridges(&self) {
        let mut ba_obj = self.ba.lock().unwrap();
        let mut db_obj = self.db.lock().unwrap();
        let mut extra_bridges = self.extra_bridges.lock().unwrap();
        ba_obj.allocate_bridges(&mut extra_bridges, &mut db_obj);
    }

    // Add an open invitation bucket to the Lox db
    pub fn add_openinv_bucket(&self, bucket: [BridgeLine; 3]) {
        let mut ba_obj = self.ba.lock().unwrap();
        let mut db_obj = self.db.lock().unwrap();
        match ba_obj.add_openinv_bridges(bucket, &mut db_obj) {
            Ok(_) => (),
            Err(e) => {
                println!("Error: {e:?}");
                for bridge in bucket {
                    self.append_extra_bridges(bridge);
                }
            }
        }
    }

    // Add a hot spare bucket to the Lox db
    pub fn add_spare_bucket(&self, bucket: [BridgeLine; 3]) {
        let mut ba_obj = self.ba.lock().unwrap();
        let mut db_obj = self.db.lock().unwrap();
        match ba_obj.add_spare_bucket(bucket, &mut db_obj) {
            Ok(_) => (),
            Err(e) => {
                println!("Error: {e:?}");
                for bridge in bucket {
                    self.append_extra_bridges(bridge);
                }
            }
        }
    }

    // Attempt to remove a bridge that is failing tests and replace it with a bridge from the
    // available bridges or from a spare bucket
    pub fn replace_with_new(&self, bridgeline: BridgeLine) -> lox_extensions::ReplaceSuccess {
        let mut ba_obj = self.ba.lock().unwrap();
        let mut eb_obj = self.extra_bridges.lock().unwrap();
        let available_bridge = eb_obj.pop();
        let result = ba_obj.bridge_replace(&bridgeline, available_bridge);
        if result != lox_extensions::ReplaceSuccess::Replaced {
            if let Some(bridge) = available_bridge {
                // If available bridge wasn't removed, return it
                eb_obj.push(bridge);
            }
        }
        result
    }

    pub fn mark_blocked(&self, bridgeline: BridgeLine) -> bool {
        let mut ba_obj = self.ba.lock().unwrap();
        let mut db_obj = self.db.lock().unwrap();
        ba_obj.bridge_blocked(&bridgeline, &mut db_obj)
    }

    // Find the bridgeline in the Lox bridge table that matches the fingerprint
    // of the bridgeline passed by argument. Once found, replace it with the bridgeline
    // passed by argument to ensure all fields besides the fingerprint are updated
    // appropriately.
    pub fn update_bridge(&self, bridgeline: BridgeLine) -> bool {
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.bridge_update(&bridgeline)
    }

    #[cfg(any(test, feature = "test-branch"))]
    /// For testing only: manually advance the day by the given number
    /// of days.
    pub fn advance_days_test(&self, num: u16) {
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.advance_days(num); // FOR TESTING ONLY
        println!("Today's date according to server: {}", ba_obj.today());
        // Also advance days for BridgeDb
        let mut db_obj = self.db.lock().unwrap();
        db_obj.advance_days(num); // FOR TESTING ONLY
    }

    #[cfg(any(test, feature = "test-branch"))]
    /// For testing only: rotate lox keys
    pub fn rotate_lox_keys(&self) -> Response<BoxBody<Bytes, Infallible>> {
        let rng = &mut rand::thread_rng();
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.rotate_lox_keys(rng); // FOR TESTING ONLY
        println!("Rotated lox cred keys");
        let jstr = serde_json::to_string(&json!({"response": "ok".to_string()})).unwrap();
        prepare_header(jstr)
    }
    #[cfg(any(test, feature = "test-branch"))]
    /// For testing only: rotate lox keys
    pub fn rotate_invite_keys(&self) -> Response<BoxBody<Bytes, Infallible>> {
        let rng = &mut rand::thread_rng();
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.rotate_invitation_keys(rng); // FOR TESTING ONLY
        println!("Rotated invite cred keys");
        let jstr = serde_json::to_string(&json!({"response": "ok".to_string()})).unwrap();
        prepare_header(jstr)
    }

    // Encrypts the Lox bridge table, should be called after every sync
    pub fn encrypt_table(&self) -> HashMap<u32, EncryptedBucket> {
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.enc_bridge_table().clone()
    }

    // Returns a vector of the Lox Authority's public keys
    fn pubkeys(&self) -> Vec<CMZPubkey<G>> {
        let ba_obj = self.ba.lock().unwrap();
        // vector of public keys (to serialize)
        vec![
            ba_obj.lox_pub.clone(),
            ba_obj.migration_pub.clone(),
            ba_obj.migrationkey_pub.clone(),
            ba_obj.reachability_pub.clone(),
            ba_obj.invitation_pub.clone(),
        ]
    }

    // Generates a Lox invitation if fewer than MAX_BRIDGES_PER_DAY have been
    // requested on a given day
    fn gen_invite(&self) -> Result<lox_utils::Invite, OpenInvitationError> {
        let mut obj = self.db.lock().unwrap();
        match obj.invite() {
            Ok(invite) => {
                if obj.current_k == 1 {
                    self.metrics.k_reset_count.inc();
                }
                Ok(lox_utils::Invite { invite })
            }
            Err(e) => Err(e),
        }
    }

    // Returns a valid open_invite::Response if the open_invite::Request is valid
    fn open_inv(
        &self,
        req: open_invite::open_invitation::Request,
        invite: lox_utils::Invite,
    ) -> Result<(open_invite::open_invitation::Reply, BridgeLine), CredentialError> {
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.open_invitation(req, &invite.invite)
    }

    // Returns a valid trust_promotion:: Response if the trust_promotion::Request is valid
    fn trust_promo(
        &self,
        req: trust_promotion::trust_promotion::Request,
    ) -> Result<(trust_promotion::trust_promotion::Reply, EncMigrationTable), CredentialError> {
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.handle_trust_promotion(req)
    }

    // Returns a valid trust_migration::Response if the trust_migration::Request is valid
    fn trust_migration(
        &self,
        req: migration::migration::Request,
    ) -> Result<migration::migration::Reply, CredentialError> {
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.handle_migration(req)
    }

    // Returns a valid level_up:: Response if the level_up::Request is valid
    fn level_up(
        &self,
        req: level_up::level_up::Request,
    ) -> Result<level_up::level_up::Reply, CredentialError> {
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.handle_level_up(req)
    }

    // Returns a valid issue_invite::Response if the issue_invite::Request is valid
    fn issue_invite(
        &self,
        req: issue_invite::issue_invite::Request,
    ) -> Result<issue_invite::issue_invite::Reply, CredentialError> {
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.handle_issue_invite(req)
    }

    // Returns a valid redeem_invite::Response if the redeem_invite::Request is valid
    fn redeem_invite(
        &self,
        req: redeem_invite::redeem_invite::Request,
    ) -> Result<redeem_invite::redeem_invite::Reply, CredentialError> {
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.handle_redeem_invite(req)
    }

    // Returns a valid check_blockage::Response if the check_blockage::Request is valid
    fn check_blockage(
        &self,
        req: check_blockage::check_blockage::Request,
    ) -> Result<(check_blockage::check_blockage::Reply, EncMigrationTable), CredentialError> {
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.handle_check_blockage(req)
    }

    // Returns a valid blockage_migration::Response if the blockage_migration::Request is valid
    fn blockage_migration(
        &self,
        req: blockage_migration::blockage_migration::Request,
    ) -> Result<blockage_migration::blockage_migration::Reply, CredentialError> {
        let mut ba_obj = self.ba.lock().unwrap();
        ba_obj.handle_blockage_migration(req)
    }

    // Generate and return an open invitation token as an HTTP response
    pub fn generate_invite(self) -> Response<BoxBody<Bytes, Infallible>> {
        self.metrics.invites_requested.inc();
        let invite = self.gen_invite();
        match invite {
            Ok(invite) => match serde_json::to_string(&invite) {
                Ok(resp) => prepare_header(resp),
                Err(e) => {
                    println!("Error parsing Invite to JSON");
                    let response = json!({"error": e.to_string()});
                    let val = serde_json::to_string(&response).unwrap();
                    prepare_header(val)
                }
            },
            Err(e) => {
                println!("Error generating open invitation");
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    fn update_cred(
        &self,
        old_key: CMZPubkey<G>,
        req: update_cred::update_cred::Request,
    ) -> Result<update_cred::update_cred::Reply, CredentialError> {
        self.ba.lock().unwrap().handle_update_cred(old_key, req)
    }

    fn update_invite(
        &self,
        old_key: CMZPubkey<G>,
        req: update_invite::update_invite::Request,
    ) -> Result<update_invite::update_invite::Reply, CredentialError> {
        self.ba.lock().unwrap().handle_update_invite(old_key, req)
    }

    // Return the serialized encrypted bridge table as an HTTP response
    pub fn send_reachability_cred(self) -> Response<BoxBody<Bytes, Infallible>> {
        let enc_table = self.encrypt_table();
        let etable = lox_utils::EncBridgeTable { etable: enc_table };
        match serde_json::to_string(&etable) {
            Ok(resp) => prepare_header(resp),
            Err(e) => {
                println!("Error parsing encrypted bridgetable to JSON");
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    // Return the serialized pubkeys for the Bridge Authority as an HTTP response
    pub fn send_keys(self) -> Response<BoxBody<Bytes, Infallible>> {
        let pubkeys = self.pubkeys();
        match serde_json::to_string(&pubkeys) {
            Ok(resp) => prepare_header(resp),
            Err(e) => {
                println!("Error parsing Pubkeys to JSON");
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    // Return the serialized pubkeys for the Bridge Authority as an HTTP response
    pub fn send_constants(self) -> Response<BoxBody<Bytes, Infallible>> {
        let constants = lox_utils::LOX_SYSTEM_INFO;
        match serde_json::to_string(&constants) {
            Ok(resp) => prepare_header(resp),
            Err(e) => {
                println!("Error parsing Constants to JSON");
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    // Verify the open invitation request and return the result as an HTTP response
    pub fn verify_and_send_open_cred(self, request: Bytes) -> Response<BoxBody<Bytes, Infallible>> {
        let req: lox_utils::OpenInvReq = match serde_json::from_slice(&request) {
            Ok(req) => req,
            Err(e) => {
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                return prepare_header(val);
            }
        };
        match self.open_inv(req.request, req.invite) {
            Ok(resp) => {
                let response = serde_json::to_string(&resp).unwrap();
                self.metrics.open_inv_count.inc();
                prepare_header(response)
            }
            Err(e) => {
                println!("Invalid Open Invitation request, Proof Error");
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    // Verify the trust promotion request and return the result as an HTTP response
    pub fn verify_and_send_trust_promo(
        self,
        request: Bytes,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let req: trust_promotion::trust_promotion::Request = match serde_json::from_slice(&request)
        {
            Ok(req) => req,
            Err(e) => {
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                return prepare_header(val);
            }
        };
        match self.trust_promo(req) {
            Ok(resp) => {
                let response = serde_json::to_string(&resp).unwrap();
                self.metrics.trust_promo_count.inc();
                prepare_header(response)
            }
            Err(e) => {
                println!("Invalid Trust Promotion request, Proof Error: {:?}", e);
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    // Verify the trust migration request and return the result as an HTTP response
    pub fn verify_and_send_trust_migration(
        self,
        request: Bytes,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let req: migration::migration::Request = match serde_json::from_slice(&request) {
            Ok(req) => req,
            Err(e) => {
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                return prepare_header(val);
            }
        };
        match self.trust_migration(req) {
            Ok(resp) => {
                let response = serde_json::to_string(&resp).unwrap();
                self.metrics.trust_mig_count.inc();
                prepare_header(response)
            }
            Err(e) => {
                println!("Invalid Trust Migration request, Proof Error: {:?}", e);
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    // Verify the level up request and return the result as an HTTP response
    pub fn verify_and_send_level_up(self, request: Bytes) -> Response<BoxBody<Bytes, Infallible>> {
        let req: level_up::level_up::Request = match serde_json::from_slice(&request) {
            Ok(req) => req,
            Err(e) => {
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                return prepare_header(val);
            }
        };
        match self.level_up(req) {
            Ok(resp) => {
                let response = serde_json::to_string(&resp).unwrap();
                self.metrics.level_up_count.inc();
                prepare_header(response)
            }
            Err(e) => {
                println!("Invalid Level up request, Proof Error: {}", e);
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    // Verify the open invitation request and return the result as an HTTP response
    pub fn verify_and_send_issue_invite(
        self,
        request: Bytes,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let req: issue_invite::issue_invite::Request = match serde_json::from_slice(&request) {
            Ok(req) => req,
            Err(e) => {
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                return prepare_header(val);
            }
        };
        match self.issue_invite(req) {
            Ok(resp) => {
                let response = serde_json::to_string(&resp).unwrap();
                self.metrics.issue_invite_count.inc();
                prepare_header(response)
            }
            Err(e) => {
                println!("Invalid Issue invite request, Proof Error: {:?}", e);
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    // Verify the redeem invite request and return the result as an HTTP response
    pub fn verify_and_send_redeem_invite(
        self,
        request: Bytes,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let req: redeem_invite::redeem_invite::Request = match serde_json::from_slice(&request) {
            Ok(req) => req,
            Err(e) => {
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                return prepare_header(val);
            }
        };
        match self.redeem_invite(req) {
            Ok(resp) => {
                let response = serde_json::to_string(&resp).unwrap();
                self.metrics.redeem_invite_count.inc();
                prepare_header(response)
            }
            Err(e) => {
                println!("Invalid Redeem Invite request, Proof Error: {:?}", e);
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    // Verify the check blockage request and return the result as an HTTP response
    pub fn verify_and_send_check_blockage(
        self,
        request: Bytes,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let req: check_blockage::check_blockage::Request = match serde_json::from_slice(&request) {
            Ok(req) => req,
            Err(e) => {
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                return prepare_header(val);
            }
        };
        match self.check_blockage(req) {
            Ok(resp) => {
                let response = serde_json::to_string(&resp).unwrap();
                self.metrics.check_blockage_count.inc();
                prepare_header(response)
            }
            Err(e) => {
                println!("Invalid Check blockage request, Proof Error:{:?}", e);
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    // Verify the blockage migration request and return the result as an HTTP response
    pub fn verify_and_send_blockage_migration(
        self,
        request: Bytes,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let req: blockage_migration::blockage_migration::Request =
            match serde_json::from_slice(&request) {
                Ok(req) => req,
                Err(e) => {
                    let response = json!({"error": e.to_string()});
                    let val = serde_json::to_string(&response).unwrap();
                    return prepare_header(val);
                }
            };
        match self.blockage_migration(req) {
            Ok(resp) => {
                let response = serde_json::to_string(&resp).unwrap();
                self.metrics.blockage_migration_count.inc();
                prepare_header(response)
            }
            Err(e) => {
                println!("Invalid Blockage Migration request, Proof Error: {:?}", e);
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    pub fn verify_and_send_update_cred(
        &self,
        request: Bytes,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let req: lox_utils::UpdateCredReq = match serde_json::from_slice(&request) {
            Ok(req) => req,
            Err(e) => {
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                return prepare_header(val);
            }
        };
        match self.update_cred(req.old_key, req.request) {
            Ok(resp) => {
                let response = serde_json::to_string(&resp).unwrap();
                self.metrics.update_cred_count.inc();
                prepare_header(response)
            }
            Err(e) => {
                println!("Invalid Update Credential request, Proof Error: {:?}", e);
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    pub(crate) fn verify_and_send_update_invite(
        &self,
        request: Bytes,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let req: lox_utils::UpdateInviteReq = match serde_json::from_slice(&request) {
            Ok(req) => req,
            Err(e) => {
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                return prepare_header(val);
            }
        };
        match self.update_invite(req.old_key, req.request) {
            Ok(resp) => {
                let response = serde_json::to_string(&resp).unwrap();
                self.metrics.update_invite_count.inc();
                prepare_header(response)
            }
            Err(e) => {
                println!("Invalid Update Invite request, Proof Error: {:?}", e);
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                prepare_header(val)
            }
        }
    }

    #[allow(dead_code)]
    #[cfg(any(test, feature = "test-branch"))]
    fn today(&self) -> u32 {
        self.ba.lock().unwrap().today()
    }

    #[allow(dead_code)]
    #[cfg(any(test, feature = "test-branch"))]
    fn send_today(self) -> Response<BoxBody<Bytes, Infallible>> {
        let today = self.today();
        prepare_header(serde_json::to_string(&today).unwrap())
    }

    #[cfg(any(test, feature = "test-branch"))]
    /// For testing only: manually advance the day by the given number
    /// of days and send back the current day.
    pub fn advance_days_with_response_test(
        self,
        request: Bytes,
    ) -> Response<BoxBody<Bytes, Infallible>> {
        let req: u16 = match serde_json::from_slice(&request) {
            Ok(req) => req,
            Err(e) => {
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                return prepare_header(val);
            }
        };
        self.advance_days_test(req);
        self.send_today()
    }

    #[cfg(feature = "test-branch")]
    /// For testing only: manually advance the day by the given number
    /// of days and send back the current day.
    pub fn block_bridges_test(self, request: Bytes) -> Response<BoxBody<Bytes, Infallible>> {
        let req: BridgeLine = match serde_json::from_slice(&request) {
            Ok(req) => req,
            Err(e) => {
                let response = json!({"error": e.to_string()});
                let val = serde_json::to_string(&response).unwrap();
                return prepare_header(val);
            }
        };
        self.mark_blocked(req);
        let builder = Response::builder()
            .header("Access-Control-Allow-Origin", HeaderValue::from_static("*"))
            .status(200);
        builder.body(empty()).unwrap()
    }
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, Infallible> {
    Full::new(chunk.into()).boxed()
}

#[cfg(feature = "test-branch")]
fn empty() -> BoxBody<Bytes, Infallible> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

// Prepare HTTP Response for successful Server Request
fn prepare_header(response: String) -> Response<BoxBody<Bytes, Infallible>> {
    let mut resp = Response::new(full(response));
    resp.headers_mut()
        .insert(ACCEPT, "application/json".parse().unwrap());
    resp.headers_mut()
        .insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
    resp
}

#[cfg(test)]
mod tests {
    use crate::{fake_resource_state::TestResourceState, metrics::Metrics, BridgeConfig};
    use lox_extensions::{bridge_table::MAX_BRIDGES_PER_BUCKET, BridgeAuth, BridgeDb};
    use std::{
        env, fs,
        sync::{Arc, Mutex},
    };

    use super::LoxServerContext;

    struct TestHarness {
        context: LoxServerContext,
    }

    impl TestHarness {
        fn new() -> Self {
            let bridgedb = BridgeDb::new();
            let rng = &mut rand::thread_rng();
            let mut lox_auth = BridgeAuth::new(bridgedb.pubkey, rng);
            lox_auth.enc_bridge_table();
            let context = LoxServerContext {
                db: Arc::new(Mutex::new(bridgedb)),
                ba: Arc::new(Mutex::new(lox_auth)),
                extra_bridges: Arc::new(Mutex::new(Vec::new())),
                metrics: Metrics::default(),
            };
            Self { context }
        }

        fn new_with_bridges() -> Self {
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
            let context = LoxServerContext {
                db: Arc::new(Mutex::new(bridgedb)),
                ba: Arc::new(Mutex::new(lox_auth)),
                extra_bridges: Arc::new(Mutex::new(Vec::new())),
                metrics: Metrics::default(),
            };
            Self { context }
        }
    }

    fn get_config() -> BridgeConfig {
        env::set_var("BRIDGE_CONFIG_PATH", "bridge_config.json");
        let path = env::var("BRIDGE_CONFIG_PATH").unwrap();
        let config_file = fs::File::open(&path).unwrap();
        serde_json::from_reader(config_file).unwrap()
    }

    #[test]
    fn test_sync_with_bridgetable_only_working_resources() {
        let bridge_config = get_config();
        // Add bridges to empty bridge table and update with changed bridge state
        let th = TestHarness::new();
        let mut rs = TestResourceState::default();
        for _ in 0..5 {
            rs.add_working_resource();
        }
        assert_ne!(rs.rstate.working, None);
        assert_eq!(rs.rstate.not_working, None);

        th.context.sync_with_bridgetable(
            bridge_config.watched_blockages,
            bridge_config.percent_spares,
            rs.rstate.clone(),
        );
        let mut reachable_expected_length = rs.rstate.clone().working.unwrap().len();
        let expected_extra_bridges = reachable_expected_length % MAX_BRIDGES_PER_BUCKET;
        if expected_extra_bridges != 0 {
            reachable_expected_length = reachable_expected_length - expected_extra_bridges;
        }
        assert_eq!(
            th.context.ba.lock().unwrap().reachable_length(),
            reachable_expected_length,
            "Unexpected number of reachable bridges"
        );
        // Extra bridges should be cleared from the Lox Context after each sync
        assert!(
            th.context.extra_bridges.lock().unwrap().is_empty(),
            "Extra bridges should be empty after sync"
        );
    }

    #[test]
    fn test_sync_with_bridgetable_working_and_not_working_resources() {
        let bridge_config = get_config();
        // Add bridges to empty bridge table and update with changed bridge state
        let th = TestHarness::new();
        let mut rs = TestResourceState::default();
        let num_buckets = 5;
        for _ in 0..num_buckets {
            rs.add_working_resource();
        }

        for _ in 0..num_buckets {
            rs.add_not_working_resource()
        }
        assert_ne!(rs.rstate.working, None);
        assert_ne!(rs.rstate.not_working, None);

        th.context.sync_with_bridgetable(
            bridge_config.watched_blockages,
            bridge_config.percent_spares,
            rs.rstate.clone(),
        );
        let mut reachable_expected_length = rs.rstate.clone().working.unwrap().len();
        let expected_extra_bridges = reachable_expected_length % MAX_BRIDGES_PER_BUCKET;
        if expected_extra_bridges != 0 {
            reachable_expected_length = reachable_expected_length - expected_extra_bridges;
        }
        assert_eq!(
            th.context.ba.lock().unwrap().reachable_length(),
            reachable_expected_length,
            "Unexpected number of reachable bridges"
        );
        // Extra bridges should be cleared from the Lox Context after each sync
        assert!(
            th.context.extra_bridges.lock().unwrap().is_empty(),
            "Extra bridges should be empty after sync"
        );
    }

    #[test]
    fn test_sync_with_preloaded_obsolete_bridgetable() {
        // Tests the case where all bridges in the bridgetable are no longer in rdsys.
        // In this case, all bridges should be replaced. If it's a bridge in a spare bucket, just remove the other bridges
        // from the spare bucket and delete the bridge
        let bridge_config = get_config();
        // Sync bridges to non-empty bridge table with disparate sets of bridges
        let th_with_bridges = TestHarness::new_with_bridges(); //Creates 5 open invitation and 5 hot spare buckets, so 30 total buckets to be replaced
        let mut rs = TestResourceState::default();
        let num_buckets = 5;
        for _ in 0..num_buckets {
            rs.add_working_resource();
        }
        assert_ne!(rs.rstate.working, None);
        assert_eq!(rs.rstate.not_working, None);

        assert_eq!(th_with_bridges.context.ba.lock().unwrap().reachable_length(), 30, "Unexpected number of reachable bridges. Should equal the number of open invitation bridges plus the number of spares added: 2x5x3");
        assert_eq!(
            th_with_bridges.context.ba.lock().unwrap().spares_length(),
            num_buckets,
            "Unexpected number of spare bridges, should be 5"
        );

        // All potentially distributed resources (i.e., those assigned to open invitation/trusted buckets)
        // not found in the rdsys update will first be replaced with any new resources coming in from rdsys then
        // by bridges from the hot spare buckets. In this case, the hot spare buckets are also not in the bridge table
        // so will also be replaced.
        // Since there are fewer working resources than resources that have populated the bridge table, this update will
        // exhaust the spare buckets and leave some obsolete bridges. The set of open invitation/trusted buckets should be
        // preserved (5 open invitation buckets * 3)
        th_with_bridges.context.sync_with_bridgetable(
            bridge_config.watched_blockages,
            bridge_config.percent_spares,
            rs.rstate.clone(),
        );
        assert_eq!(th_with_bridges.context.ba.lock().unwrap().reachable_length(), 15, "Unexpected number of reachable bridges should equal the number of open invitation bridges added: 5x3");
        assert_eq!(
            th_with_bridges.context.ba.lock().unwrap().spares_length(),
            0,
            "Unexpected number of spare bridges, should be exhausted"
        );

        assert_eq!(th_with_bridges.context.ba.lock().unwrap().unallocated_length(), 0, "Unexpected number of unallocated bridges, should be 0 (All spare buckets and new resources for replacement exhausted)"
        );
        assert_eq!(
            th_with_bridges.context.extra_bridges.lock().unwrap().len(),
            0,
            "Unexpected number of extra bridges"
        );
    }

    #[test]
    fn test_sync_with_bridgetable_block_working_resources() {
        let bridge_config = get_config();
        // Add bridges to empty bridge table and update with changed bridge state
        let th = TestHarness::new();
        let mut rs = TestResourceState::default();
        let num_buckets = 5;
        for _ in 0..num_buckets {
            rs.add_working_resource();
        }
        assert_ne!(rs.rstate.working, None);

        th.context.sync_with_bridgetable(
            bridge_config.watched_blockages.clone(),
            bridge_config.percent_spares,
            rs.rstate.clone(),
        );
        assert_eq!(
            th.context.db.lock().unwrap().openinv_length(),
            (num_buckets / 3) * 3
        );

        rs.block_working();

        th.context.sync_with_bridgetable(
            bridge_config.watched_blockages.clone(),
            bridge_config.percent_spares,
            rs.rstate.clone(),
        );

        assert_eq!(th.context.db.lock().unwrap().openinv_length(), 0);
    }
}
