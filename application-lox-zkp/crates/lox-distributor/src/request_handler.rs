use crate::lox_context::LoxServerContext;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{body::Body, header::HeaderValue, Method, Request, Response, StatusCode};
use std::{convert::Infallible, fmt::Debug};

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, Infallible> {
    Full::new(chunk.into()).boxed()
}

// Lox Request handling logic for each Lox request/protocol
pub async fn handle<B: Body>(
    cloned_context: LoxServerContext,
    req: Request<B>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible>
where
    <B as Body>::Error: Debug,
{
    match req.method() {
        &Method::OPTIONS => Ok(Response::builder()
            .header("Access-Control-Allow-Origin", HeaderValue::from_static("*"))
            .header("Access-Control-Allow-Headers", "accept, content-type")
            .header("Access-Control-Allow-Methods", "POST")
            .status(StatusCode::OK)
            .body(full("Allow POST"))
            .unwrap()),
        _ => match (req.method(), req.uri().path()) {
            #[cfg(feature = "test-branch")]
            (&Method::POST, "/advancedays") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                cloned_context.advance_days_with_response_test(bytes)
            }),
            #[cfg(feature = "test-branch")]
            (&Method::POST, "/blockbridges") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                cloned_context.block_bridges_test(bytes)
            }),
            #[cfg(feature = "test-branch")]
            (&Method::POST, "/rotate_lox_keys") => Ok::<_, _>(cloned_context.rotate_lox_keys()),
            #[cfg(feature = "test-branch")]
            (&Method::POST, "/rotate_invite_keys") => {
                Ok::<_, _>(cloned_context.rotate_invite_keys())
            }
            (&Method::POST, "/invite") => Ok::<_, Infallible>(cloned_context.generate_invite()),
            (&Method::POST, "/reachability") => {
                Ok::<_, Infallible>(cloned_context.send_reachability_cred())
            }
            (&Method::POST, "/pubkeys") => Ok::<_, Infallible>(cloned_context.send_keys()),
            (&Method::POST, "/constants") => Ok::<_, Infallible>(cloned_context.send_constants()),
            (&Method::POST, "/openreq") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                cloned_context.verify_and_send_open_cred(bytes)
            }),
            (&Method::POST, "/trustpromo") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                cloned_context.verify_and_send_trust_promo(bytes)
            }),
            (&Method::POST, "/trustmig") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                cloned_context.verify_and_send_trust_migration(bytes)
            }),
            (&Method::POST, "/levelup") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                cloned_context.verify_and_send_level_up(bytes)
            }),
            (&Method::POST, "/issueinvite") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                cloned_context.verify_and_send_issue_invite(bytes)
            }),
            (&Method::POST, "/redeem") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                cloned_context.verify_and_send_redeem_invite(bytes)
            }),
            (&Method::POST, "/checkblockage") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                // TEST ONLY: Block all existing bridges and add new ones for migration
                cloned_context.verify_and_send_check_blockage(bytes)
            }),
            (&Method::POST, "/blockagemigration") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                cloned_context.verify_and_send_blockage_migration(bytes)
            }),
            (&Method::POST, "/updatecred") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                cloned_context.verify_and_send_update_cred(bytes)
            }),
            (&Method::POST, "/updateinvite") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                cloned_context.verify_and_send_update_invite(bytes)
            }),
            _ => {
                // Return 404 not found response.
                cloned_context.metrics.invalid_endpoint_request_count.inc();
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(full("Not found"))
                    .unwrap())
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::lox_context;
    use crate::metrics::Metrics;

    use super::*;

    use chrono::{Duration, Utc};
    use http_body_util::Empty;
    use julianday::JulianDay;
    use lox_library::{bridge_table, cred::BucketReachability, proto, BridgeAuth, BridgeDb};
    use std::sync::{Arc, Mutex};

    type BoxedBody = http_body_util::combinators::BoxBody<bytes::Bytes, Infallible>;

    trait LoxClient<B: Body> {
        async fn invite(&self) -> Request<B>;
        fn reachability(&self) -> Request<B>;
        fn pubkeys(&self) -> Request<B>;
        fn constants(&self) -> Request<B>;
        fn openinvite(&self, request: proto::open_invite::Request) -> Request<B>;
        fn trustpromo(&self, request: proto::trust_promotion::Request) -> Request<B>;
        fn trustmigration(&self, request: proto::migration::Request) -> Request<B>;
        fn levelup(&self, request: proto::level_up::Request) -> Request<B>;
        fn issueinvite(&self, request: proto::issue_invite::Request) -> Request<B>;
        fn redeeminvite(&self, request: proto::redeem_invite::Request) -> Request<B>;
        fn checkblockage(&self, request: proto::check_blockage::Request) -> Request<B>;
        fn blockagemigration(&self, request: proto::blockage_migration::Request) -> Request<B>;
        fn updatecred(&self, request: proto::update_cred::Request) -> Request<B>;
        fn updateinvite(&self, request: proto::update_invite::Request) -> Request<B>;
    }

    struct LoxClientMock {}

    impl LoxClient<BoxedBody> for LoxClientMock {
        async fn invite(&self) -> Request<BoxedBody> {
            Request::builder()
                .method("POST")
                .uri("http://localhost/invite")
                .body(empty())
                .unwrap()
        }

        fn reachability(&self) -> Request<BoxedBody> {
            Request::builder()
                .method("POST")
                .uri("http://localhost/reachability")
                .body(empty())
                .unwrap()
        }

        fn pubkeys(&self) -> Request<BoxedBody> {
            Request::builder()
                .method("POST")
                .uri("http://localhost/pubkeys")
                .body(empty())
                .unwrap()
        }

        fn constants(&self) -> Request<BoxedBody> {
            Request::builder()
                .method("POST")
                .uri("http://localhost/constants")
                .body(empty())
                .unwrap()
        }

        fn openinvite(&self, request: proto::open_invite::Request) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/openreq")
                .body(full(req_str))
                .unwrap()
        }

        fn trustpromo(&self, request: proto::trust_promotion::Request) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/trustpromo")
                .body(full(req_str))
                .unwrap()
        }

        fn trustmigration(&self, request: proto::migration::Request) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/trustmig")
                .body(full(req_str))
                .unwrap()
        }

        fn levelup(&self, request: proto::level_up::Request) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/levelup")
                .body(full(req_str))
                .unwrap()
        }

        fn issueinvite(&self, request: proto::issue_invite::Request) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/issueinvite")
                .body(full(req_str))
                .unwrap()
        }

        fn redeeminvite(&self, request: proto::redeem_invite::Request) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/redeem")
                .body(full(req_str))
                .unwrap()
        }

        fn checkblockage(&self, request: proto::check_blockage::Request) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/checkblockage")
                .body(full(req_str))
                .unwrap()
        }

        fn blockagemigration(
            &self,
            request: proto::blockage_migration::Request,
        ) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/blockagemigration")
                .body(full(req_str))
                .unwrap()
        }

        fn updatecred(&self, request: proto::update_cred::Request) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/updatecred")
                .body(full(req_str))
                .unwrap()
        }

        fn updateinvite(&self, request: proto::update_invite::Request) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/updateinvite")
                .body(full(req_str))
                .unwrap()
        }
    }

    struct TestHarness {
        context: LoxServerContext,
    }

    impl TestHarness {
        fn new() -> Self {
            let mut bridgedb = BridgeDb::new();
            let mut lox_auth = BridgeAuth::new(bridgedb.pubkey);

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

        fn advance_days(&mut self, days: u16) {
            // For testing only: manually advance the day by the given number
            // of days.
            let mut ba_obj = self.context.ba.lock().unwrap();
            ba_obj.advance_days(days); // FOR TESTING ONLY
            println!("Today's date according to server: {}", ba_obj.today());
        }

        fn rotate_lox_keys(&mut self) {
            self.context.ba.lock().unwrap().rotate_lox_keys();
        }

        fn rotate_invitation_keys(&mut self) {
            self.context.ba.lock().unwrap().rotate_invitation_keys();
        }

        fn simulate_blocking(
            &mut self,
            cred: lox_library::cred::Lox,
        ) -> (lox_library::cred::Lox, u32, [u8; 16]) {
            let (id, key) = bridge_table::from_scalar(cred.bucket).unwrap();
            let mut bdb = self.context.db.lock().unwrap();
            let mut lox_auth = self.context.ba.lock().unwrap();
            let encbuckets = lox_auth.enc_bridge_table();
            let bucket =
                bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap())
                    .unwrap();
            assert!(bucket.1.is_some());
            // Block two of our bridges
            lox_auth.bridge_blocked(&bucket.0[0], &mut bdb);
            lox_auth.bridge_blocked(&bucket.0[2], &mut bdb);

            (cred, id, key)
        }

        fn prep_next_day(&mut self, id: u32, key: [u8; 16]) {
            let mut lox_auth = self.context.ba.lock().unwrap();
            let encbuckets2 = lox_auth.enc_bridge_table();
            let bucket2 =
                bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets2.get(&id).unwrap())
                    .unwrap();
            // We should no longer have a Bridge Reachability credential
            assert!(bucket2.1.is_none());
        }
    }

    // This should only be used for testing, use today in production
    fn test_today(days: i64) -> u32 {
        let naive_now_plus = (Utc::now() + Duration::days(days)).date_naive();
        JulianDay::from(naive_now_plus).inner().try_into().unwrap()
    }

    async fn body_to_string(res: Response<BoxBody<Bytes, Infallible>>) -> String {
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body_bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn test_handle_not_found() {
        let th = TestHarness::new();
        // Test Random page
        let four_oh_four_req = Request::builder()
            .header("Content-Type", "application/json")
            .method("POST")
            .uri("http://localhost/givemecreds")
            .body(empty())
            .unwrap();
        let not_found_response = handle(th.context.clone(), four_oh_four_req).await.unwrap();
        assert_eq!(not_found_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_handle_bad_request() {
        let th = TestHarness::new();
        // Test that empty request to a credential issuing endpoint fails
        let req = Request::builder()
            .method("POST")
            .uri("http://localhost/checkblockage")
            .body(empty())
            .unwrap();
        let not_found_response = handle(th.context.clone(), req).await.unwrap();
        assert_eq!(not_found_response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn test_handle_invite() {
        let th = TestHarness::new();
        let lc = LoxClientMock {};

        // Test Invite
        let invite_request = lc.invite().await;
        let invite_response = handle(th.context.clone(), invite_request).await.unwrap();
        assert_eq!(invite_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handle_reachability() {
        let th = TestHarness::new();
        let lc = LoxClientMock {};
        // Test Reachability
        let reachability_request = lc.reachability();
        let reachability_response = handle(th.context.clone(), reachability_request)
            .await
            .unwrap();
        assert_eq!(reachability_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handle_pubkeys() {
        let th = TestHarness::new();
        let lc = LoxClientMock {};
        // Test Pubkeys
        let pubkey_request = lc.pubkeys();
        let pubkey_response = handle(th.context.clone(), pubkey_request).await.unwrap();
        assert_eq!(pubkey_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handle_constants() {
        let th = TestHarness::new();
        let lc = LoxClientMock {};
        // Test Pubkeys
        let constant_request = lc.constants();
        let constant_response = handle(th.context.clone(), constant_request).await.unwrap();
        assert_eq!(constant_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handle_lox_protocols() {
        let mut th = TestHarness::new();
        let lc = LoxClientMock {};
        // Request Invite and pubkeys required for protocol tests

        // Get Open Invitation
        let invite_request = lc.invite().await;
        let invite_response = handle(th.context.clone(), invite_request).await.unwrap();

        // Test Open Invite and get response
        let invite_response_str = body_to_string(invite_response).await;
        let response_data: lox_utils::Invite = serde_json::from_str(&invite_response_str).unwrap();
        let token = match lox_utils::validate(&response_data.invite) {
            Ok(token) => token,
            Err(e) => panic!("Error: Invitation token error {:?}", e.to_string()),
        };

        // Get pubkeys
        let mut pubkey_request = lc.pubkeys();
        let mut pubkey_response = handle(th.context.clone(), pubkey_request).await.unwrap();
        let mut pubkeys = body_to_string(pubkey_response).await;
        let mut pubkeys_obj: lox_utils::PubKeys = serde_json::from_str(&pubkeys).unwrap();

        let (request, state) =
            lox_library::proto::open_invite::request(&token, &pubkeys_obj.lox_pub);
        let open_request = lc.openinvite(request);
        let open_response = handle(th.context.clone(), open_request).await.unwrap();
        assert_eq!(open_response.status(), StatusCode::OK);
        let open_resp = body_to_string(open_response).await;
        let open_response_obj = serde_json::from_str(&open_resp).unwrap();

        // Test Trust Promotion and get response
        let lox_cred = lox_library::proto::open_invite::handle_response(
            state,
            open_response_obj,
            &pubkeys_obj.lox_pub,
        )
        .unwrap();
        let mut bridge = Vec::new();
        bridge.push(lox_cred.1);
        let lox_cred: lox_utils::LoxCredential = lox_utils::LoxCredential {
            lox_credential: lox_cred.0,
            bridgelines: Some(bridge),
            invitation: None,
        };

        // Advance the context to a day after the credential becomes eligible to upgrade
        th.advance_days(31);
        let trust_result = match proto::trust_promotion::request(
            &lox_cred.lox_credential,
            &pubkeys_obj.lox_pub,
            &pubkeys_obj.migrationkey_pub,
            test_today(31),
        ) {
            Ok(trust_result) => trust_result,
            Err(e) => panic!(
                "Error: Proof error from trust promotion {:?}",
                e.to_string()
            ),
        };
        let trustpromo_request = lc.trustpromo(trust_result.0);
        let trustpromo_response = handle(th.context.clone(), trustpromo_request)
            .await
            .unwrap();
        assert_eq!(trustpromo_response.status(), StatusCode::OK);
        let trustpromo_resp = body_to_string(trustpromo_response).await;
        let trustpromo_response_obj = serde_json::from_str(&trustpromo_resp).unwrap();

        // Test Trust Migration and get response
        let mig_cred = match lox_library::proto::trust_promotion::handle_response(
            trust_result.1,
            trustpromo_response_obj,
        ) {
            Ok(mig_cred) => mig_cred,
            Err(e) => panic!("Error: Migration token error {:?}", e.to_string()),
        };
        let migration_result = match proto::migration::request(
            &lox_cred.lox_credential,
            &mig_cred,
            &pubkeys_obj.lox_pub,
            &pubkeys_obj.migration_pub,
        ) {
            Ok(migration_result) => migration_result,
            Err(e) => panic!(
                "Error: Proof error from trust migration {:?}",
                e.to_string()
            ),
        };
        let trustmig_request = lc.trustmigration(migration_result.0);
        let trustmig_response = handle(th.context.clone(), trustmig_request).await.unwrap();
        assert_eq!(trustmig_response.status(), StatusCode::OK);
        let trustmig_resp = body_to_string(trustmig_response).await;
        let trustmig_response_obj = serde_json::from_str(&trustmig_resp).unwrap();

        // Test Level up and get response
        let level_one_cred = match lox_library::proto::migration::handle_response(
            migration_result.1,
            trustmig_response_obj,
            &pubkeys_obj.lox_pub,
        ) {
            Ok(level_one_cred) => level_one_cred,
            Err(e) => panic!("Error: Level one credential error {:?}", e.to_string()),
        };
        th.advance_days(14);
        let new_reachability_request = lc.reachability();
        let new_reachability_response = handle(th.context.clone(), new_reachability_request)
            .await
            .unwrap();
        let encrypted_table = body_to_string(new_reachability_response).await;
        let reachability_cred: BucketReachability =
            lox_utils::generate_reachability_cred(&level_one_cred, encrypted_table);
        let level_up_result = match proto::level_up::request(
            &level_one_cred,
            &reachability_cred,
            &pubkeys_obj.lox_pub,
            &pubkeys_obj.reachability_pub,
            test_today(31 + 14),
        ) {
            Ok(level_up_result) => level_up_result,
            Err(e) => panic!("Error: Proof error from level up {:?}", e.to_string()),
        };
        let level_up_request = lc.levelup(level_up_result.0);
        let level_up_response = handle(th.context.clone(), level_up_request).await.unwrap();
        assert_eq!(level_up_response.status(), StatusCode::OK);
        let levelup_resp = body_to_string(level_up_response).await;
        let levelup_response_obj = serde_json::from_str(&levelup_resp).unwrap();
        let level_two_cred = match lox_library::proto::level_up::handle_response(
            level_up_result.1,
            levelup_response_obj,
            &pubkeys_obj.lox_pub,
        ) {
            Ok(level_two_cred) => level_two_cred,
            Err(e) => panic!("Error: Level two credential error {:?}", e.to_string()),
        };

        // Test Issue Invite and get response
        let new_reachability_request = lc.reachability();
        let new_reachability_response = handle(th.context.clone(), new_reachability_request)
            .await
            .unwrap();
        let encrypted_table = body_to_string(new_reachability_response).await;
        let reachability_cred: BucketReachability =
            lox_utils::generate_reachability_cred(&level_two_cred, encrypted_table);

        let issue_invite_result = match proto::issue_invite::request(
            &level_two_cred,
            &reachability_cred,
            &pubkeys_obj.lox_pub,
            &pubkeys_obj.reachability_pub,
            &pubkeys_obj.invitation_pub,
            test_today(31 + 14),
        ) {
            Ok(issue_invite_result) => issue_invite_result,
            Err(e) => panic!(
                "Error: Proof error from issue invitation {:?}",
                e.to_string()
            ),
        };
        let issue_invite_request = lc.issueinvite(issue_invite_result.0);
        let issue_invite_response = handle(th.context.clone(), issue_invite_request)
            .await
            .unwrap();
        assert_eq!(issue_invite_response.status(), StatusCode::OK);
        let invite_resp = body_to_string(issue_invite_response).await;
        let invite_response_obj = serde_json::from_str(&invite_resp).unwrap();
        let issue_invite_cred = match lox_library::proto::issue_invite::handle_response(
            issue_invite_result.1,
            invite_response_obj,
            &pubkeys_obj.lox_pub,
            &pubkeys_obj.invitation_pub,
        ) {
            Ok(issue_invite_cred) => issue_invite_cred,
            Err(e) => panic!("Error: Issue invite credential error {:?}", e.to_string()),
        };

        let old_keys = pubkeys_obj.invitation_pub;
        th.rotate_invitation_keys();

        // Get pubkeys
        pubkey_request = lc.pubkeys();
        pubkey_response = handle(th.context.clone(), pubkey_request).await.unwrap();
        pubkeys = body_to_string(pubkey_response).await;
        pubkeys_obj = serde_json::from_str(&pubkeys).unwrap();

        // Test Update Invitation
        let reissue_invite_result = match proto::update_invite::request(
            &issue_invite_cred.1,
            &old_keys,
            &pubkeys_obj.invitation_pub,
        ) {
            Ok(reissue_invite_result) => reissue_invite_result,
            Err(e) => panic!(
                "Error: Proof error from update invitation {:?}",
                e.to_string()
            ),
        };
        let reissue_invite_request = lc.updateinvite(reissue_invite_result.0);
        let reissue_invite_response = handle(th.context.clone(), reissue_invite_request)
            .await
            .unwrap();
        assert_eq!(reissue_invite_response.status(), StatusCode::OK);
        let reissued_invite_resp = body_to_string(reissue_invite_response).await;
        let reissued_invite_response_obj = serde_json::from_str(&reissued_invite_resp).unwrap();
        let reissue_invite_cred = match lox_library::proto::update_invite::handle_response(
            reissue_invite_result.1,
            reissued_invite_response_obj,
            &pubkeys_obj.invitation_pub,
        ) {
            Ok(reissue_invite_cred) => reissue_invite_cred,
            Err(e) => panic!("Error: Issue invite credential error {:?}", e.to_string()),
        };

        // Test Redeem Invite
        let new_invite = match proto::redeem_invite::request(
            &reissue_invite_cred,
            &pubkeys_obj.lox_pub,
            &pubkeys_obj.invitation_pub,
            test_today(31 + 14),
        ) {
            Ok(new_invite) => new_invite,
            Err(e) => panic!("Error: Proof error from level up {:?}", e.to_string()),
        };
        let new_redeem_invite_request = lc.redeeminvite(new_invite.0);
        let new_redeem_invite_response = handle(th.context.clone(), new_redeem_invite_request)
            .await
            .unwrap();
        assert_eq!(new_redeem_invite_response.status(), StatusCode::OK);
        let redeemed_cred_resp = body_to_string(new_redeem_invite_response).await;
        let redeemed_cred_resp_obj = serde_json::from_str(&redeemed_cred_resp).unwrap();

        let _redeemed_cred_result = match proto::redeem_invite::handle_response(
            new_invite.1,
            redeemed_cred_resp_obj,
            &pubkeys_obj.lox_pub,
        ) {
            Ok(redeemed_cred_result) => redeemed_cred_result,
            Err(e) => panic!(
                "Error: Proof error from issue invitation {:?}",
                e.to_string()
            ),
        };

        // Prepare for check blockage request
        th.advance_days(28); // First advance most recent credential to level 3
        let new_reachability_request = lc.reachability();
        let new_reachability_response = handle(th.context.clone(), new_reachability_request)
            .await
            .unwrap();
        let encrypted_table = body_to_string(new_reachability_response).await;
        let reachability_cred: BucketReachability =
            lox_utils::generate_reachability_cred(&issue_invite_cred.0, encrypted_table);
        let level_three_request = match proto::level_up::request(
            &issue_invite_cred.0,
            &reachability_cred,
            &pubkeys_obj.lox_pub,
            &pubkeys_obj.reachability_pub,
            test_today(31 + 14 + 28),
        ) {
            Ok(level_three_request) => level_three_request,
            Err(e) => panic!("Error: Proof error from level up to 3 {:?}", e.to_string()),
        };
        let level_three_req = lc.levelup(level_three_request.0);
        let level_three_response = handle(th.context.clone(), level_three_req).await.unwrap();
        assert_eq!(level_three_response.status(), StatusCode::OK);
        let levelup_resp = body_to_string(level_three_response).await;
        let levelup_response_obj = serde_json::from_str(&levelup_resp).unwrap();
        let level_three_cred = match lox_library::proto::level_up::handle_response(
            level_three_request.1,
            levelup_response_obj,
            &pubkeys_obj.lox_pub,
        ) {
            Ok(level_three_cred) => level_three_cred,
            Err(e) => panic!("Error: Level two credential error {:?}", e.to_string()),
        };
        // Simulate blocking event
        let passed_level_three_cred = th.simulate_blocking(level_three_cred);
        th.advance_days(1);
        th.prep_next_day(passed_level_three_cred.1, passed_level_three_cred.2);

        //Test Check Blockage and get response
        let migration_cred_request = match proto::check_blockage::request(
            &passed_level_three_cred.0,
            &pubkeys_obj.lox_pub,
            &pubkeys_obj.migrationkey_pub,
        ) {
            Ok(migration_cred_request) => migration_cred_request,
            Err(e) => panic!("Error: Proof error from level up to 3 {:?}", e.to_string()),
        };
        let migration_cred_req = lc.checkblockage(migration_cred_request.0);
        let migration_cred_response = handle(th.context.clone(), migration_cred_req)
            .await
            .unwrap();
        assert_eq!(migration_cred_response.status(), StatusCode::OK);
        let migration_resp = body_to_string(migration_cred_response).await;
        let migration_response_obj = serde_json::from_str(&migration_resp).unwrap();
        let mig_cred = match lox_library::proto::check_blockage::handle_response(
            migration_cred_request.1,
            migration_response_obj,
        ) {
            Ok(mig_cred) => mig_cred,
            Err(e) => panic!("Error: Migration token error {:?}", e.to_string()),
        };

        // Test Blockage Migration

        let migration_result = match proto::blockage_migration::request(
            &passed_level_three_cred.0,
            &mig_cred,
            &pubkeys_obj.lox_pub,
            &pubkeys_obj.migration_pub,
        ) {
            Ok(migration_result) => migration_result,
            Err(e) => panic!(
                "Error: Proof error from trust migration {:?}",
                e.to_string()
            ),
        };
        let blockagemig_request = lc.blockagemigration(migration_result.0);
        let blockagemig_response = handle(th.context.clone(), blockagemig_request)
            .await
            .unwrap();
        assert_eq!(blockagemig_response.status(), StatusCode::OK);

        let new_migration_resp = body_to_string(blockagemig_response).await;
        let new_migration_response_obj = serde_json::from_str(&new_migration_resp).unwrap();

        let new_migrated_cred = match lox_library::proto::blockage_migration::handle_response(
            migration_result.1,
            new_migration_response_obj,
            &pubkeys_obj.lox_pub,
        ) {
            Ok(new_lox_cred) => new_lox_cred,
            Err(e) => panic!(
                "Error: Blockage migration credential error {:?}",
                e.to_string()
            ),
        };

        let old_keys = pubkeys_obj.lox_pub;
        // Rotate Keys
        th.rotate_lox_keys();

        // Get pubkeys
        pubkey_request = lc.pubkeys();
        pubkey_response = handle(th.context.clone(), pubkey_request).await.unwrap();
        pubkeys = body_to_string(pubkey_response).await;
        pubkeys_obj = serde_json::from_str(&pubkeys).unwrap();

        // Test Upgrade Cred
        let update_cred_request = match proto::update_cred::request(
            &new_migrated_cred,
            &old_keys,
            &pubkeys_obj.lox_pub,
        ) {
            Ok(update_cred_request) => update_cred_request,
            Err(e) => panic!(
                "Error: Proof error from update credential {:?}",
                e.to_string()
            ),
        };

        let update_request = lc.updatecred(update_cred_request.0);
        let update_response = handle(th.context.clone(), update_request).await.unwrap();
        assert_eq!(update_response.status(), StatusCode::OK);
    }

    fn empty() -> BoxBody<Bytes, Infallible> {
        Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed()
    }
}
