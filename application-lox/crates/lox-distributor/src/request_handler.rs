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
            #[cfg(any(test, feature = "test-branch"))]
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
    use super::*;

    use crate::fake_context::TestHarness;
    use chrono::{Duration, NaiveDate, Utc};
    use cmz::{CMZCredential, CMZError, CMZPubkey};
    use curve25519_dalek::ristretto::RistrettoPoint as G;
    use http_body_util::Empty;
    use hyper::body::Bytes;
    use hyper::Response;
    use julianday::JulianDay;
    use lox_extensions::{
        lox_creds::{BucketReachability, Invitation, Lox, Migration},
        proto::{
            blockage_migration, check_blockage, issue_invite, level_up, migration, open_invite,
            redeem_invite, trust_promotion, update_cred, update_invite,
        },
    };
    use serde_json::Error;
    use std::convert::Infallible;

    use lox_utils::OpenInvReq;

    type BoxedBody = http_body_util::combinators::BoxBody<bytes::Bytes, Infallible>;

    trait LoxClient<B: Body> {
        async fn invite(&self) -> Request<B>;
        fn reachability(&self) -> Request<B>;
        fn pubkeys(&self) -> Request<B>;
        fn constants(&self) -> Request<B>;
        fn openinvite(&self, request: lox_utils::OpenInvReq) -> Request<B>;
        fn trustpromo(&self, request: trust_promotion::trust_promotion::Request) -> Request<B>;
        fn trustmigration(&self, request: migration::migration::Request) -> Request<B>;
        fn levelup(&self, request: level_up::level_up::Request) -> Request<B>;
        fn issueinvite(&self, request: issue_invite::issue_invite::Request) -> Request<B>;
        fn redeeminvite(&self, request: redeem_invite::redeem_invite::Request) -> Request<B>;
        fn checkblockage(&self, request: check_blockage::check_blockage::Request) -> Request<B>;
        fn blockagemigration(
            &self,
            request: blockage_migration::blockage_migration::Request,
        ) -> Request<B>;
        fn updatecred(&self, request: lox_utils::UpdateCredReq) -> Request<B>;
        fn updateinvite(&self, request: lox_utils::UpdateInviteReq) -> Request<B>;
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

        fn openinvite(&self, request: lox_utils::OpenInvReq) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/openreq")
                .body(full(req_str))
                .unwrap()
        }

        fn trustpromo(
            &self,
            request: trust_promotion::trust_promotion::Request,
        ) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/trustpromo")
                .body(full(req_str))
                .unwrap()
        }

        fn trustmigration(&self, request: migration::migration::Request) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/trustmig")
                .body(full(req_str))
                .unwrap()
        }

        fn levelup(&self, request: level_up::level_up::Request) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/levelup")
                .body(full(req_str))
                .unwrap()
        }

        fn issueinvite(&self, request: issue_invite::issue_invite::Request) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/issueinvite")
                .body(full(req_str))
                .unwrap()
        }

        fn redeeminvite(
            &self,
            request: redeem_invite::redeem_invite::Request,
        ) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/redeem")
                .body(full(req_str))
                .unwrap()
        }

        fn checkblockage(
            &self,
            request: check_blockage::check_blockage::Request,
        ) -> Request<BoxedBody> {
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
            request: blockage_migration::blockage_migration::Request,
        ) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/blockagemigration")
                .body(full(req_str))
                .unwrap()
        }

        fn updatecred(&self, request: lox_utils::UpdateCredReq) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/updatecred")
                .body(full(req_str))
                .unwrap()
        }

        fn updateinvite(&self, request: lox_utils::UpdateInviteReq) -> Request<BoxedBody> {
            let req_str = serde_json::to_string(&request).unwrap();
            Request::builder()
                .header("Content-Type", "application/json")
                .method("POST")
                .uri("http://localhost/updateinvite")
                .body(full(req_str))
                .unwrap()
        }
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

    async fn get_invite(context: LoxServerContext) -> Result<Response<BoxedBody>, Infallible> {
        let lc = LoxClientMock {};
        // Test Invite
        let invite_request = lc.invite().await;
        handle(context, invite_request).await
    }

    #[tokio::test]
    async fn test_handle_invite() {
        let th = TestHarness::new();
        let invite_response = get_invite(th.context).await.unwrap();
        assert_eq!(invite_response.status(), StatusCode::OK);
    }

    async fn get_reachability_cred(
        context: LoxServerContext,
    ) -> Result<Response<BoxedBody>, Infallible> {
        let lc = LoxClientMock {};
        // Test Reachability
        let reachability_request = lc.reachability();
        handle(context, reachability_request).await
    }

    #[tokio::test]
    async fn test_handle_reachability() {
        let th = TestHarness::new();
        let reachability_response = get_reachability_cred(th.context).await.unwrap();
        assert_eq!(reachability_response.status(), StatusCode::OK);
    }

    async fn get_pubkeys(context: LoxServerContext) -> Result<lox_utils::PubKeys, Error> {
        let lc = LoxClientMock {};
        // Test Pubkeys
        let pubkey_request = lc.pubkeys();
        let pubkey_response = handle(context, pubkey_request).await.unwrap();
        assert_eq!(pubkey_response.status(), StatusCode::OK);
        let pubkeys = body_to_string(pubkey_response).await;
        serde_json::from_str(&pubkeys)
    }

    #[tokio::test]
    async fn test_handle_pubkeys() {
        let th = TestHarness::new();
        let pubkeys = get_pubkeys(th.context).await;
        assert!(pubkeys.is_ok());
    }

    #[tokio::test]
    async fn test_handle_constants() {
        let th = TestHarness::new();
        let lc = LoxClientMock {};
        // Test Pubkeys
        let constant_request = lc.constants();
        let constant_response = handle(th.context.clone(), constant_request).await;
        assert!(constant_response.is_ok());
    }

    async fn get_token(invite_response: Response<BoxBody<Bytes, Infallible>>) -> lox_utils::Invite {
        // Test Open Invite and get response
        let invite_response_str = body_to_string(invite_response).await;
        let response_data: lox_utils::Invite = serde_json::from_str(&invite_response_str).unwrap();
        match lox_utils::validate(&response_data.invite) {
            Ok(token) => lox_utils::Invite { invite: token },
            Err(e) => panic!("Error: Invitation token error {:?}", e.to_string()),
        }
    }

    async fn get_open_invite(
        context: LoxServerContext,
        token: lox_utils::Invite,
        lox_pub: CMZPubkey<G>,
    ) -> Result<Lox, CMZError> {
        let rng = &mut rand::thread_rng();
        let lc = LoxClientMock {};
        let (request, state) = open_invite::request(rng, lox_pub).unwrap();
        let open_req: lox_utils::OpenInvReq = OpenInvReq {
            request: request,
            invite: token,
        };
        let open_request = lc.openinvite(open_req);
        let open_response = handle(context.clone(), open_request).await.unwrap();
        assert_eq!(open_response.status(), StatusCode::OK);
        let open_resp = body_to_string(open_response).await;
        let open_response_obj: lox_utils::OpenResponse = serde_json::from_str(&open_resp).unwrap();

        // Test Trust Promotion and get response
        open_invite::handle_response(state, open_response_obj.reply)
    }

    #[tokio::test]
    async fn test_handle_open_invitation() {
        let th = TestHarness::new();
        // Get Open Invitation
        let invite_response = get_invite(th.context.clone()).await.unwrap();
        let token = get_token(invite_response).await;

        // Get pubkeys
        let pubkeys_obj = get_pubkeys(th.context.clone()).await.unwrap();
        let open_response = get_open_invite(th.context, token, pubkeys_obj.lox_pub.clone()).await;
        assert!(open_response.is_ok());
    }

    // This should only be used for testing, use today in production
    fn test_today(days: i64) -> u32 {
        let naive_now_plus: NaiveDate = (Utc::now() + Duration::days(days)).date_naive();
        JulianDay::from(naive_now_plus).inner().try_into().unwrap()
    }

    #[tokio::test]
    async fn test_handle_rotate_keys() {
        let mut th = TestHarness::new();
        // Get Open Invitation
        let invite_response = get_invite(th.context.clone()).await.unwrap();
        let token = get_token(invite_response).await;

        // Get pubkeys
        let mut pubkeys_obj = get_pubkeys(th.context.clone()).await.unwrap();
        let open_response =
            get_open_invite(th.context.clone(), token, pubkeys_obj.lox_pub.clone()).await;
        assert!(open_response.is_ok());

        let old_key = pubkeys_obj.lox_pub.clone();

        // Rotate Keys
        th.rotate_lox_keys();

        // Get pubkeys
        pubkeys_obj = get_pubkeys(th.context.clone()).await.unwrap();

        // Test Upgrade Cred
        let rng = &mut rand::thread_rng();
        let lc = LoxClientMock {};
        let update_cred_request =
            match update_cred::request(rng, open_response.unwrap(), pubkeys_obj.lox_pub.clone()) {
                Ok(update_cred_request) => update_cred_request,
                Err(e) => panic!(
                    "Error: Proof error from update credential {:?}",
                    e.to_string()
                ),
            };
        let update_req = lox_utils::UpdateCredReq {
            old_key: old_key,
            request: update_cred_request.0,
        };
        let update_request = lc.updatecred(update_req);
        let update_response = handle(th.context.clone(), update_request).await.unwrap();
        assert_eq!(update_response.status(), StatusCode::OK);
        let rotate_keys_resp = body_to_string(update_response).await;
        let rotate_response_obj = serde_json::from_str(&rotate_keys_resp).unwrap();
        // Test Trust Migration and get response
        let new_lox = update_cred::handle_response(update_cred_request.1, rotate_response_obj);
        assert!(new_lox.is_ok());
        assert_eq!(*new_lox.unwrap().get_pubkey(), pubkeys_obj.lox_pub);
    }

    async fn get_trust_promotion(
        context: LoxServerContext,
        cred: Lox,
        migkey_pub: CMZPubkey<G>,
        migration_pub: CMZPubkey<G>,
    ) -> Result<Migration, CMZError> {
        let rng = &mut rand::thread_rng();
        let lc = LoxClientMock {};
        let trust_result = match trust_promotion::request(rng, cred, migkey_pub, test_today(31)) {
            Ok(trust_result) => trust_result,
            Err(e) => panic!(
                "Error: Proof error from trust promotion {:?}",
                e.to_string()
            ),
        };
        let trustpromo_request = lc.trustpromo(trust_result.0);
        let trustpromo_response = handle(context, trustpromo_request).await.unwrap();
        assert_eq!(trustpromo_response.status(), StatusCode::OK);
        let trustpromo_resp = body_to_string(trustpromo_response).await;
        let trustpromo_response_obj: lox_utils::TrustResponse =
            serde_json::from_str(&trustpromo_resp).unwrap();
        // Test Trust Migration and get response
        trust_promotion::handle_response(
            migration_pub,
            trust_result.1,
            trustpromo_response_obj.reply,
            trustpromo_response_obj.enc_mig_table,
        )
    }

    #[tokio::test]
    async fn test_handle_trust_promotion() {
        let mut th = TestHarness::new();
        // Get Open Invitation
        let invite_response = get_invite(th.context.clone()).await.unwrap();
        let token = get_token(invite_response).await;

        // Get pubkeys
        let pubkeys_obj = get_pubkeys(th.context.clone()).await.unwrap();
        let lox_cred = get_open_invite(th.context.clone(), token, pubkeys_obj.lox_pub.clone())
            .await
            .unwrap();
        // Advance the context to a day after the credential becomes eligible to upgrade
        th.advance_days(31);
        let mig_cred = get_trust_promotion(
            th.context.clone(),
            lox_cred.clone(),
            pubkeys_obj.migrationkey_pub.clone(),
            pubkeys_obj.migration_pub.clone(),
        )
        .await;
        assert!(mig_cred.is_ok());
    }

    async fn get_trust_migration(
        context: LoxServerContext,
        cred: Lox,
        mig_cred: Migration,
    ) -> Result<Lox, CMZError> {
        let rng = &mut rand::thread_rng();
        let lc = LoxClientMock {};
        let migration_result = match migration::request(rng, cred, mig_cred) {
            Ok(migration_result) => migration_result,
            Err(e) => panic!(
                "Error: Proof error from trust migration {:?}",
                e.to_string()
            ),
        };
        let trustmig_request = lc.trustmigration(migration_result.0);
        let trustmig_response = handle(context, trustmig_request).await.unwrap();
        assert_eq!(trustmig_response.status(), StatusCode::OK);
        let trustmig_resp = body_to_string(trustmig_response).await;
        let trustmig_response_obj = serde_json::from_str(&trustmig_resp).unwrap();
        // Test Level up and get response
        lox_extensions::proto::migration::handle_response(migration_result.1, trustmig_response_obj)
    }

    #[tokio::test]
    async fn test_handle_trust_migration() {
        let mut th = TestHarness::new();
        // Get Open Invitation
        let invite_response = get_invite(th.context.clone()).await.unwrap();
        let token = get_token(invite_response).await;

        // Get pubkeys
        let pubkeys_obj = get_pubkeys(th.context.clone()).await.unwrap();
        let lox_cred = get_open_invite(th.context.clone(), token, pubkeys_obj.lox_pub.clone())
            .await
            .unwrap();
        // Advance the context to a day after the credential becomes eligible to upgrade
        th.advance_days(31);
        let mig_cred = get_trust_promotion(
            th.context.clone(),
            lox_cred.clone(),
            pubkeys_obj.migrationkey_pub.clone(),
            pubkeys_obj.migration_pub.clone(),
        )
        .await
        .unwrap();
        let level_one_cred =
            get_trust_migration(th.context.clone(), lox_cred.clone(), mig_cred.clone()).await;
        assert!(level_one_cred.is_ok());
    }

    async fn get_level_up(
        context: LoxServerContext,
        reach_pub: CMZPubkey<G>,
        cred: Lox,
        days: i64,
    ) -> Result<Lox, CMZError> {
        let rng = &mut rand::thread_rng();
        let lc = LoxClientMock {};
        let new_reachability_response = get_reachability_cred(context.clone()).await.unwrap();
        let encrypted_table = body_to_string(new_reachability_response).await;
        let reachability_cred: BucketReachability =
            lox_utils::generate_reachability_cred(&cred.clone(), encrypted_table, reach_pub);
        let num_days = test_today(days);
        let level_up_result =
            match level_up::request(rng, cred.clone(), reachability_cred, num_days) {
                Ok(level_up_result) => level_up_result,
                Err(e) => panic!("Error: Proof error from level up {:?}", e.to_string()),
            };
        let level_up_request = lc.levelup(level_up_result.0);
        let level_up_response = handle(context.clone(), level_up_request).await.unwrap();
        assert_eq!(level_up_response.status(), StatusCode::OK);
        let levelup_resp = body_to_string(level_up_response).await;
        let levelup_response_obj = serde_json::from_str(&levelup_resp).unwrap();
        level_up::handle_response(level_up_result.1, levelup_response_obj)
    }

    #[tokio::test]
    async fn test_handle_level_up() {
        let mut th = TestHarness::new();
        // Get Open Invitation
        let invite_response = get_invite(th.context.clone()).await.unwrap();
        let token = get_token(invite_response).await;

        // Get pubkeys
        let pubkeys_obj = get_pubkeys(th.context.clone()).await.unwrap();
        let lox_cred = get_open_invite(th.context.clone(), token, pubkeys_obj.lox_pub.clone())
            .await
            .unwrap();
        // Advance the context to a day after the credential becomes eligible to upgrade
        th.advance_days(31);
        let mig_cred = get_trust_promotion(
            th.context.clone(),
            lox_cred.clone(),
            pubkeys_obj.migrationkey_pub.clone(),
            pubkeys_obj.migration_pub.clone(),
        )
        .await
        .unwrap();
        let level_one_cred =
            get_trust_migration(th.context.clone(), lox_cred.clone(), mig_cred.clone())
                .await
                .unwrap();
        th.advance_days(14);
        let level_two_cred = get_level_up(
            th.context.clone(),
            pubkeys_obj.reachability_pub.clone(),
            level_one_cred,
            31 + 14,
        )
        .await;
        assert!(level_two_cred.is_ok());
    }

    async fn get_issue_invite(
        context: LoxServerContext,
        reach_pub: CMZPubkey<G>,
        cred: Lox,
        invite_pub: CMZPubkey<G>,
    ) -> Result<(Invitation, Lox), CMZError> {
        let rng = &mut rand::thread_rng();
        let lc = LoxClientMock {};
        let new_reachability_response = get_reachability_cred(context.clone()).await.unwrap();
        let encrypted_table = body_to_string(new_reachability_response).await;
        let reachability_cred: BucketReachability =
            lox_utils::generate_reachability_cred(&cred.clone(), encrypted_table, reach_pub);

        let issue_invite_result = match issue_invite::request(
            rng,
            cred,
            reachability_cred,
            invite_pub,
            test_today(31 + 14),
        ) {
            Ok(issue_invite_result) => issue_invite_result,
            Err(e) => panic!(
                "Error: Proof error from issue invitation {:?}",
                e.to_string()
            ),
        };
        let issue_invite_request = lc.issueinvite(issue_invite_result.0);
        let issue_invite_response = handle(context, issue_invite_request).await.unwrap();
        assert_eq!(issue_invite_response.status(), StatusCode::OK);
        let invite_resp = body_to_string(issue_invite_response).await;
        let invite_response_obj = serde_json::from_str(&invite_resp).unwrap();
        issue_invite::handle_response(issue_invite_result.1, invite_response_obj)
    }

    #[tokio::test]
    async fn test_handle_issue_invite() {
        let mut th = TestHarness::new();
        // Get Open Invitation
        let invite_response = get_invite(th.context.clone()).await.unwrap();
        let token = get_token(invite_response).await;

        // Get pubkeys
        let pubkeys_obj = get_pubkeys(th.context.clone()).await.unwrap();
        let lox_cred = get_open_invite(th.context.clone(), token, pubkeys_obj.lox_pub.clone())
            .await
            .unwrap();
        // Advance the context to a day after the credential becomes eligible to upgrade
        th.advance_days(31);
        let mig_cred = get_trust_promotion(
            th.context.clone(),
            lox_cred.clone(),
            pubkeys_obj.migrationkey_pub.clone(),
            pubkeys_obj.migration_pub.clone(),
        )
        .await
        .unwrap();
        let level_one_cred =
            get_trust_migration(th.context.clone(), lox_cred.clone(), mig_cred.clone())
                .await
                .unwrap();
        th.advance_days(14);
        let level_two_cred = get_level_up(
            th.context.clone(),
            pubkeys_obj.reachability_pub.clone(),
            level_one_cred,
            31 + 14,
        )
        .await
        .unwrap();
        // Test Issue Invite and get response
        let issue_invite_cred = get_issue_invite(
            th.context.clone(),
            pubkeys_obj.reachability_pub.clone(),
            level_two_cred,
            pubkeys_obj.invitation_pub.clone(),
        )
        .await;
        assert!(issue_invite_cred.is_ok());
    }

    #[tokio::test]
    async fn test_handle_rotate_invitation_keys() {
        let mut th = TestHarness::new();
        // Get Open Invitation
        let invite_response = get_invite(th.context.clone()).await.unwrap();
        let token = get_token(invite_response).await;

        // Get pubkeys
        let mut pubkeys_obj = get_pubkeys(th.context.clone()).await.unwrap();
        let lox_cred = get_open_invite(th.context.clone(), token, pubkeys_obj.lox_pub.clone())
            .await
            .unwrap();
        // Advance the context to a day after the credential becomes eligible to upgrade
        th.advance_days(31);
        // Do Trust Promotion
        let mig_cred = get_trust_promotion(
            th.context.clone(),
            lox_cred.clone(),
            pubkeys_obj.migrationkey_pub.clone(),
            pubkeys_obj.migration_pub.clone(),
        )
        .await
        .unwrap();
        let level_one_cred =
            get_trust_migration(th.context.clone(), lox_cred.clone(), mig_cred.clone())
                .await
                .unwrap();
        th.advance_days(14);
        // Do Level Up
        let level_two_cred = get_level_up(
            th.context.clone(),
            pubkeys_obj.reachability_pub.clone(),
            level_one_cred,
            31 + 14,
        )
        .await
        .unwrap();

        // Test Issue Invite and get response
        let issue_invite_cred = get_issue_invite(
            th.context.clone(),
            pubkeys_obj.reachability_pub.clone(),
            level_two_cred,
            pubkeys_obj.invitation_pub.clone(),
        )
        .await
        .unwrap();

        let old_key = pubkeys_obj.invitation_pub.clone();

        th.rotate_invitation_keys();

        // Get pubkeys
        pubkeys_obj = get_pubkeys(th.context.clone()).await.unwrap();

        // Test Update Invitation
        let rng = &mut rand::thread_rng();
        let lc = LoxClientMock {};
        let reissue_invite_result = match update_invite::request(
            rng,
            issue_invite_cred.0,
            pubkeys_obj.invitation_pub.clone(),
        ) {
            Ok(reissue_invite_result) => reissue_invite_result,
            Err(e) => panic!(
                "Error: Proof error from update invitation {:?}",
                e.to_string()
            ),
        };
        let reissue_req: lox_utils::UpdateInviteReq = lox_utils::UpdateInviteReq {
            old_key: old_key,
            request: reissue_invite_result.0,
        };
        let reissue_invite_request = lc.updateinvite(reissue_req);
        let reissue_invite_response = handle(th.context.clone(), reissue_invite_request)
            .await
            .unwrap();
        assert_eq!(reissue_invite_response.status(), StatusCode::OK);
        let reissued_invite_resp = body_to_string(reissue_invite_response).await;
        let reissued_invite_response_obj = serde_json::from_str(&reissued_invite_resp).unwrap();
        let reissue_invite_cred =
            update_invite::handle_response(reissue_invite_result.1, reissued_invite_response_obj);
        assert!(reissue_invite_cred.is_ok());
        assert_eq!(
            *reissue_invite_cred.unwrap().get_pubkey(),
            pubkeys_obj.invitation_pub.clone()
        );
    }

    async fn get_redeem_invite(
        context: LoxServerContext,
        cred: Invitation,
        lox_pub: CMZPubkey<G>,
        days: i64,
    ) -> Result<Lox, CMZError> {
        let rng = &mut rand::thread_rng();
        let lc = LoxClientMock {};
        let num_days = test_today(days);
        let new_invite = match redeem_invite::request(rng, cred, lox_pub, num_days) {
            Ok(new_invite) => new_invite,
            Err(e) => panic!("Error: Proof error from level up {:?}", e.to_string()),
        };
        let new_redeem_invite_request = lc.redeeminvite(new_invite.0);
        let new_redeem_invite_response = handle(context, new_redeem_invite_request).await.unwrap();
        assert_eq!(new_redeem_invite_response.status(), StatusCode::OK);
        let redeemed_cred_resp = body_to_string(new_redeem_invite_response).await;
        let redeemed_cred_resp_obj = serde_json::from_str(&redeemed_cred_resp).unwrap();
        redeem_invite::handle_response(new_invite.1, redeemed_cred_resp_obj)
    }

    #[tokio::test]
    async fn test_handle_redeem_invite() {
        let mut th = TestHarness::new();
        // Get Open Invitation
        let invite_response = get_invite(th.context.clone()).await.unwrap();
        let token = get_token(invite_response).await;

        // Get pubkeys
        let pubkeys_obj = get_pubkeys(th.context.clone()).await.unwrap();
        let lox_cred = get_open_invite(th.context.clone(), token, pubkeys_obj.lox_pub.clone())
            .await
            .unwrap();
        // Advance the context to a day after the credential becomes eligible to upgrade
        th.advance_days(31);
        let mig_cred = get_trust_promotion(
            th.context.clone(),
            lox_cred.clone(),
            pubkeys_obj.migrationkey_pub.clone(),
            pubkeys_obj.migration_pub.clone(),
        )
        .await
        .unwrap();
        let level_one_cred =
            get_trust_migration(th.context.clone(), lox_cred.clone(), mig_cred.clone())
                .await
                .unwrap();
        th.advance_days(14);
        let level_two_cred = get_level_up(
            th.context.clone(),
            pubkeys_obj.reachability_pub.clone(),
            level_one_cred,
            31 + 14,
        )
        .await
        .unwrap();
        // Test Issue Invite and get response
        let issue_invite_cred = get_issue_invite(
            th.context.clone(),
            pubkeys_obj.reachability_pub.clone(),
            level_two_cred,
            pubkeys_obj.invitation_pub.clone(),
        )
        .await
        .unwrap();

        // Test Redeem Invite
        let redeem_invite = get_redeem_invite(
            th.context.clone(),
            issue_invite_cred.0,
            pubkeys_obj.lox_pub.clone(),
            31 + 14,
        )
        .await;
        assert!(redeem_invite.is_ok());
    }

    #[tokio::test]
    async fn test_handle_check_blockage() {
        let mut th = TestHarness::new();
        // Get Open Invitation
        let invite_response = get_invite(th.context.clone()).await.unwrap();
        let token = get_token(invite_response).await;

        // Get pubkeys
        let pubkeys_obj = get_pubkeys(th.context.clone()).await.unwrap();
        let lox_cred = get_open_invite(th.context.clone(), token, pubkeys_obj.lox_pub.clone())
            .await
            .unwrap();
        // Advance the context to a day after the credential becomes eligible to upgrade
        th.advance_days(31);
        let mig_cred = get_trust_promotion(
            th.context.clone(),
            lox_cred.clone(),
            pubkeys_obj.migrationkey_pub.clone(),
            pubkeys_obj.migration_pub.clone(),
        )
        .await
        .unwrap();
        let level_one_cred =
            get_trust_migration(th.context.clone(), lox_cred.clone(), mig_cred.clone())
                .await
                .unwrap();
        th.advance_days(14);
        let level_two_cred = get_level_up(
            th.context.clone(),
            pubkeys_obj.reachability_pub.clone(),
            level_one_cred,
            31 + 14,
        )
        .await
        .unwrap();
        // Prepare for check blockage request
        th.advance_days(28);
        let level_three_cred = get_level_up(
            th.context.clone(),
            pubkeys_obj.reachability_pub.clone(),
            level_two_cred,
            28 + 31 + 14,
        )
        .await
        .unwrap();
        let rng = &mut rand::thread_rng();
        let lc = LoxClientMock {};

        // Simulate blocking event
        let bucket_info = th.simulate_blocking(
            level_three_cred.clone(),
            pubkeys_obj.reachability_pub.clone(),
        );
        th.advance_days(1);
        th.prep_next_day(
            bucket_info.0,
            bucket_info.1,
            pubkeys_obj.reachability_pub.clone(),
        );

        //Test Check Blockage and get response
        let migration_cred_request = match check_blockage::request(
            rng,
            level_three_cred.clone(),
            pubkeys_obj.migrationkey_pub,
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
        let migration_response_obj: lox_utils::CheckBlockageResponse =
            serde_json::from_str(&migration_resp).unwrap();
        let mig_cred = match check_blockage::handle_response(
            pubkeys_obj.migration_pub,
            migration_cred_request.1,
            migration_response_obj.reply,
            migration_response_obj.enc_mig_table,
        ) {
            Ok(mig_cred) => mig_cred,
            Err(e) => panic!("Error: Migration token error {:?}", e.to_string()),
        };

        // Test Blockage Migration

        let migration_result =
            match blockage_migration::request(rng, level_three_cred.clone(), mig_cred) {
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

        let _new_migrated_cred = match blockage_migration::handle_response(
            migration_result.1,
            new_migration_response_obj,
        ) {
            Ok(new_lox_cred) => new_lox_cred,
            Err(e) => panic!(
                "Error: Blockage migration credential error {:?}",
                e.to_string()
            ),
        };
    }

    fn empty() -> BoxBody<Bytes, Infallible> {
        Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed()
    }
}
