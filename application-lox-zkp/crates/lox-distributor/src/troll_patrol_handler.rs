use crate::{command::Command, lox_context::LoxServerContext};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body::{Body, Bytes},
    header::HeaderValue,
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use std::{convert::Infallible, fmt::Debug, net::SocketAddr};
use tokio::{
    net::TcpListener,
    spawn,
    sync::{broadcast::Receiver, mpsc::Sender, oneshot},
    task::JoinHandle,
};

pub async fn tp_handler(
    tp_port: u16,
    tp_request_tx: Sender<Command>,
    mut kill_tp: Receiver<()>,
) -> JoinHandle<()> {
    // Address for connections from Troll Patrol
    let tp_addr = SocketAddr::from(([127, 0, 0, 1], tp_port));
    let listener = TcpListener::bind(tp_addr).await.expect("failed to bind");

    let tp_svc = move |req| {
        let request_tx = tp_request_tx.clone();
        let (response_tx, response_rx) = oneshot::channel();
        let cmd = Command::TpRequest {
            req,
            sender: response_tx,
        };
        async move {
            if let Err(err) = request_tx.send(cmd).await {
                println!("Error sending http request to troll patrol handler{err:?}");
            }
            response_rx.await.unwrap()
        }
    };

    spawn(async move {
        loop {
            tokio::select! {
                res = listener.accept() => {
                    let (stream, _) = res.expect("Failed to accept");
                    let io = TokioIo::new(stream);
                    let handler = tp_svc.clone();
                    spawn(async move {
                        if let Err(err) = http1::Builder::new().serve_connection(io, service_fn(handler)).await {
                            println!("Error serving connection: {err:?}");
                        }
                    });
                }
                _ = kill_tp.recv() => {
                    println!("Shut down troll patrol handler");
                    break;
                }
            }
        }
    })
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, Infallible> {
    Full::new(chunk.into()).boxed()
}

// Handle for each Troll Patrol request/protocol
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
            // We need a way for simulated users to get the keys to
            // encrypt their negative reports. As Troll Patrol may
            // not be directly accessible when users are submitting
            // negative reports, in practice we expect that these
            // keys will be made available elsewhere.
            //  (&Method::POST, "/nrkey") => {
            //      Ok::<_, Infallible>(cloned_context.send_negative_report_key())
            //  }
            (&Method::POST, "/verifynegative") => Ok::<_, Infallible>({
                let bytes = req.into_body().collect().await.unwrap().to_bytes();
                cloned_context.verify_negative_reports(bytes)
            }),
            _ => {
                // Return 404 not found response.
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
    use base64::{engine::general_purpose, Engine as _};
    use curve25519_dalek::Scalar;
    use lox_library::{
        bridge_table::{self, BridgeLine},
        bridge_verification_info::BridgeVerificationInfo,
        cred::Lox,
        proto::*,
        scalar_u32, BridgeAuth, BridgeDb,
    };
    use lox_zkp::ProofError;
    use rand::RngCore;
    use sha1::{Digest, Sha1};
    use std::{
        collections::{HashMap, HashSet},
        sync::{Arc, Mutex},
    };
    use troll_patrol::{
        negative_report::{
            HashOfBridgeLine, HashOfBucket, NegativeReport, ProofOfBridgeKnowledge,
            SerializableNegativeReport,
        },
        BridgeDistributor,
    };
    type BoxedBody = http_body_util::combinators::BoxBody<bytes::Bytes, Infallible>;

    use super::*;

    trait TpClient<B: Body> {
        fn reportblocked(&self, blocked_bridges: HashMap<String, HashSet<String>>) -> Request<B>;
        fn verifynegative(&self, reports: Vec<SerializableNegativeReport>) -> Request<B>;
    }

    struct TpClientMock {}

    impl TpClient<BoxedBody> for TpClientMock {
        fn reportblocked(
            &self,
            blocked_bridges: HashMap<String, HashSet<String>>,
        ) -> Request<BoxedBody> {
            let req = serde_json::to_string(&blocked_bridges).unwrap();
            Request::builder()
                .method("POST")
                .uri("http://localhost/reportblocked")
                .body(full(req))
                .unwrap()
        }

        fn verifynegative(&self, reports: Vec<SerializableNegativeReport>) -> Request<BoxedBody> {
            let req = serde_json::to_string(&reports).unwrap();
            Request::builder()
                .method("POST")
                .uri("http://localhost/verifynegative")
                .body(full(req))
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
                let bucket = [random(), random(), random()];
                let _ = lox_auth.add_openinv_bridges(bucket, &mut bridgedb);
            }

            // Add hot_spare more hot spare buckets
            for _ in 0..5 {
                let bucket = [random(), random(), random()];
                let _ = lox_auth.add_spare_bucket(bucket, &mut bridgedb);
            }
            // Create the encrypted bridge table
            lox_auth.enc_bridge_table();

            let context = lox_context::LoxServerContext {
                db: Arc::new(Mutex::new(bridgedb)),
                ba: Arc::new(Mutex::new(lox_auth)),
                extra_bridges: Arc::new(Mutex::new(Vec::new())),
                tp_bridge_infos: Arc::new(Mutex::new(
                    HashMap::<String, BridgeVerificationInfo>::new(),
                )),
                metrics: Metrics::default(),
            };
            Self { context }
        }
    }

    pub fn random() -> BridgeLine {
        let mut rng = rand::thread_rng();
        let mut res: BridgeLine = BridgeLine::default();
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
        rng.fill_bytes(&mut res.hashed_fingerprint);
        let mut cert: [u8; 52] = [0; 52];
        rng.fill_bytes(&mut cert);
        let infostr: String = format!(
            "obfs4 cert={}, iat-mode=0",
            general_purpose::STANDARD_NO_PAD.encode(cert)
        );
        res.info[..infostr.len()].copy_from_slice(infostr.as_bytes());
        res
    }

    async fn body_to_string(res: Response<BoxBody<Bytes, Infallible>>) -> String {
        let body_bytes = res.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body_bytes.to_vec()).unwrap()
    }

    async fn get_bucket(
        th: &mut TestHarness,
        cred: &Lox,
    ) -> [BridgeLine; bridge_table::MAX_BRIDGES_PER_BUCKET] {
        let (id, key) = bridge_table::from_scalar(cred.bucket).unwrap();
        let mut ba = th.context.ba.lock().unwrap();
        let encbuckets = ba.enc_bridge_table();
        let bucket =
            bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap())
                .unwrap();
        bucket.0
    }

    async fn get_new_credential(th: &mut TestHarness) -> Lox {
        let inv = th.context.db.lock().unwrap().invite().unwrap();
        let (req, state) = open_invite::request(&inv);
        let resp = th
            .context
            .ba
            .lock()
            .unwrap()
            .handle_open_invite(req)
            .unwrap();
        let (cred, _bridgeline) =
            open_invite::handle_response(state, resp, &th.context.ba.lock().unwrap().lox_pub)
                .unwrap();
        cred
    }

    async fn level_up(th: &mut TestHarness, cred: &Lox) -> Result<Lox, ProofError> {
        let current_level = scalar_u32(&cred.trust_level).unwrap();
        if current_level == 0 {
            th.context
                .advance_days_test(trust_promotion::UNTRUSTED_INTERVAL.try_into().unwrap());
            let mut ba = th.context.ba.lock().unwrap();
            let (promreq, promstate) =
                trust_promotion::request(cred, &ba.lox_pub, ba.today()).unwrap();
            let promresp = ba.handle_trust_promotion(promreq)?;
            let migcred = trust_promotion::handle_response(promstate, promresp)?;
            let (migreq, migstate) =
                migration::request(cred, &migcred, &ba.lox_pub, &ba.migration_pub).unwrap();
            let migresp = ba.handle_migration(migreq)?;
            let new_cred = migration::handle_response(migstate, migresp, &ba.lox_pub).unwrap();
            Ok(new_cred)
        } else {
            th.context.advance_days_test(
                level_up::LEVEL_INTERVAL[usize::try_from(current_level).unwrap()]
                    .try_into()
                    .unwrap(),
            );
            let mut ba = th.context.ba.lock().unwrap();
            let (id, key) = bridge_table::from_scalar(cred.bucket).unwrap();
            let encbuckets = ba.enc_bridge_table();
            let bucket =
                bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap())
                    .unwrap();
            let reachcred = match bucket.1 {
                Some(v) => v,
                None => return Err(ProofError::VerificationFailure),
            };
            //let reachcred = bucket.1.unwrap();
            let (lvreq, lvstate) = level_up::request(
                cred,
                &reachcred,
                &ba.lox_pub,
                &ba.reachability_pub,
                ba.today(),
            )
            .unwrap();
            let lvresp = ba.handle_level_up(lvreq)?;
            let new_cred = level_up::handle_response(lvstate, lvresp, &ba.lox_pub).unwrap();
            Ok(new_cred)
        }
    }

    #[tokio::test]
    async fn test_report_open_entry_blocked_bridge() {
        let mut th = TestHarness::new();
        let tpc = TpClientMock {};

        // helper function to create map of bridges from bucket to mark blocked
        fn bridges_to_block(
            bucket: [BridgeLine; bridge_table::MAX_BRIDGES_PER_BUCKET],
            num_bridges_to_block: usize,
        ) -> HashMap<String, HashSet<String>> {
            let mut blocked_bridges = HashMap::<String, HashSet<String>>::new();
            for i in 0..num_bridges_to_block {
                let mut hasher = Sha1::new();
                hasher.update(bucket[i].hashed_fingerprint);
                let mut countries = HashSet::<String>::new();
                countries.insert("RU".to_string());
                blocked_bridges.insert(array_bytes::bytes2hex("", hasher.finalize()), countries);
            }
            blocked_bridges
        }

        // Get new level 0 credential
        let cred = get_new_credential(&mut th).await;

        th.context.generate_tp_bridge_infos();

        let bridges = get_bucket(&mut th, &cred).await;

        // Block our first (and only) bridge
        let blocked_bridges = bridges_to_block(bridges, 1);
        let request = tpc.reportblocked(blocked_bridges);
        let response = handle(th.context.clone(), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let resp_str = body_to_string(response).await;
        assert_eq!(resp_str, "OK");

        th.context.generate_tp_bridge_infos();

        // We should not be able to migrate to level 1
        assert!(level_up(&mut th, &cred).await.is_err());
    }

    #[tokio::test]
    async fn test_report_trusted_blocked_bridge() {
        let mut th = TestHarness::new();
        let tpc = TpClientMock {};

        // helper function to create map of bridges from bucket to mark blocked
        fn bridges_to_block(
            bucket: [BridgeLine; bridge_table::MAX_BRIDGES_PER_BUCKET],
            num_bridges_to_block: usize,
        ) -> HashMap<String, HashSet<String>> {
            let mut blocked_bridges = HashMap::<String, HashSet<String>>::new();
            for i in 0..num_bridges_to_block {
                let mut hasher = Sha1::new();
                hasher.update(bucket[i].hashed_fingerprint);
                let mut countries = HashSet::<String>::new();
                countries.insert("RU".to_string());
                blocked_bridges.insert(array_bytes::bytes2hex("", hasher.finalize()), countries);
            }
            blocked_bridges
        }

        // Get new level 1 credential
        let cred = get_new_credential(&mut th).await;
        let cred = level_up(&mut th, &cred).await.unwrap();

        th.context.generate_tp_bridge_infos();

        let bridges = get_bucket(&mut th, &cred).await;

        // Block as many bridges as possible without preventing level up
        let blocked_bridges = bridges_to_block(
            bridges,
            bridge_table::MAX_BRIDGES_PER_BUCKET - bridge_table::MIN_BUCKET_REACHABILITY,
        );
        let request = tpc.reportblocked(blocked_bridges);
        let response = handle(th.context.clone(), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let resp_str = body_to_string(response).await;
        assert_eq!(resp_str, "OK");

        th.context.generate_tp_bridge_infos();

        // We should still be able to level up
        let cred = level_up(&mut th, &cred).await.unwrap();

        th.context.generate_tp_bridge_infos();

        let bridges = get_bucket(&mut th, &cred).await;

        // Block enough bridges to prevent level up
        let blocked_bridges = bridges_to_block(
            bridges,
            bridge_table::MAX_BRIDGES_PER_BUCKET - bridge_table::MIN_BUCKET_REACHABILITY + 1,
        );
        let request = tpc.reportblocked(blocked_bridges);
        let response = handle(th.context.clone(), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let resp_str = body_to_string(response).await;
        assert_eq!(resp_str, "OK");

        // We should not be able to level up
        let (id, key) = bridge_table::from_scalar(cred.bucket).unwrap();
        let mut binding = th.context.ba.lock().unwrap();
        binding.advance_days(1);
        let encbuckets = binding.enc_bridge_table();
        let bucket =
            bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap())
                .unwrap();
        drop(binding);
        assert!(bucket.1.is_none());
        assert!(level_up(&mut th, &cred).await.is_err());
    }

    #[tokio::test]
    async fn test_report_both_types_blocked_bridge() {
        let mut th = TestHarness::new();
        let tpc = TpClientMock {};

        // helper function to create map of bridges from bucket to mark blocked
        fn bridges_to_block(
            bucket: [BridgeLine; bridge_table::MAX_BRIDGES_PER_BUCKET],
            num_bridges_to_block: usize,
        ) -> HashMap<String, HashSet<String>> {
            let mut blocked_bridges = HashMap::<String, HashSet<String>>::new();
            for i in 0..num_bridges_to_block {
                let mut hasher = Sha1::new();
                hasher.update(bucket[i].hashed_fingerprint);
                let mut countries = HashSet::<String>::new();
                countries.insert("RU".to_string());
                blocked_bridges.insert(array_bytes::bytes2hex("", hasher.finalize()), countries);
            }
            blocked_bridges
        }

        // Get new level 0 credential
        let cred = get_new_credential(&mut th).await;

        th.context.generate_tp_bridge_infos();

        let bridges = get_bucket(&mut th, &cred).await;

        // Block our first (and only) bridge
        let blocked_bridges = bridges_to_block(bridges, 1);
        let request = tpc.reportblocked(blocked_bridges);
        let response = handle(th.context.clone(), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let resp_str = body_to_string(response).await;
        assert_eq!(resp_str, "OK");

        th.context.generate_tp_bridge_infos();

        // We should not be able to migrate to level 1
        assert!(level_up(&mut th, &cred).await.is_err());

        // Get new level 1 credential
        let cred = get_new_credential(&mut th).await;
        let cred = level_up(&mut th, &cred).await.unwrap();

        th.context.generate_tp_bridge_infos();

        let bridges = get_bucket(&mut th, &cred).await;

        // Block as many bridges as possible in a bucket without preventing level up
        let blocked_bridges = bridges_to_block(
            bridges,
            bridge_table::MAX_BRIDGES_PER_BUCKET - bridge_table::MIN_BUCKET_REACHABILITY,
        );
        let request = tpc.reportblocked(blocked_bridges);
        let response = handle(th.context.clone(), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let resp_str = body_to_string(response).await;
        assert_eq!(resp_str, "OK");

        th.context.generate_tp_bridge_infos();

        // We should still be able to level up
        let cred = level_up(&mut th, &cred).await.unwrap();

        th.context.generate_tp_bridge_infos();

        let bridges = get_bucket(&mut th, &cred).await;

        // Block enough bridges to prevent level up
        let blocked_bridges = bridges_to_block(
            bridges,
            bridge_table::MAX_BRIDGES_PER_BUCKET - bridge_table::MIN_BUCKET_REACHABILITY + 1,
        );
        let request = tpc.reportblocked(blocked_bridges);
        let response = handle(th.context.clone(), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let resp_str = body_to_string(response).await;
        assert_eq!(resp_str, "OK");

        // We should not be able to level up
        let (id, key) = bridge_table::from_scalar(cred.bucket).unwrap();
        let mut binding = th.context.ba.lock().unwrap();
        binding.advance_days(1);
        let encbuckets = binding.enc_bridge_table();
        let bucket =
            bridge_table::BridgeTable::decrypt_bucket(id, &key, encbuckets.get(&id).unwrap())
                .unwrap();
        drop(binding);
        assert!(bucket.1.is_none());
        assert!(level_up(&mut th, &cred).await.is_err());
    }

    #[tokio::test]
    async fn test_negative_reports() {
        let mut th = TestHarness::new();
        let tpc = TpClientMock {};

        // Get new level 1 credential
        let cred = get_new_credential(&mut th).await;
        let cred = level_up(&mut th, &cred).await.unwrap();

        th.context.generate_tp_bridge_infos();

        let bridges = get_bucket(&mut th, &cred).await;

        // Create negative report for each bridge in bucket
        let mut reports = Vec::<SerializableNegativeReport>::new();

        let date = th.context.ba.lock().unwrap().today();

        let report_1 =
            NegativeReport::from_bridgeline(bridges[0], "ru".to_string(), BridgeDistributor::Lox);
        reports.push(report_1.to_serializable_report());

        let report_2 = NegativeReport::from_lox_bucket(
            bridges[1].hashed_fingerprint,
            cred.bucket,
            "ru".to_string(),
        );
        reports.push(report_2.to_serializable_report());

        let report_3 = NegativeReport::from_lox_credential(
            bridges[2].hashed_fingerprint,
            &cred,
            "ru".to_string(),
        );
        reports.push(report_3.to_serializable_report());

        // Check that reports with invalid fields are not counted

        let mut rng = rand::thread_rng();

        // Date in the future
        let mut invalid_report_1 =
            NegativeReport::from_bridgeline(bridges[0], "ru".to_string(), BridgeDistributor::Lox)
                .to_serializable_report();
        invalid_report_1.date = invalid_report_1.date + 2;
        reports.push(invalid_report_1);

        // Invalid country code
        let invalid_report_2 =
            NegativeReport::from_bridgeline(bridges[1], "xx".to_string(), BridgeDistributor::Lox)
                .to_serializable_report();
        reports.push(invalid_report_2);

        // Check that well-formed reports with incorrect bridge data are not counted
        let mut hasher = Sha1::new();
        hasher.update([0; 20]);
        let empty_bridgeline_fingerprint: [u8; 20] = hasher.finalize().into();

        // Unknown bridge fingerprint
        let mut invalid_report_3 =
            NegativeReport::from_bridgeline(bridges[2], "ru".to_string(), BridgeDistributor::Lox);
        invalid_report_3.hashed_fingerprint = empty_bridgeline_fingerprint;
        reports.push(invalid_report_3.to_serializable_report());

        // Incorrect BridgeLine hash
        let mut nonce = [0; 32];
        rng.fill_bytes(&mut nonce);
        let invalid_report_4 = NegativeReport::new(
            bridges[0].hashed_fingerprint,
            ProofOfBridgeKnowledge::HashOfBridgeLine(HashOfBridgeLine::new(
                &BridgeLine::default(),
                date,
                nonce,
            )),
            "ru".to_string(),
            date,
            nonce,
            BridgeDistributor::Lox,
        );
        reports.push(invalid_report_4.to_serializable_report());

        // Incorrect bucket hash
        let mut nonce = [0; 32];
        rng.fill_bytes(&mut nonce);
        let invalid_report_5 = NegativeReport::new(
            bridges[1].hashed_fingerprint,
            ProofOfBridgeKnowledge::HashOfBucket(HashOfBucket::new(&Scalar::ZERO, date, nonce)),
            "ru".to_string(),
            date,
            nonce,
            BridgeDistributor::Lox,
        );
        reports.push(invalid_report_5.to_serializable_report());

        // Ensure each negative report is added successfully
        assert_eq!(reports.len(), 8);

        let request = tpc.verifynegative(reports);
        let response = handle(th.context.clone(), request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let count: u32 = body_to_string(response).await.parse().unwrap();
        assert_eq!(3, count);
    }
}
