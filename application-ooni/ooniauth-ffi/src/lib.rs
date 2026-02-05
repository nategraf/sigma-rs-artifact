use std::ffi::{c_char, CString};
use std::sync::Once;
use std::time::Instant;

use ooniauth_core::registration::UserAuthCredential;
use ooniauth_core::{scalar_u32, ServerState, UserState};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

static TRACING_INIT: Once = Once::new();

fn init_tracing() {
    TRACING_INIT.call_once(|| {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        Registry::default()
            .with(env_filter)
            .with(ForestLayer::default())
            .init();
    });
}

fn push_line(log: &mut String, line: &str) {
    log.push_str(line);
    log.push('\n');
}

fn log_credential(log: &mut String, label: &str, cred: &UserAuthCredential) -> Result<(), String> {
    push_line(log, "");
    push_line(log, &format!("   === {label} ==="));

    let nym_id = cred
        .nym_id
        .ok_or_else(|| "missing nym_id in credential".to_string())?;
    let age = cred
        .age
        .ok_or_else(|| "missing age in credential".to_string())?;
    let measurement_count = cred
        .measurement_count
        .ok_or_else(|| "missing measurement_count in credential".to_string())?;

    push_line(
        log,
        &format!("   - nym_id: {}", hex::encode(nym_id.to_bytes())),
    );

    let age_value = scalar_u32(&age).ok_or_else(|| "age is not a u32".to_string())?;
    push_line(log, &format!("   - age: {}", age_value));

    let measurement_value = scalar_u32(&measurement_count)
        .ok_or_else(|| "measurement_count is not a u32".to_string())?;
    push_line(
        log,
        &format!("   - measurement_count: {}", measurement_value),
    );

    Ok(())
}

fn run_basic_usage_demo() -> Result<String, String> {
    init_tracing();
    let mut log = String::new();
    push_line(&mut log, "=== Anonymous Credential Example ===");
    push_line(&mut log, "");

    // Match the flow in ooniauth-core/examples/basic_usage.rs so the iOS app
    // surfaces identical outputs and timings.
    let mut rng = rand::thread_rng();
    push_line(&mut log, "1. Initializing server...");
    let now = Instant::now();
    let server = ServerState::new(&mut rng);
    let public_params = server.public_parameters();
    push_line(
        &mut log,
        &format!(
            "   Key generation completed in {} ms",
            now.elapsed().as_millis()
        ),
    );

    push_line(&mut log, "");
    push_line(&mut log, "2. Initializing user...");
    let now = Instant::now();
    let mut user = UserState::new(public_params);
    push_line(
        &mut log,
        &format!("   User initialized in {} ms", now.elapsed().as_millis()),
    );

    push_line(&mut log, "");
    push_line(&mut log, "3. User registration...");
    let now = Instant::now();
    let (reg_request, reg_state) = user
        .request(&mut rng)
        .map_err(|e| format!("registration request failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   Registration request created in {} ms",
            now.elapsed().as_millis()
        ),
    );

    let request_bytes = reg_request.as_bytes();
    push_line(
        &mut log,
        &format!("   Request size: {} bytes", request_bytes.len()),
    );
    push_line(
        &mut log,
        &format!("   Request payload (hex): {}", hex::encode(&request_bytes)),
    );

    let now = Instant::now();
    let reg_response = server
        .open_registration(reg_request)
        .map_err(|e| format!("registration response failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   Server processed registration in {} ms",
            now.elapsed().as_millis()
        ),
    );

    let response_bytes = reg_response.as_bytes();
    push_line(
        &mut log,
        &format!("   Response size: {} bytes", response_bytes.len()),
    );

    let now = Instant::now();
    user.handle_response(reg_state, reg_response)
        .map_err(|e| format!("registration finalize failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   User handled response in {} ms",
            now.elapsed().as_millis()
        ),
    );

    log_credential(
        &mut log,
        "Initial Credential Attributes",
        user.get_credential()
            .ok_or_else(|| "credential missing after registration".to_string())?,
    )?;

    push_line(&mut log, "");
    push_line(&mut log, "4. Creating anonymous report submission...");
    let probe_cc = "US".to_string();
    let probe_asn = "AS1234".to_string();
    let today = ServerState::today();
    let age_range = (today - 30)..(today + 1);
    let measurement_count_range = 0..100;

    let now = Instant::now();
    let ((submit_request, submit_state), nym) = user
        .submit_request(
            &mut rng,
            probe_cc.clone(),
            probe_asn.clone(),
            age_range.clone(),
            measurement_count_range.clone(),
        )
        .map_err(|e| format!("submit request failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   Submit request created for {probe_cc}/{probe_asn} in {} ms",
            now.elapsed().as_millis()
        ),
    );
    push_line(&mut log, "   Domain-specific pseudonym computed");
    push_line(&mut log, &format!("   NYM (hex): {}", hex::encode(nym)));
    let submit_request_bytes = submit_request.as_bytes();
    push_line(
        &mut log,
        &format!("   Request size: {} bytes", submit_request_bytes.len()),
    );

    let now = Instant::now();
    let submit_response = server
        .handle_submit(
            &mut rng,
            submit_request,
            &nym,
            &probe_cc,
            &probe_asn,
            age_range,
            measurement_count_range,
        )
        .map_err(|e| format!("submit handling failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   Server validated submission and issued updated credential in {} ms",
            now.elapsed().as_millis()
        ),
    );
    let submit_response_bytes = submit_response.as_bytes();
    push_line(
        &mut log,
        &format!("   Response size: {} bytes", submit_response_bytes.len()),
    );
    let now = Instant::now();
    user.handle_submit_response(submit_state, submit_response)
        .map_err(|e| format!("submit finalize failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   User handled submit response in {} ms",
            now.elapsed().as_millis()
        ),
    );

    log_credential(
        &mut log,
        "Updated Credential Attributes",
        user.get_credential()
            .ok_or_else(|| "credential missing after submit".to_string())?,
    )?;

    push_line(&mut log, "");
    push_line(&mut log, "5. Creating second submission...");
    let probe_cc2 = "UK".to_string();
    let probe_asn2 = "AS5678".to_string();

    let age_range2 = (today - 30)..(today + 1);
    let measurement_count_range2 = 0..100;

    let now = Instant::now();
    let ((submit_request2, submit_state2), nym2) = user
        .submit_request(
            &mut rng,
            probe_cc2.clone(),
            probe_asn2.clone(),
            age_range2.clone(),
            measurement_count_range2.clone(),
        )
        .map_err(|e| format!("submit request 2 failed: {e:?}"))?;

    push_line(
        &mut log,
        &format!(
            "   Submit request created for {probe_cc2}/{probe_asn2} in {} ms",
            now.elapsed().as_millis()
        ),
    );
    push_line(&mut log, "   Different domain produces different pseudonym");
    push_line(&mut log, &format!("   NYM (hex): {}", hex::encode(nym2)));

    let now = Instant::now();
    let submit_response2 = server
        .handle_submit(
            &mut rng,
            submit_request2,
            &nym2,
            &probe_cc2,
            &probe_asn2,
            age_range2,
            measurement_count_range2,
        )
        .map_err(|e| format!("submit handling 2 failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   Second submit request handled by server in {} ms",
            now.elapsed().as_millis()
        ),
    );

    let now = Instant::now();
    user.handle_submit_response(submit_state2, submit_response2)
        .map_err(|e| format!("submit finalize 2 failed: {e:?}"))?;
    push_line(
        &mut log,
        &format!(
            "   Second submit response handled by user in {} ms",
            now.elapsed().as_millis()
        ),
    );

    log_credential(
        &mut log,
        "Final Credential Attributes",
        user.get_credential()
            .ok_or_else(|| "credential missing after second submit".to_string())?,
    )?;

    Ok(log)
}

#[derive(Default)]
struct BenchStats {
    samples: usize,
    total_micros: u128,
    min_micros: u128,
    max_micros: u128,
}

impl BenchStats {
    fn add_sample(&mut self, micros: u128) {
        if self.samples == 0 {
            self.min_micros = micros;
            self.max_micros = micros;
        } else {
            self.min_micros = self.min_micros.min(micros);
            self.max_micros = self.max_micros.max(micros);
        }
        self.samples += 1;
        self.total_micros += micros;
    }

    fn avg_micros(&self) -> u128 {
        if self.samples == 0 {
            0
        } else {
            self.total_micros / self.samples as u128
        }
    }
}

fn format_duration(micros: u128) -> String {
    if micros >= 1_000 {
        format!("{:.2} ms", micros as f64 / 1_000.0)
    } else {
        format!("{micros} us")
    }
}

fn push_stats(log: &mut String, label: &str, stats: &BenchStats) {
    let avg = format_duration(stats.avg_micros());
    let min = format_duration(stats.min_micros);
    let max = format_duration(stats.max_micros);
    push_line(log, &format!("  - {label}: avg {avg} (min {min}, max {max})"));
}

fn run_benchmarks() -> Result<String, String> {
    init_tracing();
    let mut log = String::new();
    let iterations: usize = 20;

    push_line(&mut log, "OONI Auth Benchmarks");
    push_line(&mut log, &format!("Iterations: {iterations}"));
    push_line(&mut log, "");

    // Client-side timings (mirrors ooniauth-core/benches/bench_client.rs)
    push_line(&mut log, "Client timings:");

    // user.request
    {
        let mut rng = rand::thread_rng();
        let server = ServerState::new(&mut rng);
        let user = UserState::new(server.public_parameters());
        let mut stats = BenchStats::default();
        for _ in 0..iterations {
            let start = Instant::now();
            user.request(&mut rng)
                .map_err(|e| format!("user.request failed: {e:?}"))?;
            stats.add_sample(start.elapsed().as_micros());
        }
        push_stats(&mut log, "user.request", &stats);
    }

    // user.handle_response
    {
        let mut rng = rand::thread_rng();
        let server = ServerState::new(&mut rng);
        let public_params = server.public_parameters();
        let mut stats = BenchStats::default();
        for _ in 0..iterations {
            let mut rng = rand::thread_rng();
            let mut user = UserState::new(public_params.clone());
            let (req, state) = user
                .request(&mut rng)
                .map_err(|e| format!("user.request failed: {e:?}"))?;
            let resp = server
                .open_registration(req)
                .map_err(|e| format!("server.open_registration failed: {e:?}"))?;
            let start = Instant::now();
            user.handle_response(state, resp)
                .map_err(|e| format!("user.handle_response failed: {e:?}"))?;
            stats.add_sample(start.elapsed().as_micros());
        }
        push_stats(&mut log, "user.handle_response", &stats);
    }

    // user.update_request
    {
        let mut rng = rand::thread_rng();
        let old_server = ServerState::new(&mut rng);
        let public_params = old_server.public_parameters();
        let mut user = UserState::new(public_params);

        let (reg_req, reg_state) = user
            .request(&mut rng)
            .map_err(|e| format!("user.request failed: {e:?}"))?;
        let reg_resp = old_server
            .open_registration(reg_req)
            .map_err(|e| format!("server.open_registration failed: {e:?}"))?;
        user.handle_response(reg_state, reg_resp)
            .map_err(|e| format!("user.handle_response failed: {e:?}"))?;

        let new_server = ServerState::new(&mut rng);
        user.pp = new_server.public_parameters();

        let mut stats = BenchStats::default();
        for _ in 0..iterations {
            let start = Instant::now();
            user.update_request(&mut rng)
                .map_err(|e| format!("user.update_request failed: {e:?}"))?;
            stats.add_sample(start.elapsed().as_micros());
        }
        push_stats(&mut log, "user.update_request", &stats);
    }

    // user.handle_update_response
    {
        let mut stats = BenchStats::default();
        for _ in 0..iterations {
            let mut rng = rand::thread_rng();
            let old_server = ServerState::new(&mut rng);
            let mut user = UserState::new(old_server.public_parameters());

            let (reg_req, reg_state) = user
                .request(&mut rng)
                .map_err(|e| format!("user.request failed: {e:?}"))?;
            let reg_resp = old_server
                .open_registration(reg_req)
                .map_err(|e| format!("server.open_registration failed: {e:?}"))?;
            user.handle_response(reg_state, reg_resp)
                .map_err(|e| format!("user.handle_response failed: {e:?}"))?;

            let new_server = ServerState::new(&mut rng);
            user.pp = new_server.public_parameters();

            let (update_req, update_state) = user
                .update_request(&mut rng)
                .map_err(|e| format!("user.update_request failed: {e:?}"))?;
            let update_resp = new_server
                .handle_update(
                    &mut rng,
                    update_req,
                    old_server.secret_key_ref(),
                    old_server.public_parameters_ref(),
                )
                .map_err(|e| format!("server.handle_update failed: {e:?}"))?;

            let start = Instant::now();
            user.handle_update_response(update_state, update_resp)
                .map_err(|e| format!("user.handle_update_response failed: {e:?}"))?;
            stats.add_sample(start.elapsed().as_micros());
        }
        push_stats(&mut log, "user.handle_update_response", &stats);
    }

    // user.submit_request
    {
        let mut rng = rand::thread_rng();
        let server = ServerState::new(&mut rng);
        let public_params = server.public_parameters();
        let today = ServerState::today();
        let age_range = (today - 30)..(today + 1);
        let measurement_count_range = 0..100;

        let mut stats = BenchStats::default();
        for _ in 0..iterations {
            let mut rng = rand::thread_rng();
            let mut user = UserState::new(public_params.clone());
            let (req, state) = user
                .request(&mut rng)
                .map_err(|e| format!("user.request failed: {e:?}"))?;
            let resp = server
                .open_registration(req)
                .map_err(|e| format!("server.open_registration failed: {e:?}"))?;
            user.handle_response(state, resp)
                .map_err(|e| format!("user.handle_response failed: {e:?}"))?;
            let start = Instant::now();
            user.submit_request(
                &mut rng,
                "US".to_string(),
                "AS1234".to_string(),
                age_range.clone(),
                measurement_count_range.clone(),
            )
            .map_err(|e| format!("user.submit_request failed: {e:?}"))?;
            stats.add_sample(start.elapsed().as_micros());
        }
        push_stats(&mut log, "user.submit_request", &stats);
    }

    // user.handle_submit_response
    {
        let mut rng = rand::thread_rng();
        let server = ServerState::new(&mut rng);
        let public_params = server.public_parameters();
        let today = ServerState::today();
        let age_range = (today - 30)..(today + 1);
        let measurement_count_range = 0..100;

        let mut stats = BenchStats::default();
        for _ in 0..iterations {
            let mut rng = rand::thread_rng();
            let mut user = UserState::new(public_params.clone());
            let (req, state) = user
                .request(&mut rng)
                .map_err(|e| format!("user.request failed: {e:?}"))?;
            let resp = server
                .open_registration(req)
                .map_err(|e| format!("server.open_registration failed: {e:?}"))?;
            user.handle_response(state, resp)
                .map_err(|e| format!("user.handle_response failed: {e:?}"))?;

            let ((submit_req, submit_state), nym) = user
                .submit_request(
                    &mut rng,
                    "US".to_string(),
                    "AS1234".to_string(),
                    age_range.clone(),
                    measurement_count_range.clone(),
                )
                .map_err(|e| format!("user.submit_request failed: {e:?}"))?;

            let submit_resp = server
                .handle_submit(
                    &mut rng,
                    submit_req,
                    &nym,
                    "US",
                    "AS1234",
                    age_range.clone(),
                    measurement_count_range.clone(),
                )
                .map_err(|e| format!("server.handle_submit failed: {e:?}"))?;

            let start = Instant::now();
            user.handle_submit_response(submit_state, submit_resp)
                .map_err(|e| format!("user.handle_submit_response failed: {e:?}"))?;
            stats.add_sample(start.elapsed().as_micros());
        }
        push_stats(&mut log, "user.handle_submit_response", &stats);
    }

    push_line(&mut log, "");

    // Server-side timings (mirrors ooniauth-core/benches/bench_server.rs)
    push_line(&mut log, "Server timings:");

    // server.open_registration
    {
        let mut rng = rand::thread_rng();
        let server = ServerState::new(&mut rng);
        let user = UserState::new(server.public_parameters());
        let (registration_req, _) = user
            .request(&mut rng)
            .map_err(|e| format!("user.request failed: {e:?}"))?;

        let mut stats = BenchStats::default();
        for _ in 0..iterations {
            let req = registration_req.clone();
            let start = Instant::now();
            server
                .open_registration(req)
                .map_err(|e| format!("server.open_registration failed: {e:?}"))?;
            stats.add_sample(start.elapsed().as_micros());
        }
        push_stats(&mut log, "server.open_registration", &stats);
    }

    // server.handle_submit
    {
        let mut rng = rand::thread_rng();
        let server = ServerState::new(&mut rng);
        let mut user = UserState::new(server.public_parameters());

        let (registration_req, reg_state) = user
            .request(&mut rng)
            .map_err(|e| format!("user.request failed: {e:?}"))?;
        let resp = server
            .open_registration(registration_req)
            .map_err(|e| format!("server.open_registration failed: {e:?}"))?;
        user.handle_response(reg_state, resp)
            .map_err(|e| format!("user.handle_response failed: {e:?}"))?;

        let today = ServerState::today();
        let cc = "VE";
        let asn = "AS1234";
        let age_range = (today - 30)..(today + 1);
        let msm_range = 0..100;
        let ((req, _), nym) = user
            .submit_request(
                &mut rng,
                cc.into(),
                asn.into(),
                age_range.clone(),
                msm_range.clone(),
            )
            .map_err(|e| format!("user.submit_request failed: {e:?}"))?;

        let mut stats = BenchStats::default();
        for _ in 0..iterations {
            let start = Instant::now();
            server
                .handle_submit(
                    &mut rng,
                    req.clone(),
                    &nym,
                    cc,
                    asn,
                    age_range.clone(),
                    msm_range.clone(),
                )
                .map_err(|e| format!("server.handle_submit failed: {e:?}"))?;
            stats.add_sample(start.elapsed().as_micros());
        }
        push_stats(&mut log, "server.handle_submit", &stats);
    }

    // server.handle_update
    {
        let mut rng = rand::thread_rng();
        let old_server = ServerState::new(&mut rng);
        let mut user = UserState::new(old_server.public_parameters());

        let (reg_request, reg_state) = user
            .request(&mut rng)
            .map_err(|e| format!("user.request failed: {e:?}"))?;
        let reg_response = old_server
            .open_registration(reg_request)
            .map_err(|e| format!("server.open_registration failed: {e:?}"))?;
        user.handle_response(reg_state, reg_response)
            .map_err(|e| format!("user.handle_response failed: {e:?}"))?;

        let new_server = ServerState::new(&mut rng);
        user.pp = new_server.public_parameters();

        let mut stats = BenchStats::default();
        for _ in 0..iterations {
            let (update_request, _) = user
                .update_request(&mut rng)
                .map_err(|e| format!("user.update_request failed: {e:?}"))?;
            let start = Instant::now();
            new_server
                .handle_update(
                    &mut rng,
                    update_request,
                    old_server.secret_key_ref(),
                    old_server.public_parameters_ref(),
                )
                .map_err(|e| format!("server.handle_update failed: {e:?}"))?;
            stats.add_sample(start.elapsed().as_micros());
        }
        push_stats(&mut log, "server.handle_update", &stats);
    }

    Ok(log)
}

#[no_mangle]
pub extern "C" fn ooniauth_run_basic_usage() -> *mut c_char {
    let output = match run_basic_usage_demo() {
        Ok(log) => log,
        Err(err) => format!("error: {err}"),
    };

    CString::new(output)
        .unwrap_or_else(|_| CString::new("error: output contained nul byte").unwrap())
        .into_raw()
}

#[no_mangle]
pub extern "C" fn ooniauth_run_benchmarks() -> *mut c_char {
    let output = match run_benchmarks() {
        Ok(log) => log,
        Err(err) => format!("error: {err}"),
    };

    CString::new(output)
        .unwrap_or_else(|_| CString::new("error: output contained nul byte").unwrap())
        .into_raw()
}

/// # Safety
/// Caller must pass the pointer returned by `ooniauth_run_basic_usage`.
/// The pointer must be valid, non-null, and freed exactly once.
#[no_mangle]
pub unsafe extern "C" fn ooniauth_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    drop(CString::from_raw(ptr));
}
