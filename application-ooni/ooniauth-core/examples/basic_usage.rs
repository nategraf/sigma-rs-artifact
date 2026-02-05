use std::time::Instant;

use ooniauth_core::{scalar_u32, ServerState, UserState};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing with forest layer for runtime display
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();
    let mut rng = rand::thread_rng();

    println!("=== Anonymous Credential Example ===\n");

    // 1. Server initialization
    let now = Instant::now();
    println!("1. Initializing server...");
    let server = ServerState::new(&mut rng);
    let public_params = server.public_parameters();
    println!(
        "   Key generation completed in {} ms",
        now.elapsed().as_millis()
    );

    // 2. User initialization
    let now = Instant::now();
    println!("\n2. Initializing user...");
    let mut user = UserState::new(public_params);
    println!("   User initialized in {} ms", now.elapsed().as_millis());

    // 3. Registration: User requests initial credential
    let now = Instant::now();
    println!("\n3. User registration...");
    let (reg_request, reg_state) = user.request(&mut rng)?;
    println!(
        "   Registration request created in {} ms",
        now.elapsed().as_millis()
    );

    // Convert request to bytes for transmission
    let request_bytes = reg_request.as_bytes();
    println!("   Request size: {} bytes", request_bytes.len());
    println!("   Request payload (hex): {}", hex::encode(&request_bytes));

    // Server processes registration
    let now = Instant::now();
    let reg_response = server.open_registration(reg_request)?;
    println!(
        "   Server processed registration in {} ms",
        now.elapsed().as_millis()
    );

    // Convert response to bytes for transmission
    let response_bytes = reg_response.as_bytes();
    println!("   Response size: {} bytes", response_bytes.len());

    // User receives credential
    let now = Instant::now();
    user.handle_response(reg_state, reg_response)?;
    println!(
        "   User handled response in {} ms",
        now.elapsed().as_millis()
    );

    // Print initial credential attributes
    println!("\n   === Initial Credential Attributes ===");
    if let Some(cred) = user.get_credential() {
        println!(
            "   - nym_id: {} (kept secret by user)",
            hex::encode(cred.nym_id.unwrap().to_bytes())
        );
        println!(
            "   - age: {} (days since epoch)",
            scalar_u32(&cred.age.unwrap()).unwrap()
        );
        println!(
            "   - measurement_count: {}",
            scalar_u32(&cred.measurement_count.unwrap()).unwrap()
        );
    }

    // 4. Submit: User creates anonymous report
    println!("\n4. Creating anonymous report submission...");
    let probe_cc = "US".to_string();
    let probe_asn = "AS1234".to_string();

    // Set valid age range (credential valid for 30 days)
    let today = ServerState::today();
    let age_range = (today - 30)..(today + 1);
    let measurement_count_range = 0..100;

    let now = Instant::now();
    let ((submit_request, submit_state), nym) = user.submit_request(
        &mut rng,
        probe_cc.clone(),
        probe_asn.clone(),
        age_range.clone(),
        measurement_count_range.clone(),
    )?;

    println!(
        "   Submit request created for {}/{} in {} ms",
        probe_cc,
        probe_asn,
        now.elapsed().as_millis()
    );
    println!("   Domain-specific pseudonym computed");

    // Show the NYM as hex
    println!("   NYM (hex): {}", hex::encode(nym));

    // Convert to bytes
    let submit_request_bytes = submit_request.as_bytes();
    println!("   Request size: {} bytes", submit_request_bytes.len());

    // Server processes submission
    let now = Instant::now();
    let submit_response = server.handle_submit(
        &mut rng,
        submit_request,
        &nym,
        &probe_cc,
        &probe_asn,
        age_range,
        measurement_count_range,
    )?;
    println!(
        "   Server validated submission and issued updated credential in {} ms",
        now.elapsed().as_millis()
    );

    // Convert response to bytes
    let submit_response_bytes = submit_response.as_bytes();
    println!("   Response size: {} bytes", submit_response_bytes.len());

    // User receives updated credential

    let now = Instant::now();
    user.handle_submit_response(submit_state, submit_response)?;
    println!(
        "  User handled submit response in {} ms",
        now.elapsed().as_millis()
    );

    // Print updated credential attributes
    println!("\n   === Updated Credential Attributes ===");
    if let Some(cred) = user.get_credential() {
        println!(
            "   - nym_id: {} (unchanged)",
            hex::encode(cred.nym_id.unwrap().to_bytes())
        );
        println!(
            "   - age: {} (unchanged)",
            scalar_u32(&cred.age.unwrap()).unwrap()
        );
        println!(
            "   - measurement_count: {} (incremented)",
            scalar_u32(&cred.measurement_count.unwrap()).unwrap()
        );
    }

    // 5. Demonstrate multiple submissions
    println!("\n5. Creating second submission...");
    let probe_cc2 = "UK".to_string();
    let probe_asn2 = "AS5678".to_string();

    let age_range2 = (today - 30)..(today + 1);
    let measurement_count_range2 = 0..100;

    let now = Instant::now();
    let ((submit_request2, submit_state2), nym2) = user.submit_request(
        &mut rng,
        probe_cc2.clone(),
        probe_asn2.clone(),
        age_range2.clone(),
        measurement_count_range2.clone(),
    )?;

    println!(
        "   Submit request created for {}/{} in {} ms",
        probe_cc2,
        probe_asn2,
        now.elapsed().as_millis()
    );
    println!("   Different domain produces different pseudonym");

    // Show the second NYM as hex
    println!("   NYM (hex): {}", hex::encode(nym2));

    let now = Instant::now();
    let submit_response2 = server.handle_submit(
        &mut rng,
        submit_request2,
        &nym2,
        &probe_cc2,
        &probe_asn2,
        age_range2,
        measurement_count_range2,
    )?;
    println!(
        "   Second submit request handled by server in {} ms",
        now.elapsed().as_millis()
    );

    let now = Instant::now();
    user.handle_submit_response(submit_state2, submit_response2)?;
    println!(
        "   Second submit response handled by user in {} ms",
        now.elapsed().as_millis()
    );

    // Print final credential attributes
    println!("\n   === Final Credential Attributes ===");
    if let Some(cred) = user.get_credential() {
        println!(
            "   - nym_id: {} (unchanged)",
            hex::encode(cred.nym_id.unwrap().to_bytes())
        );
        println!(
            "   - age: {} (unchanged)",
            scalar_u32(&cred.age.unwrap()).unwrap()
        );
        println!(
            "   - measurement_count: {} (incremented again)",
            scalar_u32(&cred.measurement_count.unwrap()).unwrap()
        );
    }

    Ok(())
}
