use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ooniauth_core::{ServerState, UserState};
use rand::{rngs::ThreadRng, thread_rng};
use std::hint::black_box;

fn setup() -> (ThreadRng, UserState, ServerState) {
    let mut rng = thread_rng();
    let server = ServerState::new(&mut rng);
    let pp = server.public_parameters();
    let user = UserState::new(pp);

    (rng, user, server)
}

// For now we will only care about server functions, specially handling submit and
// registration, since those are the most important bottleneck for our backend
fn bench_registration(c: &mut Criterion) {
    let (mut rng, user, server) = setup();

    // Create the request
    let (registration_req, _) = user.request(&mut rng).unwrap();
    c.bench_function("server.open_registration", |b| {
        b.iter(|| server.open_registration(black_box(registration_req.clone())))
    });
}

fn bench_submit(c: &mut Criterion) {
    let (mut rng, mut user, server) = setup();

    c.bench_function("server.handle_submit", |b| {
        let (registration_req, reg_state) = user.request(&mut rng).unwrap();
        let resp = server.open_registration(registration_req).unwrap();
        user.handle_response(reg_state, resp)
            .expect("Should handle response properly");
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
            .unwrap();
        b.iter(|| {
            server.handle_submit(
                black_box(&mut rng),
                black_box(req.clone()),
                black_box(&nym),
                black_box(cc),
                black_box(asn),
                black_box(age_range.clone()),
                black_box(msm_range.clone()),
            )
        })
    });
}

fn bench_update(c: &mut Criterion) {
    let mut rng = thread_rng();
    let old_server = ServerState::new(&mut rng);
    let mut user = UserState::new(old_server.public_parameters());

    let (reg_request, reg_state) = user.request(&mut rng).unwrap();
    let reg_response = old_server.open_registration(reg_request).unwrap();
    user.handle_response(reg_state, reg_response).unwrap();

    let new_server = ServerState::new(&mut rng);
    user.pp = new_server.public_parameters();

    c.bench_function("server.handle_update", |b| {
        b.iter_batched(
            || {
                let mut rng = thread_rng();
                let (update_request, _update_state) = user.update_request(&mut rng).unwrap();
                (rng, update_request)
            },
            |(mut rng, update_request)| {
                new_server
                    .handle_update(
                        &mut rng,
                        update_request,
                        old_server.secret_key_ref(),
                        old_server.public_parameters_ref(),
                    )
                    .unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bench_registration, bench_submit, bench_update);
criterion_main!(benches);
