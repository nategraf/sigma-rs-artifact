use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ooniauth_core::{ServerState, UserState};
use rand::thread_rng;
use std::hint::black_box;

fn bench_user_request(c: &mut Criterion) {
    let mut rng = thread_rng();
    let server = ServerState::new(&mut rng);
    let user = UserState::new(server.public_parameters());

    c.bench_function("user.request", |b| {
        b.iter(|| user.request(black_box(&mut rng)))
    });
}

fn bench_user_handle_response(c: &mut Criterion) {
    let mut rng = thread_rng();
    let server = ServerState::new(&mut rng);
    let public_params = server.public_parameters();

    c.bench_function("user.handle_response", |b| {
        b.iter_batched(
            || {
                let mut rng = thread_rng();
                let user = UserState::new(public_params.clone());
                let (req, state) = user.request(&mut rng).unwrap();
                let resp = server.open_registration(req).unwrap();
                (user, state, resp)
            },
            |(mut user, state, resp)| {
                user.handle_response(state, resp).unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_user_update_request(c: &mut Criterion) {
    let mut rng = thread_rng();
    let old_server = ServerState::new(&mut rng);
    let public_params = old_server.public_parameters();
    let mut user = UserState::new(public_params);

    let (reg_req, reg_state) = user.request(&mut rng).unwrap();
    let reg_resp = old_server.open_registration(reg_req).unwrap();
    user.handle_response(reg_state, reg_resp).unwrap();

    let new_server = ServerState::new(&mut rng);
    user.pp = new_server.public_parameters();

    c.bench_function("user.update_request", |b| {
        b.iter(|| user.update_request(black_box(&mut rng)))
    });
}

fn bench_user_handle_update_response(c: &mut Criterion) {
    c.bench_function("user.handle_update_response", |b| {
        b.iter_batched(
            || {
                let mut rng = thread_rng();
                let old_server = ServerState::new(&mut rng);
                let mut user = UserState::new(old_server.public_parameters());

                let (reg_req, reg_state) = user.request(&mut rng).unwrap();
                let reg_resp = old_server.open_registration(reg_req).unwrap();
                user.handle_response(reg_state, reg_resp).unwrap();

                let new_server = ServerState::new(&mut rng);
                user.pp = new_server.public_parameters();

                let (update_req, update_state) = user.update_request(&mut rng).unwrap();
                let update_resp = new_server
                    .handle_update(
                        &mut rng,
                        update_req,
                        old_server.secret_key_ref(),
                        old_server.public_parameters_ref(),
                    )
                    .unwrap();

                (user, update_state, update_resp)
            },
            |(mut user, update_state, update_resp)| {
                user.handle_update_response(update_state, update_resp)
                    .unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_user_submit_request(c: &mut Criterion) {
    let mut rng = thread_rng();
    let server = ServerState::new(&mut rng);
    let public_params = server.public_parameters();
    let today = ServerState::today();
    let age_range = (today - 30)..(today + 1);
    let measurement_count_range = 0..100;

    c.bench_function("user.submit_request", |b| {
        b.iter_batched(
            || {
                let mut rng = thread_rng();
                let mut user = UserState::new(public_params.clone());
                let (req, state) = user.request(&mut rng).unwrap();
                let resp = server.open_registration(req).unwrap();
                user.handle_response(state, resp).unwrap();
                (rng, user)
            },
            |(mut rng, user)| {
                user.submit_request(
                    &mut rng,
                    "US".to_string(),
                    "AS1234".to_string(),
                    age_range.clone(),
                    measurement_count_range.clone(),
                )
                .unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_user_handle_submit_response(c: &mut Criterion) {
    let mut rng = thread_rng();
    let server = ServerState::new(&mut rng);
    let public_params = server.public_parameters();
    let today = ServerState::today();
    let age_range = (today - 30)..(today + 1);
    let measurement_count_range = 0..100;

    c.bench_function("user.handle_submit_response", |b| {
        b.iter_batched(
            || {
                let mut rng = thread_rng();
                let mut user = UserState::new(public_params.clone());
                let (req, state) = user.request(&mut rng).unwrap();
                let resp = server.open_registration(req).unwrap();
                user.handle_response(state, resp).unwrap();

                let ((submit_req, submit_state), nym) = user
                    .submit_request(
                        &mut rng,
                        "US".to_string(),
                        "AS1234".to_string(),
                        age_range.clone(),
                        measurement_count_range.clone(),
                    )
                    .unwrap();
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
                    .unwrap();
                (user, submit_state, submit_resp)
            },
            |(mut user, submit_state, submit_resp)| {
                user.handle_submit_response(submit_state, submit_resp)
                    .unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_user_request,
    bench_user_handle_response,
    bench_user_update_request,
    bench_user_handle_update_response,
    bench_user_submit_request,
    bench_user_handle_submit_response
);
criterion_main!(benches);
