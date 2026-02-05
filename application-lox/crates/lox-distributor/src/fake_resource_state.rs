#[cfg(test)]
use crate::resource_parser::ACCEPTED_HOURS_OF_FAILURE;
#[cfg(test)]
use chrono::{Duration, Utc};
#[cfg(test)]
use rand::{Rng, RngCore};
#[cfg(test)]
use rdsys_backend::proto::{Resource, ResourceState, TestResults};
#[cfg(test)]
use std::collections::HashMap;

#[derive(Default)]
#[cfg(test)]
pub struct TestResourceState {
    pub rstate: ResourceState,
}

#[cfg(test)]
impl TestResourceState {
    // Block resources that are working. Targeted blocked regions are specified in bridge_config.json
    pub fn block_working(&mut self) {
        match &mut self.rstate.working {
            Some(resources) => {
                for resource in resources {
                    resource.blocked_in = HashMap::from([
                        ("AS".to_owned(), true),
                        ("IR".to_owned(), false),
                        ("RU".to_owned(), true),
                        ("CN".to_owned(), false),
                        ("SA".to_owned(), false),
                    ]);
                }
            }
            None => {
                panic!("rstate.working Empty")
            }
        }
        assert_ne!(self.rstate.working, None);
    }

    // Add a resource that is working
    pub fn add_working_resource(&mut self) {
        let working_resource = make_resource(
            HashMap::from([
                ("AS".to_owned(), false),
                ("IR".to_owned(), false),
                ("RU".to_owned(), false),
                ("CN".to_owned(), false),
                ("SA".to_owned(), false),
            ]),
            ACCEPTED_HOURS_OF_FAILURE - 12,
        );
        self.add_working_to_rstate(working_resource);
    }

    // Add a not-working resource that has been failing for 1 hour longer than the accepted threshold
    pub fn add_not_working_resource(&mut self) {
        let not_working_resource = make_resource(
            HashMap::from([
                ("AS".to_owned(), false),
                ("IR".to_owned(), false),
                ("RU".to_owned(), false),
                ("CN".to_owned(), false),
                ("SA".to_owned(), false),
            ]),
            ACCEPTED_HOURS_OF_FAILURE + 1,
        );
        self.add_not_working_to_rstate(not_working_resource);
    }

    // Add resource to rstate's working field
    pub fn add_working_to_rstate(&mut self, working_resource: Resource) {
        match &mut self.rstate.working {
            Some(resources) => {
                resources.push(working_resource);
            }
            None => {
                self.rstate.working = Some(vec![working_resource]);
            }
        }
    }

    // Add resource to rstate's not_working field
    pub fn add_not_working_to_rstate(&mut self, not_working_resource: Resource) {
        match &mut self.rstate.not_working {
            Some(resources) => {
                resources.push(not_working_resource);
            }
            None => {
                self.rstate.not_working = Some(vec![not_working_resource]);
            }
        }
    }
}

#[cfg(test)]
pub fn make_resource(blocked_in: HashMap<String, bool>, last_working: i64) -> Resource {
    let mut flags = HashMap::new();
    flags.insert(String::from("fast"), true);
    flags.insert(String::from("stable"), true);
    let mut params = HashMap::new();
    params.insert(
        String::from("password"),
        String::from("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
    );
    Resource {
        r#type: String::from("obfs4"),
        blocked_in,
        test_result: TestResults {
            last_working: Utc::now() - Duration::hours(last_working),
        },
        ip_version: 0,
        address: gen_ip(),
        port: gen_port(),
        fingerprint: gen_fingerprint(),
        or_addresses: None,
        distribution: String::from("https"),
        flags: Some(flags),
        params: Some(params),
    }
}

#[cfg(test)]
pub fn gen_fingerprint() -> String {
    let mut rng = rand::thread_rng();
    let mut fingerprint_array: [u8; 20] = [0; 20];
    rng.fill_bytes(&mut fingerprint_array);
    hex::encode_upper(fingerprint_array)
}

#[cfg(test)]
pub fn gen_port() -> u16 {
    rand::thread_rng().gen_range(0..u16::MAX)
}

#[cfg(test)]
pub fn gen_ip() -> String {
    let i = rand::thread_rng().gen_range(1..u8::MAX);
    let ii = rand::thread_rng().gen_range(1..u8::MAX);
    let iii = rand::thread_rng().gen_range(1..u8::MAX);
    let iv = rand::thread_rng().gen_range(1..u8::MAX);
    format!("{}.{}.{}.{}", i, ii, iii, iv)
}
