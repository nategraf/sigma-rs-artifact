use chrono::{Duration, Utc};
use lox_library::bridge_table::{BridgeLine, BRIDGE_BYTES, MAX_BRIDGES_PER_BUCKET};
use rdsys_backend::proto::Resource;

/// Since the last distributed time for a working > non-working resource
/// may be older than the current time by rdsys' expiry time (currently 18 hours): https://gitlab.torproject.org/tpo/anti-censorship/rdsys/-/blob/main/pkg/usecases/resources/bridges.go?ref_type=heads#L176
/// the distributor must use that time to decide on the ACCEPTED_HOURS_OF_FAILURE
pub const RDSYS_EXPIRY: i64 = 18;

/// This value must correspond with rdsys' expiry time
/// and decide on an acceptable grace period for resources that aren't working
/// but may come back (and so shouldn't be replaced)
pub const ACCEPTED_HOURS_OF_FAILURE: i64 = 3 + RDSYS_EXPIRY;

// Parse each resource from rdsys into a Bridgeline as expected by the Lox Bridgetable and return
// Bridgelines as two vectors, those that are marked as blocked in a specified region (indicated in the config file)
// and those that are not blocked.
pub fn parse_into_bridgelines(
    watched_blockages: Vec<String>,
    resources: Vec<Resource>,
) -> (Vec<BridgeLine>, Vec<BridgeLine>) {
    let mut bridgelines: Vec<BridgeLine> = Vec::new();
    let mut blocked_bridgelines: Vec<BridgeLine> = Vec::new();
    for resource in resources {
        if resource.ip_version == 6 {
            continue;
        }
        let mut ip_bytes: [u8; 16] = [0; 16];
        ip_bytes[..resource.address.len()].copy_from_slice(resource.address.as_bytes());
        let resource_uid = resource
            .get_uid()
            .expect("Unable to get Fingerprint UID of resource");
        let infostr: String = format!(
            "type={} fingerprint={:?} params={:?}",
            resource.r#type, resource.fingerprint, resource.params,
        );
        let mut info_bytes: [u8; BRIDGE_BYTES - 26] = [0; BRIDGE_BYTES - 26];

        info_bytes[..infostr.len()].copy_from_slice(infostr.as_bytes());
        let mut blocked = false;
        for watched_blockage in watched_blockages.clone() {
            if let Some(blockage) = resource.blocked_in.get(&watched_blockage) {
                if *blockage {
                    blocked = true;
                    break;
                }
            }
        }
        if blocked {
            blocked_bridgelines.push(BridgeLine {
                addr: ip_bytes,
                port: resource.port,
                uid_fingerprint: resource_uid,
                info: info_bytes,
            });
        } else {
            bridgelines.push(BridgeLine {
                addr: ip_bytes,
                port: resource.port,
                uid_fingerprint: resource_uid,
                info: info_bytes,
            });
        }
    }
    (bridgelines, blocked_bridgelines)
}

// Allocate each Bridgeline into a bucket that will later be allocated into spare buckets or open invitation buckets
// Any leftover buckets from total_bridgelines % MAX_BRIDGES_PER_BUCKET are returned in a separate Vec<Bridgeline>
// TODO: Improve this function to sort bridgelines into buckets in a more intentional manner. This could include
// sorting bridgelines with high bandwidth into buckets that are only distributed to more trusted users or sorting
// bridgelines by location
pub fn parse_into_buckets(
    mut bridgelines: Vec<BridgeLine>,
) -> (Vec<[BridgeLine; MAX_BRIDGES_PER_BUCKET]>, Vec<BridgeLine>) {
    let mut buckets: Vec<[BridgeLine; MAX_BRIDGES_PER_BUCKET]> = Vec::new();
    let mut count = 0;
    let mut bucket = [BridgeLine::default(); MAX_BRIDGES_PER_BUCKET];
    let mut leftovers: Vec<BridgeLine> = Vec::new();
    for bridgeline in bridgelines.clone() {
        println!(
            "Added bridge with fingerprint: {:?}",
            bridgeline.uid_fingerprint
        );
        if count < MAX_BRIDGES_PER_BUCKET {
            bucket[count] = bridgeline;
            count += 1;
        } else {
            buckets.push(bucket);
            bucket = [BridgeLine::default(); MAX_BRIDGES_PER_BUCKET];
            bucket[0] = bridgeline;
            count = 1;
        }
    }
    // Handle the extra buckets that were not allocated already
    if count != 0 {
        for _ in 0..count {
            // Assumes that the unallocated bridgelines will be the last x of the distributed bridgelines
            leftovers.push(bridgelines.pop().unwrap());
        }
    }
    (buckets, leftovers)
}

// Sort Resources into those that are functional, those that are failing based on the last time
// they were passing tests, and those that are blocked in the region(s) specified in the config file.
// Before passing them back to the calling function, they are parsed into BridgeLines
pub fn sort_for_parsing(
    watched_blockages: Vec<String>,
    resources: Vec<Resource>,
) -> (Vec<BridgeLine>, Vec<BridgeLine>, Vec<BridgeLine>) {
    let mut grace_period: Vec<Resource> = Vec::new();
    let mut failing: Vec<Resource> = Vec::new();
    let mut blocked: Vec<BridgeLine> = Vec::new();
    for resource in resources {
        // TODO: Maybe filter for untested resources first if last_working alone would skew
        // the filter in an unintended direction
        if resource.test_result.last_working + Duration::hours(ACCEPTED_HOURS_OF_FAILURE)
            >= Utc::now()
        {
            grace_period.push(resource);
        } else {
            failing.push(resource);
        }
    }
    let (grace_period_bridgelines, mut grace_period_blocked) =
        parse_into_bridgelines(watched_blockages.clone(), grace_period);
    let (failing_bridgelines, mut failing_blocked) =
        parse_into_bridgelines(watched_blockages, failing);
    blocked.append(&mut grace_period_blocked);
    blocked.append(&mut failing_blocked);

    (grace_period_bridgelines, failing_bridgelines, blocked)
}

#[cfg(test)]
mod tests {
    use rdsys_backend::proto::{Resource, TestResults};
    use std::collections::HashMap;

    use chrono::{Duration, Utc};

    use crate::resource_parser::{parse_into_bridgelines, ACCEPTED_HOURS_OF_FAILURE};

    use super::sort_for_parsing;

    pub fn make_resource(
        rtype: String,
        blocked_in: HashMap<String, bool>,
        ip_version: u16,
        address: String,
        port: u16,
        fingerprint: String,
        last_working: i64,
    ) -> Resource {
        let mut flags = HashMap::new();
        flags.insert(String::from("fast"), true);
        flags.insert(String::from("stable"), true);
        let mut params = HashMap::new();
        params.insert(
            String::from("password"),
            String::from("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
        );
        Resource {
            r#type: String::from(rtype),
            blocked_in: blocked_in,
            test_result: TestResults {
                last_working: Utc::now() - Duration::hours(last_working),
            },
            ip_version: ip_version,
            address: String::from(address),
            port: port,
            fingerprint: String::from(fingerprint),
            or_addresses: None,
            distribution: String::from("https"),
            flags: Some(flags),
            params: Some(params),
        }
    }

    pub fn make_ip_resource(ip_version: u16) -> Resource {
        make_resource(
            "scramblesuit".to_owned(),
            HashMap::from([("RU".to_owned(), false)]),
            ip_version,
            "123.456.789.100".to_owned(),
            3002,
            "BE84A97D02130470A1C77839954392BA979F7EE1".to_owned(),
            ACCEPTED_HOURS_OF_FAILURE - 3,
        )
    }

    #[test]
    fn test_sort_for_parsing() {
        let resource_one = make_resource(
            "scramblesuit".to_owned(),
            HashMap::from([
                ("AS".to_owned(), false),
                ("IR".to_owned(), false),
                ("PS".to_owned(), false),
                ("CN".to_owned(), false),
                ("RU".to_owned(), false),
            ]),
            0,
            "123.456.789.100".to_owned(),
            3002,
            "BE84A97D02130470A1C77839954392BA979F7EE1".to_owned(),
            ACCEPTED_HOURS_OF_FAILURE - 1,
        );
        let resource_two = make_resource(
            "https".to_owned(),
            HashMap::from([
                ("AI".to_owned(), false),
                ("AG".to_owned(), false),
                ("BD".to_owned(), false),
                ("BB".to_owned(), false),
                ("RU".to_owned(), false),
            ]),
            0,
            "123.222.333.444".to_owned(),
            6002,
            "C56B9EF202130470A1C77839954392BA979F7FF9".to_owned(),
            ACCEPTED_HOURS_OF_FAILURE + 2,
        );
        let resource_three = make_resource(
            "scramblesuit".to_owned(),
            HashMap::from([
                ("SZ".to_owned(), true),
                ("DO".to_owned(), false),
                ("GN".to_owned(), false),
                ("KR".to_owned(), false),
                ("RU".to_owned(), false),
            ]),
            0,
            "443.288.222.100".to_owned(),
            3042,
            "5E3A8BD902130470A1C77839954392BA979F7B46".to_owned(),
            ACCEPTED_HOURS_OF_FAILURE + 1,
        );
        let resource_four = make_resource(
            "https".to_owned(),
            HashMap::from([
                ("SH".to_owned(), true),
                ("ZA".to_owned(), true),
                ("UM".to_owned(), true),
                ("ZW".to_owned(), true),
                ("SK".to_owned(), true),
            ]),
            0,
            "555.444.212.100".to_owned(),
            8022,
            "FF024DC302130470A1C77839954392BA979F7AE2".to_owned(),
            ACCEPTED_HOURS_OF_FAILURE,
        );
        let resource_five = make_resource(
            "https".to_owned(),
            HashMap::from([
                ("CA".to_owned(), false),
                ("UK".to_owned(), true),
                ("SR".to_owned(), false),
                ("RW".to_owned(), true),
                ("RU".to_owned(), false),
            ]),
            0,
            "234.111.212.100".to_owned(),
            10432,
            "7B4DE14CB2130470A1C77839954392BA979F7AE2".to_owned(),
            1,
        );
        let resource_six = make_resource(
            "https".to_owned(),
            HashMap::from([
                ("CA".to_owned(), false),
                ("UK".to_owned(), false),
                ("SR".to_owned(), false),
                ("RW".to_owned(), false),
                ("RU".to_owned(), true),
            ]),
            0,
            "434.777.212.100".to_owned(),
            10112,
            "7B4DE04A22130470A1C77839954392BA979F7AE2".to_owned(),
            0,
        );
        let resource_seven = make_resource(
            "https".to_owned(),
            HashMap::from([
                ("CA".to_owned(), true),
                ("UK".to_owned(), false),
                ("SR".to_owned(), false),
                ("RW".to_owned(), false),
                ("RU".to_owned(), true),
            ]),
            0,
            "434.777.212.211".to_owned(),
            8112,
            "01E6FA4A22130470A1C77839954392BA979F7AE2".to_owned(),
            5,
        );
        let mut test_vec: Vec<Resource> = Vec::new();
        test_vec.push(resource_one);
        test_vec.push(resource_two);
        test_vec.push(resource_three);
        test_vec.push(resource_four);
        test_vec.push(resource_five);
        test_vec.push(resource_six);
        test_vec.push(resource_seven);
        println!("How many in test? {:?}", test_vec.len());
        let mut watched_blockages: Vec<String> = Vec::new();
        watched_blockages.push("RU".to_string());
        let (functional, failing, blocked) = sort_for_parsing(watched_blockages, test_vec);
        assert!(
            functional.len() == 2,
            "There should be 2 functional bridges"
        );
        assert!(failing.len() == 3, "There should be 3 failing bridges");
        assert!(blocked.len() == 2, "There should be 2 blocked bridges");
    }

    #[test]
    fn test_ip_version() {
        let ip_six_resource = make_ip_resource(6);
        let ip_four_resource = make_ip_resource(4);
        let ip_any_resource = make_ip_resource(0);
        let mut test_vec: Vec<Resource> = Vec::new();
        test_vec.push(ip_six_resource);
        test_vec.push(ip_four_resource);
        test_vec.push(ip_any_resource);
        let watched_blockages: Vec<String> = Vec::new();
        let (functional, blocked) = parse_into_bridgelines(watched_blockages, test_vec);
        assert!(
            functional.len() == 2,
            "There should be 2 functional bridges"
        );
        assert!(blocked.len() == 0, "There should be 0 blocked bridges");
    }
}
