use chrono::{offset::Utc, DateTime};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::HashMap;

/// The body of the request for resources made to the rdsys backend
#[derive(Serialize)]
pub struct ResourceRequest {
    pub request_origin: String,
    pub resource_types: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TestResults {
    pub last_working: DateTime<Utc>,
}

/// Representation of a bridge resource
#[derive(Clone, Deserialize, PartialEq, Eq, Debug)]
pub struct Resource {
    pub r#type: String,
    pub blocked_in: HashMap<String, bool>,
    pub test_result: TestResults,
    #[serde(rename = "ip-version")]
    pub ip_version: u16,
    pub address: String,
    pub port: u16,
    pub fingerprint: String,
    #[serde(rename = "or-addresses")]
    pub or_addresses: Option<Vec<String>>,
    pub distribution: String,
    pub flags: Option<HashMap<String, bool>>,
    pub params: Option<HashMap<String, String>>,
}

impl Resource {
    /// get_uid creates a unique identifier of the resource from a hash of the fingerprint
    /// and bridge type. A similar process is used in rdsys
    /// https://gitlab.torproject.org/tpo/anti-censorship/rdsys/-/blob/main/pkg/usecases/resources/bridges.go#L99
    /// however, the golang and rust implementations of crc64 lead to different hash values.
    /// The polynomial used for rust's crc64 package is: https://docs.rs/crc64/2.0.0/src/crc64/lib.rs.html#8
    /// using "Jones" coefficients. Changing go's polynomial to match rust's still doesn't make the hashes the same.
    /// We use the get_uid in this case for an identifier in the distributor so as long as it is unique, it doesn't
    /// strictly need to match the value in rdsys' backend.
    pub fn get_uid(&self) -> Result<u64, hex::FromHexError> {
        let hex_fingerprint = hex::decode(self.fingerprint.clone())?;

        let mut hasher = Sha1::new();
        hasher.update(hex_fingerprint);
        let result_fingerprint = hasher.finalize();
        let uid_string = self.r#type.clone() + &hex::encode_upper(result_fingerprint);

        Ok(crc64::crc64(0, uid_string.as_bytes()))
    }
}

/// A ResourceState holds information about new, changed, or pruned resources
#[derive(Clone, Deserialize, Default, PartialEq, Eq, Debug)]
pub struct ResourceState {
    pub working: Option<Vec<Resource>>,
    pub not_working: Option<Vec<Resource>>,
}

/// A ResourceDiff holds information about new, changed, or pruned resources
#[derive(Deserialize, PartialEq, Eq, Debug)]
pub struct ResourceDiff {
    pub new: Option<HashMap<String, Option<Vec<Resource>>>>,
    pub changed: Option<HashMap<String, Option<Vec<Resource>>>>,
    pub gone: Option<HashMap<String, Option<Vec<Resource>>>>,
    pub full_update: bool,
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    #[test]
    fn serialize_resource_request() {
        let req = ResourceRequest {
            request_origin: String::from("https"),
            resource_types: vec![String::from("obfs2"), String::from("scramblesuit")],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            "{\"request_origin\":\"https\",\"resource_types\":[\"obfs2\",\"scramblesuit\"]}"
        )
    }

    #[test]
    fn deserialize_resource() {
        let mut flags = HashMap::new();
        flags.insert(String::from("fast"), true);
        flags.insert(String::from("stable"), true);
        let mut params = HashMap::new();
        params.insert(
            String::from("password"),
            String::from("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
        );
        let bridge = Resource {
            r#type: String::from("scramblesuit"),
            blocked_in: HashMap::new(),
            test_result: TestResults {
                last_working: "2023-05-30T14:20:28Z".parse::<DateTime<Utc>>().unwrap(),
            },
            ip_version: 0,
            address: String::from("216.117.3.62"),
            port: 63174,
            fingerprint: String::from("BE84A97D02130470A1C77839954392BA979F7EE1"),
            or_addresses: None,
            distribution: String::from("https"),
            flags: Some(flags),
            params: Some(params),
        };

        let data = r#"
            {
                "type": "scramblesuit",
                "blocked_in": {},
                "test_result" : {
                "last_working": "2023-05-30T14:20:28.000+00:00"
                },
                "ip-version": 0,
                "address": "216.117.3.62",
                "port": 63174,
                "fingerprint": "BE84A97D02130470A1C77839954392BA979F7EE1",
                "or-addresses": null,
                "distribution": "https",
                "flags": {
                    "fast": true,
                    "stable": true
                },
                "params": {
                    "password": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
                }
            }"#;
        let res: Resource = serde_json::from_str(data).unwrap();
        assert_eq!(bridge, res);
    }

    #[test]
    fn deserialize_resource_diff() {
        let data = r#"
            {
                "new": {
                    "obfs2": [
                        {
                            "type": "obfs2",
                            "blocked_in": {},
                            "test_result" : {
                            "last_working": "2023-05-30T11:42:28.000+07:00"
                            },
                            "Location": null,
                            "ip-version": 0,
                            "address": "176.247.216.207",
                            "port": 42810,
                            "fingerprint": "10282810115283F99ADE5CFE42D49644F45D715D",
                            "or-addresses": null,
                            "distribution": "https",
                            "flags": {
                                "fast": true,
                                "stable": true,
                                "running": true,
                                "valid": true
                            }
                        },
                        {
                            "type": "obfs2",
                            "blocked_in": {},
                            "test_result" : {
                            "last_working": "2023-05-30T12:20:28.000+07:00"
                            },
                            "ip-version": 0,
                            "address": "133.69.16.145",
                            "port": 58314,
                            "fingerprint": "BE84A97D02130470A1C77839954392BA979F7EE1",
                            "or-addresses": null,
                            "distribution": "https",
                            "flags": {
                                "fast": true,
                                "stable": true,
                                "running": true,
                                "valid": true
                            }
                        }
                    ],
                    "scramblesuit": [
                        {
                            "type": "scramblesuit",
                            "blocked_in": {},
                            "test_result" : {
                            "last_working": "2023-05-30T14:20:28.000+07:00"
                            },
                            "ip-version": 0,
                            "address": "216.117.3.62",
                            "port": 63174,
                            "fingerprint": "BE84A97D02130470A1C77839954392BA979F7EE1",
                            "or-addresses": null,
                            "distribution": "https",
                            "flags": {
                                "fast": true,
                                "stable": true,
                                "running": true,
                                "valid": true
                            },
                            "params": {
                                "password": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
                            }
                        }
                    ]
                },
                "changed": null,
                "gone": null,
                "full_update": true
            }"#;
        let diff: ResourceDiff = serde_json::from_str(data).unwrap();
        assert_ne!(diff.new, None);
        assert_eq!(diff.changed, None);
        assert_eq!(diff.gone, None);
        assert!(diff.full_update);
        if let Some(new) = diff.new {
            if let Some(obfs2) = &new["obfs2"] {
                assert_eq!(obfs2[0].r#type, "obfs2");
            }
        }
    }

    #[test]
    fn deserialize_empty_resource_diff() {
        let data = r#"
            {
                "new": null,
                "changed": null,
                "gone": null,
                "full_update": true
            }"#;
        let diff: ResourceDiff = serde_json::from_str(data).unwrap();
        let empty_diff = ResourceDiff {
            new: None,
            changed: None,
            gone: None,
            full_update: true,
        };
        assert_eq!(diff, empty_diff);
    }

    #[test]
    fn deserialize_empty_condensed_diff() {
        let data = "{\"new\": null,\"changed\": null,\"gone\": null,\"full_update\": true}";
        let diff: ResourceDiff = serde_json::from_str(data).unwrap();
        let empty_diff = ResourceDiff {
            new: None,
            changed: None,
            gone: None,
            full_update: true,
        };
        assert_eq!(diff, empty_diff);
    }

    #[test]
    fn deserialize_empty_hashmap() {
        let data = r#"
            {
                "new": {
                    "obfs4": null,
                    "scramblesuit": []
                },
                "changed": null,
                "gone": null,
                "full_update": true
            }"#;
        let diff: ResourceDiff = serde_json::from_str(data).unwrap();
        assert_ne!(diff.new, None);
        assert_eq!(diff.changed, None);
        assert_eq!(diff.gone, None);
        assert!(diff.full_update);
    }
}
