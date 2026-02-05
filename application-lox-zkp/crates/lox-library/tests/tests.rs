use lox_library::dup_filter;
use lox_library::dup_filter::SeenType::{Fresh, Seen};
use lox_library::BridgeDb;

use curve25519_dalek::scalar::Scalar;

#[test]
fn test_bridgedb() {
    let mut bdb = BridgeDb::new();
    for i in &[1u32, 5, 7, 12, 19, 20, 22] {
        bdb.insert_openinv(*i);
    }
    let inv = bdb.invite().unwrap();
    println!("{:?}", inv);
    let res = BridgeDb::verify(inv, bdb.pubkey);
    println!("{:?}", res);
}

#[test]
fn test_dup_filter() {
    let mut df1: dup_filter::DupFilter<Scalar> = Default::default();
    let mut df2: dup_filter::DupFilter<Scalar> = Default::default();
    let mut rng = rand::rngs::OsRng;
    let s1 = Scalar::random(&mut rng);
    let s2 = Scalar::random(&mut rng);
    let s3 = Scalar::random(&mut rng);
    let s4 = Scalar::random(&mut rng);
    let s5 = Scalar::random(&mut rng);
    // Check basic behaviour
    assert_eq!(df1.check(&s1), Fresh);
    assert_eq!(df1.filter(&s1), Fresh);
    assert_eq!(df1.check(&s1), Seen);
    assert_eq!(df1.filter(&s1), Seen);
    // Ensure different instances of DupFilter have different tables
    assert_eq!(df2.check(&s1), Fresh);
    assert_eq!(df2.filter(&s1), Fresh);
    assert_eq!(df2.filter(&s1), Seen);
    assert_eq!(df2.check(&s1), Seen);
    // Check multiple ids
    assert_eq!(df1.check(&s2), Fresh);
    assert_eq!(df1.filter(&s3), Fresh);
    assert_eq!(df1.filter(&s4), Fresh);
    assert_eq!(df1.filter(&s3), Seen);
    assert_eq!(df1.check(&s1), Seen);
    assert_eq!(df1.filter(&s1), Seen);
    assert_eq!(df1.filter(&s5), Fresh);
    println!("df1 = {:?}", df1);
    println!("df2 = {:?}", df2);
}
