use ddns_rs::provider::sign::{
    civil_from_days, hex, hmac_sha256, num, pe, sha256_hex, utc_date, utc_datetime, utc_now,
};

#[test]
fn percent_encode_keeps_unreserved_and_encodes_rest() {
    assert_eq!(pe("a b"), "a%20b");
    assert_eq!(pe("a*b~c-d_e.f"), "a%2Ab~c-d_e.f");
    assert_eq!(pe("/"), "%2F");
}

#[test]
fn sign_primitives_match_standard_vectors() {
    // 标准固定向量：签名基元回归会静默打挂全部调用
    assert_eq!(
        sha256_hex("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&hmac_sha256(b"Jefe", "what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn num_accepts_number_and_string_forms() {
    assert_eq!(num(&serde_json::json!(600)), Some(600));
    assert_eq!(num(&serde_json::json!("600")), Some(600));
    assert_eq!(num(&serde_json::json!("x")), None);
}

#[test]
fn julian_day_converts_to_calendar() {
    assert_eq!(civil_from_days(0), (1970, 1, 1));
    assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    assert_eq!(civil_from_days(20_733), (2026, 10, 7));
}

#[test]
fn timestamp_is_iso8601_utc() {
    let t = utc_now();
    assert_eq!(t.len(), 20, "{t}");
    assert!(t.ends_with('Z') && t.as_bytes()[10] == b'T', "{t}");
    assert_eq!(utc_date().len(), 10);
    assert_eq!(utc_datetime().len(), 16, "{}", utc_datetime());
}
