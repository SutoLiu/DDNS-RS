use ddns_rs::engine::{FamilyStatus, State};

#[test]
fn status_json_pins_frontend_contract() {
    // 前端按字段名与小写状态串取值，改动即静默错显
    assert_eq!(
        serde_json::to_string(&FamilyStatus::default()).unwrap(),
        r#"{"ip":"","state":"idle","message":""}"#
    );
    assert_eq!(
        serde_json::to_string(&[State::Ok, State::Err]).unwrap(),
        r#"["ok","err"]"#
    );
}
