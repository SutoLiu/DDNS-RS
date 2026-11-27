use ddns_rs::ip::RecordKind;
use ddns_rs::provider::dynv6::params;

const ZONE: &str = "home.example.dynv6.net";

#[test]
fn ipv4_maps_to_ipv4_field_with_full_hostname() {
    // dynv6 的 zone 参数是完整主机名，不是根域+子域
    assert_eq!(
        params(ZONE, "tok", RecordKind::A, "1.2.3.4"),
        [("zone", ZONE), ("token", "tok"), ("ipv4", "1.2.3.4")]
    );
}

#[test]
fn ipv6_maps_to_ipv6_field() {
    assert_eq!(
        params(ZONE, "tok", RecordKind::Aaaa, "2001:db8::1"),
        [("zone", ZONE), ("token", "tok"), ("ipv6", "2001:db8::1")]
    );
}
