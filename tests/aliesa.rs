use ddns_rs::provider::aliesa::merge_ips;

#[test]
fn merge_ips_replaces_own_family_only() {
    assert_eq!(merge_ips("1.1.1.1", "2.2.2.2", true), "2.2.2.2");
    assert_eq!(merge_ips("1.1.1.1", "2001::1", false), "1.1.1.1,2001::1");
    assert_eq!(
        merge_ips("1.1.1.1,2001::1", "2.2.2.2", true),
        "2.2.2.2,2001::1"
    );
    assert_eq!(
        merge_ips("1.1.1.1,2001::1", "2001::2", false),
        "1.1.1.1,2001::2"
    );
    // 同值合并结果不变，配合调用方比对实现跳过
    assert_eq!(
        merge_ips("1.1.1.1,2001::1", "1.1.1.1", true),
        "1.1.1.1,2001::1"
    );
}
