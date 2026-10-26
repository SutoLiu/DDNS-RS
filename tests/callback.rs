use ddns_rs::ip::RecordKind;
use ddns_rs::provider::Upsert;
use ddns_rs::provider::callback::render;

#[test]
fn ttl_falls_back_to_default_when_unset() {
    let up = |ttl| Upsert {
        zone: "example.com",
        sub: "@",
        fqdn: "example.com",
        kind: RecordKind::A,
        ip: "1.2.3.4",
        ttl,
    };
    assert_eq!(render("#{ttl}", &up(0)), "600");
    assert_eq!(render("#{ttl}", &up(1200)), "1200");
}

#[test]
fn render_substitutes_all_placeholders() {
    // 占位符为前端与用户模板的契约，改动即静默发错请求
    let up = Upsert {
        zone: "example.com",
        sub: "home",
        fqdn: "home.example.com",
        kind: RecordKind::Aaaa,
        ip: "2001::1",
        ttl: 60,
    };
    assert_eq!(
        render("#{ip}|#{domain}|#{recordType}|#{ttl}", &up),
        "2001::1|home.example.com|AAAA|60"
    );
}
