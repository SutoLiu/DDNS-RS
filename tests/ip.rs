use ddns_rs::config::Source;
use ddns_rs::ip::{RecordKind, Resolver, iface_addr, pick};
use ddns_rs::net::Iface;

fn show(list: &[Iface], pats: &[&str], k: RecordKind) -> Option<String> {
    let p: Vec<String> = pats.iter().map(|x| x.to_string()).collect();
    iface_addr(list, &p, k).map(|i| i.to_string())
}

#[test]
fn iface_addr_falls_back_in_order() {
    let list = vec![
        Iface {
            name: "eth0".into(),
            v4: Some("1.1.1.1".parse().unwrap()),
            v6: None,
        },
        Iface {
            name: "eth1".into(),
            v4: None,
            v6: Some("2001:db8::2".parse().unwrap()),
        },
        Iface {
            name: "wlan0".into(),
            v4: Some("3.3.3.3".parse().unwrap()),
            v6: Some("2001:db8::3".parse().unwrap()),
        },
    ];
    assert_eq!(
        show(&list, &["eth0", "eth1"], RecordKind::Aaaa),
        Some("2001:db8::2".into())
    );
    assert_eq!(
        show(&list, &["eth0", "wlan0"], RecordKind::A),
        Some("1.1.1.1".into())
    );
    assert_eq!(
        show(&list, &["eth1", "wlan0"], RecordKind::A),
        Some("3.3.3.3".into())
    );
    assert_eq!(
        show(&list, &["e?h*"], RecordKind::A),
        Some("1.1.1.1".into())
    );
    assert_eq!(
        show(&list, &["wlan*"], RecordKind::A),
        Some("3.3.3.3".into())
    );
    assert_eq!(
        show(&list, &["usb9", "eth*"], RecordKind::A),
        Some("1.1.1.1".into())
    );
    assert_eq!(show(&list, &[], RecordKind::A), None);
}

#[test]
fn iface_addr_keeps_name_intact() {
    let list = vec![
        Iface {
            name: "以太网".into(),
            v4: Some("1.1.1.1".parse().unwrap()),
            v6: None,
        },
        Iface {
            name: "以太网 2".into(),
            v4: Some("2.2.2.2".parse().unwrap()),
            v6: Some("2001:db8::2".parse().unwrap()),
        },
        Iface {
            name: "虚拟,VPN".into(),
            v4: Some("4.4.4.4".parse().unwrap()),
            v6: None,
        },
    ];
    assert_eq!(
        show(&list, &["以太网 2"], RecordKind::A),
        Some("2.2.2.2".into())
    );
    assert_eq!(
        show(&list, &["以太网 2"], RecordKind::Aaaa),
        Some("2001:db8::2".into())
    );
    assert_eq!(
        show(&list, &["虚拟,VPN"], RecordKind::A),
        Some("4.4.4.4".into())
    );
    assert_eq!(
        show(&list, &["以太网", "以太网 2"], RecordKind::A),
        Some("1.1.1.1".into())
    );
    assert_eq!(
        show(&list, &["以太网", "以太网 2"], RecordKind::Aaaa),
        Some("2001:db8::2".into())
    );
}

#[test]
fn picks_address_of_requested_family() {
    assert_eq!(
        pick("1.2.3.4\n", RecordKind::A).map(|i| i.to_string()),
        Some("1.2.3.4".into())
    );
    assert_eq!(
        pick("Your IP: 2400:cb00::1 ok", RecordKind::Aaaa).map(|i| i.to_string()),
        Some("2400:cb00::1".into())
    );
    assert_eq!(
        pick("ip is 1.2.3.4.", RecordKind::A).map(|i| i.to_string()),
        Some("1.2.3.4".into())
    );
    assert_eq!(
        pick("addr=2400:cb00::1.2.3.4", RecordKind::Aaaa).map(|i| i.to_string()),
        Some("2400:cb00::102:304".into())
    );
    assert!(pick("addr=::ffff:1.2.3.4", RecordKind::Aaaa).is_none());
    assert_eq!(
        pick("addr=::ffff:1.2.3.4", RecordKind::A).map(|i| i.to_string()),
        Some("1.2.3.4".into())
    );
}

#[test]
fn ignores_text_without_matching_address() {
    assert!(pick("no address here", RecordKind::A).is_none());
    assert!(pick("2400:cb00::1", RecordKind::A).is_none());
}

#[tokio::test]
async fn resolve_falls_back_across_blocks_in_order() {
    let client = reqwest::Client::new();
    let mut res = Resolver::new(&[]);
    let cmd = |c: &str| Source::Cmd { cmd: c.into() };
    let kind = RecordKind::A;
    assert_eq!(
        res.resolve(&client, &[cmd("echo 1.2.3.4"), cmd("echo 5.6.7.8")], kind)
            .await
            .map(|i| i.to_string()),
        Some("1.2.3.4".into())
    );
    assert_eq!(
        res.resolve(&client, &[cmd("echo none"), cmd("echo 5.6.7.8")], kind)
            .await
            .map(|i| i.to_string()),
        Some("5.6.7.8".into())
    );
    assert_eq!(
        res.resolve(
            &client,
            &[cmd("echo x"), cmd("echo y"), cmd("echo 9.9.9.9")],
            kind
        )
        .await
        .map(|i| i.to_string()),
        Some("9.9.9.9".into())
    );
    assert!(
        res.resolve(&client, &[cmd("echo x"), cmd("exit 1")], kind)
            .await
            .is_none()
    );
    assert!(res.resolve(&client, &[], kind).await.is_none());
}

#[tokio::test]
async fn same_source_resolves_once_per_round() {
    // 同轮同源只执行一次，结果（含未命中）同轮共享
    let f = std::env::temp_dir().join("ddns-resolve-once.txt");
    let _ = std::fs::remove_file(&f);
    let src = vec![Source::Cmd {
        cmd: format!("echo 1.2.3.4; echo x >> '{}'", f.display()),
    }];
    let mut res = Resolver::new(&[]);
    let client = reqwest::Client::new();
    let a = res.resolve(&client, &src, RecordKind::A).await;
    let b = res.resolve(&client, &src, RecordKind::A).await;
    assert_eq!(a.map(|i| i.to_string()), Some("1.2.3.4".into()));
    assert_eq!(b, a);
    // 按字节计数：PowerShell 重定向写 UTF-16，文本读取不可靠
    let n = std::fs::read(&f)
        .unwrap()
        .iter()
        .filter(|&&b| b == b'x')
        .count();
    assert_eq!(n, 1, "同源仅执行一次");
}

#[tokio::test]
async fn net_interface_resolves_from_shared_snapshot() {
    let client = reqwest::Client::new();
    let ifaces = vec![Iface {
        name: "eth0".into(),
        v4: Some("1.1.1.1".parse().unwrap()),
        v6: None,
    }];
    let src = vec![Source::NetInterface {
        name: vec!["eth*".into()],
    }];
    assert_eq!(
        Resolver::new(&ifaces)
            .resolve(&client, &src, RecordKind::A)
            .await
            .map(|i| i.to_string()),
        Some("1.1.1.1".into())
    );
}
