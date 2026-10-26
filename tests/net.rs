use ddns_rs::net::{NetMonitor, glob_match, ifaces, is_lan};
use std::net::IpAddr;

#[test]
fn ifaces_names_sorted_and_populated() {
    let v = ifaces();
    assert!(
        v.windows(2).all(|w| w[0].name < w[1].name),
        "网卡应按名称排序"
    );
    assert!(
        v.iter()
            .all(|i| !i.name.is_empty() && (i.v4.is_some() || i.v6.is_some())),
        "每张网卡应有名称且至少一个可用地址"
    );
}

#[cfg(any(target_os = "linux", target_os = "android", windows))]
#[test]
fn net_monitor_registers_platform_notification() {
    assert!(NetMonitor::new().is_ok(), "原生地址事件订阅应注册成功");
}

#[test]
fn lan_check_covers_loopback_private_linklocal() {
    let lan = [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.5",
        "169.254.1.1",
        "::1",
        "fd00::1",
        "fe80::1",
    ];
    let wan = ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"];
    for s in lan {
        assert!(is_lan(s.parse::<IpAddr>().unwrap()), "{s} 应判为局域网");
    }
    for s in wan {
        assert!(!is_lan(s.parse::<IpAddr>().unwrap()), "{s} 应判为公网");
    }
    assert!(is_lan("::ffff:192.168.1.5".parse().unwrap()));
    assert!(!is_lan("::ffff:8.8.8.8".parse().unwrap()));
}

#[test]
fn glob_match_covers_fnmatch_syntax() {
    let hit = |p: &str, s: &str| glob_match(p, s);
    assert!(hit("eth0", "eth0"));
    assert!(!hit("eth0", "eth1"));
    assert!(hit("*", "wlan0"));
    assert!(hit("eth*", "eth0"));
    assert!(hit("*usb", "rndis_usb"));
    assert!(hit("e*h0", "eth0"));
    assert!(hit("eth?", "eth0"));
    assert!(!hit("eth?", "eth10"));
    assert!(hit("usb[0-9]", "usb3"));
    assert!(!hit("usb[0-9]", "usb3x"));
    assert!(hit("[a-z]th0", "eth0"));
    assert!(!hit("usb[!0-9]", "usb1"));
    assert!(hit("usb[!0-9]", "usbx"));
    assert!(hit("eth[01]*", "eth0mock"));
    assert!(!hit("eth*", "wlan0"));
    // POSIX：集合首位的 ] 为字面量；未闭合的 [ 整体按字面量
    assert!(hit("[]]", "]"));
    assert!(!hit("[!]]", "]"));
    assert!(hit("[!]]", "x"));
    assert!(!hit("[!]", "x"));
}
