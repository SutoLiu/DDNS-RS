use ddns_rs::config::{Config, Entry, Family, Mode, Provider, Source};

fn entry(zone: &str, subs: &str) -> Entry {
    Entry {
        zone: zone.into(),
        sub_domains: subs.into(),
        ipv4: Family {
            enabled: true,
            sources: vec![Source::Url {
                url: vec!["https://ipv4.icanhazip.com".into()],
            }],
        },
        provider: Provider::Cloudflare {
            token: "t".into(),
            proxied: false,
        },
        ..Default::default()
    }
}

fn secret_val(c: &Config, i: usize, key: &str) -> String {
    serde_json::to_value(&c.entries[i].provider).unwrap()[key]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn sub_domains_expand_and_dedup() {
    let e = entry("example.com", "home, vpn home");
    assert_eq!(e.subs(), vec!["home", "vpn"]);
    assert_eq!(e.fqdn("home"), "home.example.com");
    let root = entry("example.com", "");
    assert_eq!(root.subs(), vec!["@"]);
    assert_eq!(root.fqdn("@"), "example.com");
}

#[test]
fn validate_rejects_incomplete_entry() {
    let mut e = entry("example.com", "home");
    e.provider = Provider::Cloudflare {
        token: "  ".into(),
        proxied: false,
    };
    assert!(e.validate().is_err());
    let mut e2 = entry("example.com", "home");
    e2.ipv4.enabled = false;
    assert!(e2.validate().is_err());
}

#[test]
fn config_roundtrips_through_json() {
    let cfg = Config {
        entries: vec![entry("example.com", "home")],
        ..Default::default()
    };
    let text = serde_json::to_string(&cfg).unwrap();
    let back: Config = serde_json::from_str(&text).unwrap();
    assert_eq!(back.entries[0].provider.kind(), "cloudflare");
    assert_eq!(back.entries[0].mode, Mode::Poll);
    assert_eq!(back.entries[0].interval, 300);
}

#[test]
fn defaults_are_safe() {
    let d = Config::default();
    assert!(!d.not_allow_wan, "禁止公网访问应默认关闭");
    assert!(d.pwd_hash.is_empty(), "默认不含密码，需首次初始化");
    assert_eq!(d.site_title, "DDNS-RS", "站点标题默认为产品名");
}

#[test]
fn provider_variants_roundtrip_and_check_credentials() {
    let samples = [
        r#"{"type":"cloudflare","token":"t"}"#,
        r#"{"type":"aliyun","access_key_id":"a","access_key_secret":"b"}"#,
        r#"{"type":"aliesa","access_key_id":"a","access_key_secret":"b"}"#,
        r#"{"type":"tencent","secret_id":"a","secret_key":"b"}"#,
        r#"{"type":"dnspod","id":"1","token":"t"}"#,
        r#"{"type":"huawei","access_key_id":"a","secret_key":"b"}"#,
        r#"{"type":"baidu","access_key_id":"a","secret_key":"b"}"#,
        r#"{"type":"volcengine","access_key_id":"a","secret_key":"b"}"#,
        r#"{"type":"porkbun","apikey":"a","secretapikey":"b"}"#,
        r#"{"type":"godaddy","key":"a","secret":"b"}"#,
        r#"{"type":"namecheap","password":"p"}"#,
        r#"{"type":"callback","url":"https://x"}"#,
    ];
    for s in samples {
        let v: serde_json::Value = serde_json::from_str(s).unwrap();
        let tag = v["type"].as_str().unwrap().to_string();
        let p: Provider = serde_json::from_value(v).unwrap();
        assert_eq!(p.kind(), tag, "{s}");
        assert!(p.missing().is_empty(), "完整凭据不应报缺失: {s}");
        let out = serde_json::to_string(&p).unwrap();
        assert!(out.contains(&format!("\"type\":\"{tag}\"")), "{out}");
    }
    let blanks = [
        r#"{"type":"cloudflare","token":"  ","proxied":false}"#,
        r#"{"type":"aliyun","access_key_id":"","access_key_secret":"b"}"#,
        r#"{"type":"aliesa","access_key_id":"a","access_key_secret":""}"#,
        r#"{"type":"tencent","secret_id":" ","secret_key":"b"}"#,
        r#"{"type":"dnspod","id":"","token":""}"#,
        r#"{"type":"huawei","access_key_id":"a","secret_key":" "}"#,
        r#"{"type":"baidu","access_key_id":"","secret_key":""}"#,
        r#"{"type":"volcengine","access_key_id":"a","secret_key":" "}"#,
        r#"{"type":"porkbun","apikey":"","secretapikey":"b"}"#,
        r#"{"type":"godaddy","key":"","secret":""}"#,
        r#"{"type":"namecheap","password":" "}"#,
        r#"{"type":"callback","url":""}"#,
    ];
    for s in blanks {
        let p: Provider = serde_json::from_str(s).unwrap();
        assert!(!p.missing().is_empty(), "应检出凭据缺失: {s}");
    }
    let e: Entry = serde_json::from_str(
        r#"{"zone":"example.com","ipv4":{"enabled":true,"sources":[{"type":"url","url":["u"]}]}}"#,
    )
    .unwrap();
    assert_eq!(e.provider.kind(), "aliyun");
}

#[test]
fn missing_credential_error_names_provider() {
    // 错误信息须带服务商标识与全部缺失字段
    let mut e = entry("example.com", "home");
    e.provider = Provider::Aliyun {
        access_key_id: "".into(),
        access_key_secret: "".into(),
    };
    let err = e.validate().unwrap_err().to_string();
    assert!(
        err.contains("缺少阿里云 AccessKey ID、AccessKey Secret"),
        "{err}"
    );
    e.provider = Provider::Cloudflare {
        token: "".into(),
        proxied: false,
    };
    let err = e.validate().unwrap_err().to_string();
    assert!(err.contains("缺少 Cloudflare API Token"), "{err}");
    e.provider = Provider::Callback {
        url: "".into(),
        body: "".into(),
    };
    let err = e.validate().unwrap_err().to_string();
    assert!(err.contains("缺少 Callback URL"), "{err}");
}

#[test]
fn callback_is_notify_only() {
    // 纯通知型契约：漏登记即恢复重复推送
    assert!(
        Provider::Callback {
            url: "u".into(),
            body: "".into()
        }
        .notify_only()
    );
    assert!(
        !Provider::Cloudflare {
            token: "t".into(),
            proxied: false
        }
        .notify_only()
    );
}

#[test]
fn namecheap_rejects_ipv6() {
    let mut e = entry("example.com", "home");
    e.provider = Provider::Namecheap {
        password: "p".into(),
    };
    assert!(e.validate().is_ok(), "仅 IPv4 时应通过");
    // IPv6 须带有效来源，防被空来源校验抢先报错
    e.ipv6 = Family {
        enabled: true,
        sources: vec![Source::Url {
            url: vec!["https://ipv6.icanhazip.com".into()],
        }],
    };
    let err = e.validate().unwrap_err().to_string();
    assert!(
        err.contains("Namecheap"),
        "应命中 Namecheap IPv6 拦截: {err}"
    );
}

#[test]
fn validate_rejects_zero_port() {
    let mut cfg = Config {
        port: 0,
        token_ttl: 0,
        ..Default::default()
    };
    assert!(cfg.validate().is_err(), "端口 0 应被拒绝");
    assert_eq!(cfg.token_ttl, 60, "校验失败亦须完成独立归一");
}

#[test]
fn lang_normalizes_to_supported() {
    let mut cfg = Config {
        lang: "fr".into(),
        ..Default::default()
    };
    cfg.validate().unwrap();
    assert_eq!(cfg.lang, "zh-cn", "非法语言应回退默认");
    cfg.lang = "en".into();
    cfg.validate().unwrap();
    assert_eq!(cfg.lang, "en", "合法语言应保留");
}

#[test]
fn log_cap_normalizes_to_range() {
    let mut cfg = Config {
        log_cap: 0,
        ..Default::default()
    };
    cfg.validate().unwrap();
    assert_eq!(cfg.log_cap, 50, "越界条数应回退默认");
    cfg.log_cap = 1000;
    cfg.validate().unwrap();
    assert_eq!(cfg.log_cap, 1000, "合法条数应保留");
}

#[test]
fn token_ttl_defaults_and_clamps_floor_only() {
    assert_eq!(Config::default().token_ttl, 1800);
    let cfg: Config = serde_json::from_str(r#"{"entries":[]}"#).unwrap();
    assert_eq!(cfg.token_ttl, 1800);
    let mut cfg = Config {
        token_ttl: 0,
        ..Default::default()
    };
    cfg.validate().unwrap();
    assert_eq!(cfg.token_ttl, 60);
    let mut cfg = Config {
        token_ttl: 31_536_000,
        ..Default::default()
    };
    cfg.validate().unwrap();
    assert_eq!(cfg.token_ttl, 31_536_000);
}

#[test]
fn netinterface_name_keeps_full_items() {
    let cfg: Config = serde_json::from_str(
        r#"{"entries":[{"zone":"a.com","watch":["虚拟,VPN"],"ipv4":{"enabled":true,"sources":[{"type":"netInterface","name":["虚拟,VPN","以太网 2"]}]},"provider":{"type":"cloudflare","token":"t"}}]}"#,
    )
    .unwrap();
    assert_eq!(cfg.entries[0].watch, vec!["虚拟,VPN"]);
    let Source::NetInterface { name } = &cfg.entries[0].ipv4.sources[0] else {
        panic!()
    };
    assert_eq!(name, &vec!["虚拟,VPN".to_string(), "以太网 2".to_string()]);
}

#[test]
fn validate_rejects_bad_poll_interval() {
    let mut e = entry("example.com", "home");
    e.interval = 5;
    assert!(e.validate().is_err(), "轮询模式间隔下限为 10 秒");
    e.mode = Mode::Listen;
    assert!(e.validate().is_ok());
}

#[test]
fn entry_omitted_fields_get_defaults() {
    let e: Entry = serde_json::from_str(
        r#"{"zone":"example.com","ipv4":{"enabled":true,"sources":[{"type":"url","url":["u"]}]}}"#,
    )
    .unwrap();
    assert!(e.enabled);
    assert_eq!(e.mode, Mode::Poll);
    assert_eq!(e.interval, 300);
}

#[tokio::test]
async fn replace_keeps_disk_pwd_hash() {
    // 口令散列以落盘为准：Web 传入值不生效
    let dir = std::env::temp_dir().join("ddns-pwd-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    let _ = std::fs::remove_file(&path);
    let store = ddns_rs::config::ConfigStore::new(Config::default(), path.clone());
    store.init_pwd_hash("h1".into()).await.unwrap();
    let mut cfg = (*store.get().await).clone();
    cfg.pwd_hash = "evil".into();
    store.replace(cfg).await.unwrap();
    assert_eq!(store.pwd_hash().await.unwrap(), "h1");
    assert_eq!(Config::load(&path).await.unwrap().pwd_hash, "h1");
    store.set_pwd_hash("h2".into()).await.unwrap();
    assert_eq!(store.pwd_hash().await.unwrap(), "h2");
}

#[tokio::test]
async fn reset_pwd_hash_takes_effect_live() {
    // CLI 重置不停服即时生效，Web 保存不得回滚
    let dir = std::env::temp_dir().join("ddns-pwd-live");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    let _ = std::fs::remove_file(&path);
    let store = ddns_rs::config::ConfigStore::new(Config::default(), path.clone());
    assert!(
        store.pwd_hash().await.unwrap().is_empty(),
        "无落盘文件且内存无口令即未初始化"
    );
    store.init_pwd_hash("h1".into()).await.unwrap();
    Config::reset_pwd_hash(&path, "cli").await.unwrap();
    assert_eq!(
        store.pwd_hash().await.unwrap(),
        "cli",
        "无需重启即读到新口令"
    );
    let mut cfg = (*store.get().await).clone();
    cfg.pwd_hash = "evil".into();
    store.replace(cfg).await.unwrap();
    assert_eq!(store.pwd_hash().await.unwrap(), "cli", "保存不得回滚口令");
}

#[tokio::test]
async fn init_pwd_hash_only_when_empty() {
    let dir = std::env::temp_dir().join("ddns-init-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    let _ = std::fs::remove_file(&path);
    let store = ddns_rs::config::ConfigStore::new(Config::default(), path.clone());
    assert!(store.init_pwd_hash("h1".into()).await.unwrap());
    assert!(!store.init_pwd_hash("h2".into()).await.unwrap());
    assert_eq!(store.get().await.pwd_hash, "h1");
    assert_eq!(Config::load(&path).await.unwrap().pwd_hash, "h1");
}

#[tokio::test]
async fn reset_pwd_hash_keeps_valid_config() {
    let dir = std::env::temp_dir().join("ddns-reset-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    let cfg = Config {
        pwd_hash: "old".into(),
        entries: vec![entry("example.com", "home")],
        ..Default::default()
    };
    let store = ddns_rs::config::ConfigStore::new(cfg.clone(), path.clone());
    store.replace(cfg).await.unwrap();
    Config::reset_pwd_hash(&path, "new-hash").await.unwrap();
    let back = Config::load(&path).await.unwrap();
    assert_eq!(back.pwd_hash, "new-hash");
    assert_eq!(back.entries.len(), 1);
    assert_eq!(back.entries[0].zone, "example.com");
}

#[tokio::test]
async fn reset_pwd_hash_rejects_broken_json() {
    // 损坏配置拒绝重置，原文件不得被覆盖
    let dir = std::env::temp_dir().join("ddns-reset-broken");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("broken.json");
    std::fs::write(&path, "not json").unwrap();
    assert!(Config::reset_pwd_hash(&path, "h").await.is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "not json");
}

#[tokio::test]
async fn reset_pwd_hash_preserves_unknown_fields() {
    // JSON 局部更新只改口令，任务与未知字段原样保留
    let dir = std::env::temp_dir().join("ddns-reset-unknown");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    let _ = std::fs::remove_file(&path);
    let cfg = Config {
        pwd_hash: "old".into(),
        entries: vec![entry("example.com", "home")],
        ..Default::default()
    };
    ddns_rs::config::ConfigStore::new(cfg.clone(), path.clone())
        .replace(cfg)
        .await
        .unwrap();
    let mut doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    doc["future"] = serde_json::json!("keep");
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    Config::reset_pwd_hash(&path, "new").await.unwrap();
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(doc["pwd_hash"], "new");
    assert_eq!(doc["future"], "keep");
    assert_eq!(doc["entries"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn missing_file_falls_back_to_memory_hash() {
    // 文件缺失时口令回退内存值，Web 保存不得写空
    let dir = std::env::temp_dir().join("ddns-pwd-fallback");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gone.json");
    let _ = std::fs::remove_file(&path);
    let cfg = Config {
        pwd_hash: "mem".into(),
        ..Default::default()
    };
    let store = ddns_rs::config::ConfigStore::new(cfg.clone(), path.clone());
    assert_eq!(store.pwd_hash().await.unwrap(), "mem");
    store.replace(cfg).await.unwrap();
    assert_eq!(store.pwd_hash().await.unwrap(), "mem");
    assert_eq!(Config::load(&path).await.unwrap().pwd_hash, "mem");
}

#[tokio::test]
async fn pwd_hash_tolerates_structural_drift() {
    // 口令只取单字段，任务结构不兼容不得阻断登录与保存
    let dir = std::env::temp_dir().join("ddns-pwd-drift");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(
        &path,
        r#"{"pwd_hash":"h","entries":[{"provider":{"type":"future"}}]}"#,
    )
    .unwrap();
    let cfg = Config::default();
    let store = ddns_rs::config::ConfigStore::new(cfg.clone(), path.clone());
    assert_eq!(store.pwd_hash().await.unwrap(), "h");
    store.replace(cfg).await.unwrap();
    assert_eq!(store.pwd_hash().await.unwrap(), "h");
}

#[tokio::test]
async fn reset_pwd_hash_creates_when_missing() {
    let dir = std::env::temp_dir().join("ddns-reset-missing");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("fresh.json");
    let _ = std::fs::remove_file(&path);
    Config::reset_pwd_hash(&path, "h").await.unwrap();
    let cfg = Config::load(&path).await.unwrap();
    assert_eq!(cfg.pwd_hash, "h");
    assert!(cfg.entries.is_empty());
}

#[tokio::test]
async fn reset_pwd_hash_propagates_io_error() {
    let dir = std::env::temp_dir().join("ddns-reset-io");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("as-dir");
    std::fs::create_dir_all(&path).unwrap();
    assert!(Config::reset_pwd_hash(&path, "h").await.is_err());
}

#[test]
fn normalize_splits_full_domain_into_zone_and_subs() {
    let mut e = entry("www.example.com", "@");
    e.normalize();
    assert_eq!(e.zone, "example.com");
    assert_eq!(e.sub_domains, "www");
    let mut e = entry("a.b.example.eu.org", "vpn");
    e.normalize();
    assert_eq!(e.zone, "example.eu.org");
    assert_eq!(e.sub_domains, "a.b,vpn");
    let mut e = entry(" Example.COM ", "home");
    e.normalize();
    assert_eq!(e.zone, "example.com");
    assert_eq!(e.sub_domains, "home");
}

#[test]
fn validate_normalizes_all_entries_before_rejecting() {
    // 校验失败不留半归一状态：首败条目之后的条目亦须归一（启动容错路径继续使用配置）
    let mut bad = entry("example.com", "home");
    bad.provider = Provider::Cloudflare {
        token: "".into(),
        proxied: false,
    };
    let mut cfg = Config {
        entries: vec![bad, entry("WWW.Example.com", "@")],
        ..Default::default()
    };
    assert!(cfg.validate().is_err());
    assert_eq!(cfg.entries[1].zone, "example.com");
    assert_eq!(cfg.entries[1].sub_domains, "www");
}

#[test]
fn punycode_conversion_for_idn() {
    use ddns_rs::config::to_punycode;
    assert_eq!(to_punycode("home.example.com"), "home.example.com");
    assert!(to_punycode("中文.example.com").starts_with("xn--"));
    assert_eq!(to_punycode("@"), "@");
}

#[test]
fn enabled_family_without_source_is_rejected() {
    // 留空缺省须被校验拦截，防 v6 静默误用 v4 回显
    let e: Entry = serde_json::from_str(
        r#"{"zone":"example.com","ipv6":{"enabled":true},"provider":{"type":"cloudflare","token":"t"}}"#,
    )
    .unwrap();
    assert!(e.validate().is_err());
}

#[test]
fn sources_roundtrip_keeps_block_and_candidate_order() {
    // 块序为主序、块内候选为次级序，须保持
    let cfg = Config {
        entries: vec![Entry {
            ipv4: Family {
                enabled: true,
                sources: vec![
                    Source::Url {
                        url: vec!["u1".into(), "u2".into()],
                    },
                    Source::Cmd {
                        cmd: "echo 1.2.3.4".into(),
                    },
                    Source::Url {
                        url: vec!["u3".into()],
                    },
                ],
            },
            ..entry("example.com", "home")
        }],
        ..Default::default()
    };
    let text = serde_json::to_string(&cfg).unwrap();
    let back: Config = serde_json::from_str(&text).unwrap();
    let s = &back.entries[0].ipv4.sources;
    assert_eq!(s.len(), 3);
    let Source::Url { url } = &s[0] else { panic!() };
    assert_eq!(url, &vec!["u1".to_string(), "u2".to_string()]);
    assert!(matches!(&s[1], Source::Cmd { cmd } if cmd == "echo 1.2.3.4"));
    let Source::Url { url } = &s[2] else { panic!() };
    assert_eq!(url, &vec!["u3".to_string()]);
}

#[test]
fn blank_source_blocks_are_dropped_and_rejected() {
    assert!(Source::Url { url: vec![] }.is_blank());
    assert!(
        Source::NetInterface {
            name: vec!["".into(), "  ".into()]
        }
        .is_blank()
    );
    assert!(Source::Cmd { cmd: " ".into() }.is_blank());
    assert!(
        !Source::Cmd {
            cmd: "echo 1.2.3.4".into()
        }
        .is_blank()
    );
    let mut e = entry("example.com", "home");
    e.ipv6.sources = vec![
        Source::Cmd { cmd: "".into() },
        Source::Url {
            url: vec!["  ".into()],
        },
        Source::Cmd {
            cmd: "echo 1".into(),
        },
    ];
    e.normalize();
    assert_eq!(e.ipv6.sources.len(), 1);
    let mut e = entry("example.com", "home");
    e.ipv4.sources = vec![Source::Cmd { cmd: "".into() }];
    assert!(e.validate().is_err());
}

#[tokio::test]
async fn replace_bumps_revision_only_for_entries() {
    let dir = std::env::temp_dir().join("ddns-rev-test");
    std::fs::create_dir_all(&dir).unwrap();
    let store = ddns_rs::config::ConfigStore::new(Config::default(), dir.join("config.json"));
    let r0 = store.revision();
    let mut cfg = (*store.get().await).clone();
    cfg.site_title = "x".into();
    assert!(
        !store.replace(cfg).await.unwrap(),
        "展示字段变化不应触发引擎重建"
    );
    assert_eq!(store.revision(), r0);
    let mut cfg = (*store.get().await).clone();
    cfg.entries.push(entry("example.com", "home"));
    assert!(store.replace(cfg).await.unwrap(), "任务变化应触发引擎重建");
    assert_eq!(store.revision(), r0 + 1);
}

#[tokio::test]
async fn load_handles_bom_missing_and_broken() {
    let dir = std::env::temp_dir().join("ddns-load-test");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("bom.json");
    std::fs::write(&p, "\u{feff}{\"port\":7777}").unwrap();
    assert_eq!(Config::load(&p).await.unwrap().port, 7777);
    let d = Config::load(&dir.join("no-such.json")).await.unwrap();
    assert_eq!(d.port, 9999);
    assert!(d.entries.is_empty());
    let p = dir.join("broken.json");
    std::fs::write(&p, "not json").unwrap();
    assert!(Config::load(&p).await.is_err());
}

#[tokio::test]
async fn secrets_stay_plaintext_across_save_and_load() {
    let dir = std::env::temp_dir().join("ddns-secret-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    let _ = std::fs::remove_file(&path);
    let mut e = entry("example.com", "home");
    e.provider = Provider::Cloudflare {
        token: "tok-123".into(),
        proxied: false,
    };
    let cfg = Config {
        entries: vec![e],
        ..Default::default()
    };
    let store = ddns_rs::config::ConfigStore::new(cfg.clone(), path.clone());
    store.replace(cfg).await.unwrap();
    assert!(
        std::fs::read_to_string(&path).unwrap().contains("tok-123"),
        "凭据明文落盘"
    );
    assert_eq!(
        secret_val(store.get().await.as_ref(), 0, "token"),
        "tok-123"
    );
    let store = ddns_rs::config::ConfigStore::new(Config::load(&path).await.unwrap(), path);
    assert_eq!(
        secret_val(store.get().await.as_ref(), 0, "token"),
        "tok-123"
    );
}

#[tokio::test]
async fn empty_secret_field_stays_empty() {
    // Callback 请求体留空走 GET
    let dir = std::env::temp_dir().join("ddns-empty-test");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    let _ = std::fs::remove_file(&path);
    let mut e = entry("example.com", "home");
    e.provider = Provider::Callback {
        url: "https://hook".into(),
        body: "".into(),
    };
    let cfg = Config {
        entries: vec![e],
        ..Default::default()
    };
    let store = ddns_rs::config::ConfigStore::new(cfg.clone(), path.clone());
    store.replace(cfg).await.unwrap();
    assert_eq!(
        secret_val(&Config::load(&path).await.unwrap(), 0, "body"),
        ""
    );
}
