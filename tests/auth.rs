use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ddns_rs::auth::{FailTrack, MasterKey, Token, check_strength, pwd_hash, pwd_verify};

#[test]
fn token_verify_returns_remaining_and_rejects_expired() {
    let mk = MasterKey::new();
    let t = Token::issue(&mk, 100);
    let remain = Token::verify(&t.to_b64(), &mk).unwrap();
    assert!(
        (1..=100).contains(&remain),
        "剩余寿命应在 (0, ttl] 内: {remain}"
    );
    let dead = Token::issue(&mk, 0);
    assert!(Token::verify(&dead.to_b64(), &mk).is_err());
    // 密钥轮换（改密/重启）后旧令牌立即失效
    assert!(Token::verify(&t.to_b64(), &MasterKey::new()).is_err());
}

#[test]
fn renew_returns_none_or_fresh_by_half_life_and_shrink() {
    let mk = MasterKey::new();
    let t = Token::issue(&mk, 100);
    // 半衰内活跃才续期；TTL 调小则任意请求收紧；无效凭证不续期
    assert!(
        Token::renew(&t.to_b64(), &mk, false, 100)
            .unwrap()
            .is_none()
    );
    let fresh = Token::renew(&t.to_b64(), &mk, true, 300).unwrap().unwrap();
    assert!(Token::verify(&fresh, &mk).unwrap() > 100);
    assert!(Token::renew(&t.to_b64(), &mk, false, 50).unwrap().is_some());
    assert!(Token::renew("bad", &mk, true, 100).is_err());
}

#[test]
fn token_rejects_tampering_and_bad_length() {
    let mk = MasterKey::new();
    let mut raw = URL_SAFE_NO_PAD
        .decode(Token::issue(&mk, 100).to_b64())
        .unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0xff;
    assert!(
        Token::verify(&URL_SAFE_NO_PAD.encode(&raw), &mk).is_err(),
        "篡改签名应拒绝"
    );
    assert!(
        Token::verify(&URL_SAFE_NO_PAD.encode([0u8; 8]), &mk).is_err(),
        "长度不符应拒绝"
    );
}

#[test]
fn lockout_triggers_on_nth_attempt() {
    // 第 max 次尝试仍放行并置锁，其后拒绝直至 clear
    let ft = FailTrack::new(3, 60);
    for _ in 0..3 {
        assert!(ft.try_acquire("1.2.3.4").is_ok());
    }
    assert!(ft.try_acquire("1.2.3.4").is_err(), "达上限后应锁定");
    assert!(ft.try_acquire("5.6.7.8").is_ok(), "其他来源不受影响");
    ft.clear("1.2.3.4");
    assert!(ft.try_acquire("1.2.3.4").is_ok(), "清除后恢复");
}

#[test]
fn lockout_expires_after_lock_secs() {
    let ft = FailTrack::new(1, 1);
    assert!(ft.try_acquire("1.2.3.4").is_ok());
    assert!(ft.try_acquire("1.2.3.4").is_err());
    std::thread::sleep(std::time::Duration::from_millis(1100));
    assert!(ft.try_acquire("1.2.3.4").is_ok(), "锁定期满应恢复放行");
}

#[test]
fn strength_rejects_weak_passwords() {
    assert!(check_strength("12345678").is_err(), "纯数字低熵应拒绝");
    assert!(check_strength("abc").is_err(), "过短应拒绝");
    assert!(check_strength("Abcd1234").is_ok());
    assert!(
        check_strength("一个足够长的中文口令呀").is_ok(),
        "非 ASCII 计入大字符池"
    );
}

#[test]
fn pwd_hash_roundtrip_and_rejects_wrong_or_broken() {
    let h = pwd_hash("Abcd1234!").unwrap();
    assert!(pwd_verify(&h, "Abcd1234!"), "正确口令应通过");
    assert!(!pwd_verify(&h, "Abcd1234"), "错误口令应拒绝");
    assert!(!pwd_verify("not-a-hash", "x"), "非法哈希应拒绝");
    assert_ne!(
        pwd_hash("Abcd1234!").unwrap(),
        h,
        "随机盐：同口令散列应不同"
    );
}
