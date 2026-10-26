use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

const MIN_PWD: usize = 8;

pub fn check_strength(pwd: &str) -> Result<()> {
    if pwd.chars().count() < MIN_PWD {
        return Err(Error::Arg(format!("密码至少 {MIN_PWD} 位")));
    }
    let chars: Vec<char> = pwd.chars().collect();
    let mut pool = 0.0f64;
    if chars.iter().any(|c| c.is_ascii_lowercase()) {
        pool += 26.0;
    }
    if chars.iter().any(|c| c.is_ascii_uppercase()) {
        pool += 26.0;
    }
    if chars.iter().any(|c| c.is_ascii_digit()) {
        pool += 10.0;
    }
    if chars.iter().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 33.0;
    }
    if chars.iter().any(|c| !c.is_ascii()) {
        pool += 100.0;
    }
    if chars.len() as f64 * pool.log2() < 30.0 {
        return Err(Error::Arg("密码强度不足，请混合大小写、数字或符号".into()));
    }
    Ok(())
}

/// 进程内随机，重启即失效全部会话
pub struct MasterKey(HmacSha256);

impl MasterKey {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut k = [0u8; 32];
        getrandom::getrandom(&mut k).expect("系统随机数源不可用");
        Self(<HmacSha256 as Mac>::new_from_slice(&k).expect("hmac 定长密钥"))
    }
}

/// 单调时钟锚点，令牌判定不受系统时间跳变影响
static T0: LazyLock<Instant> = LazyLock::new(Instant::now);

/// 令牌：8 字节到期时刻 + 32 字节 HMAC，Base64URL 无填充
pub struct Token {
    exp: u64,
    tag: [u8; 32],
}

const TOKEN_BYTES: usize = 40;

impl Token {
    pub fn issue(mk: &MasterKey, ttl: u64) -> Self {
        let exp = T0.elapsed().as_secs().saturating_add(ttl);
        let mut mac = mk.0.clone();
        mac.update(&exp.to_le_bytes());
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&mac.finalize().into_bytes());
        Self { exp, tag }
    }

    pub fn to_b64(&self) -> String {
        let mut v = [0u8; TOKEN_BYTES];
        v[0..8].copy_from_slice(&self.exp.to_le_bytes());
        v[8..40].copy_from_slice(&self.tag);
        URL_SAFE_NO_PAD.encode(v)
    }

    pub fn verify(cred: &str, mk: &MasterKey) -> Result<u64> {
        let b = URL_SAFE_NO_PAD.decode(cred).map_err(|_| Error::Auth)?;
        if b.len() != TOKEN_BYTES {
            return Err(Error::Auth);
        }
        let exp = u64::from_le_bytes(b[0..8].try_into().map_err(|_| Error::Auth)?);
        let mut mac = mk.0.clone();
        mac.update(&exp.to_le_bytes());
        mac.verify_slice(&b[8..40]).map_err(|_| Error::Auth)?;
        let now = T0.elapsed().as_secs();
        if now >= exp {
            return Err(Error::Auth);
        }
        Ok(exp - now)
    }

    pub fn renew(cred: &str, mk: &MasterKey, active: bool, ttl: u64) -> Result<Option<String>> {
        let remain = Self::verify(cred, mk)?;
        Ok(((active && remain < ttl / 2) || remain > ttl).then(|| Self::issue(mk, ttl).to_b64()))
    }
}

fn argon2() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19456, 3, 1, None).expect("argon2 参数"),
    )
}

pub fn pwd_hash(pwd: &str) -> Result<String> {
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt).expect("系统随机数源不可用");
    let salt = SaltString::encode_b64(&salt).expect("salt 编码");
    argon2()
        .hash_password(pwd.as_bytes(), &salt)
        .map_err(|e| Error::Internal(format!("argon2: {e}")))
        .map(|h| h.to_string())
}

pub fn pwd_verify(hash: &str, pwd: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .and_then(|p| argon2().verify_password(pwd.as_bytes(), &p).ok())
        .is_some()
}

/// 登录限速：检查与计数同锁，达上限即锁定
pub struct FailTrack {
    max: u32,
    lock: Duration,
    inner: Mutex<HashMap<String, FailEntry>>,
}

struct FailEntry {
    count: u32,
    lock_until: Option<Instant>,
    last_fail: Instant,
}

impl FailTrack {
    pub fn new(max: u32, lock_secs: u64) -> Self {
        Self {
            max,
            lock: Duration::from_secs(lock_secs),
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn try_acquire(&self, ip: &str) -> Result<()> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        if g.len() > 128
            && let Some(cutoff) = now.checked_sub(self.lock * 2)
        {
            g.retain(|_, e| matches!(e.lock_until, Some(t) if t > now) || e.last_fail > cutoff);
        }
        if let Some(e) = g.get(ip)
            && matches!(e.lock_until, Some(t) if t > now)
        {
            return Err(Error::Arg("尝试次数过多，请稍后再试".into()));
        }
        let e = g.entry(ip.to_string()).or_insert(FailEntry {
            count: 0,
            lock_until: None,
            last_fail: now,
        });
        e.count += 1;
        e.last_fail = now;
        if e.count >= self.max {
            e.lock_until = Some(now + self.lock);
            e.count = 0;
        }
        Ok(())
    }

    pub fn clear(&self, ip: &str) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(ip);
    }
}
