use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_hex(data: &str) -> String {
    hex(&Sha256::digest(data.as_bytes()))
}

pub fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC 支持任意长度密钥");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// JSON 数值兼容字符串形式（Porkbun / DNSPod 旧 API 的 TTL 为字符串）
pub fn num(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

/// RFC3986 百分号编码：保留 -_.~，空格转 %20
pub fn pe(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// UTC 时刻（2025-01-09T12:00:00Z），阿里云/百度云签名用
pub fn utc_now() -> String {
    let secs = crate::now_secs() as i64;
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// UTC 日期（2025-01-09），腾讯云凭证范围用
pub fn utc_date() -> String {
    let (y, m, d) = civil_from_days((crate::now_secs() as i64).div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// UTC 紧凑时刻（20250109T120000Z），华为云/火山引擎共用
pub fn utc_datetime() -> String {
    let secs = crate::now_secs() as i64;
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// 儒略日转公历（Howard Hinnant 算法）
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 阿里云 RPC 调用上下文（HMAC-SHA1），DNS 与 ESA 共用
pub struct AliyunRpc<'a> {
    pub client: &'a reqwest::Client,
    pub ak: &'a str,
    pub sk: &'a str,
    pub endpoint: &'a str,
    pub version: &'a str,
}

impl AliyunRpc<'_> {
    pub async fn call(
        &self,
        method: reqwest::Method,
        action: &str,
        extra: &[(&str, String)],
    ) -> Result<Value> {
        let mut nb = [0u8; 16];
        getrandom::getrandom(&mut nb).expect("系统随机数源不可用");
        let mut params: Vec<(String, String)> = vec![
            ("Format".into(), "JSON".into()),
            ("Version".into(), self.version.into()),
            ("AccessKeyId".into(), self.ak.into()),
            ("SignatureMethod".into(), "HMAC-SHA1".into()),
            ("SignatureVersion".into(), "1.0".into()),
            ("SignatureNonce".into(), hex(&nb)),
            ("Timestamp".into(), utc_now()),
            ("Action".into(), action.into()),
        ];
        params.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
        params.sort();

        let canonical = params
            .iter()
            .map(|(k, v)| format!("{}={}", pe(k), pe(v)))
            .collect::<Vec<_>>()
            .join("&");
        let string_to_sign = format!("{}&{}&{}", method.as_str(), pe("/"), pe(&canonical));
        let mut mac = Hmac::<Sha1>::new_from_slice(format!("{}&", self.sk).as_bytes())
            .map_err(|e| Error::Internal(format!("签名初始化失败: {e}")))?;
        mac.update(string_to_sign.as_bytes());
        let sig = STANDARD.encode(mac.finalize().into_bytes());

        let query = format!("{canonical}&Signature={}", pe(&sig));
        let v: Value = self
            .client
            .request(method, format!("{}?{query}", self.endpoint))
            .send()
            .await?
            .json()
            .await?;
        if let Some(code) = v["Code"].as_str() {
            let msg = v["Message"].as_str().unwrap_or("");
            return Err(Error::Internal(format!("阿里云 {code}: {msg}")));
        }
        Ok(v)
    }
}
