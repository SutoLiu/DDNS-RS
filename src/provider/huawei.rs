use async_trait::async_trait;
use reqwest::Method;
use serde_json::{Value, json};

use super::sign::{hex, hmac_sha256, pe, sha256_hex, utc_datetime};
use super::{Provider, Upsert};
use crate::error::{Error, Result};

const API: &str = "https://dns.myhuaweicloud.com";
const HOST: &str = "dns.myhuaweicloud.com";

pub struct Huawei {
    client: reqwest::Client,
    ak: String,
    sk: String,
}

impl Huawei {
    pub fn new(client: reqwest::Client, ak: String, sk: String) -> Self {
        Self { client, ak, sk }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: &str,
    ) -> Result<Value> {
        let ts = utc_datetime();
        // 规范 URI 补尾斜杠是签名约定，与实际路径无关
        let uri = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{path}/")
        };
        let mut q: Vec<&(String, String)> = query.iter().collect();
        q.sort();
        let qs = q
            .iter()
            .map(|(k, v)| format!("{}={}", pe(k), pe(v)))
            .collect::<Vec<_>>()
            .join("&");
        let canonical = format!(
            "{method}\n{uri}\n{qs}\ncontent-type:application/json\nhost:{HOST}\nx-sdk-date:{ts}\n\ncontent-type;host;x-sdk-date\n{}",
            sha256_hex(body)
        );
        let string_to_sign = format!("SDK-HMAC-SHA256\n{ts}\n{}", sha256_hex(&canonical));
        let signature = hex(&hmac_sha256(self.sk.as_bytes(), &string_to_sign));
        let auth = format!(
            "SDK-HMAC-SHA256 Access={}, SignedHeaders=content-type;host;x-sdk-date, Signature={signature}",
            self.ak
        );
        let url = if qs.is_empty() {
            format!("{API}{path}")
        } else {
            format!("{API}{path}?{qs}")
        };
        let mut req = self
            .client
            .request(method, url)
            .header("Content-Type", "application/json")
            .header("X-Sdk-Date", &ts)
            .header("Authorization", auth);
        if !body.is_empty() {
            req = req.body(body.to_string());
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            let msg = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| {
                    v["error"]["message"]
                        .as_str()
                        .or(v["message"].as_str())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| format!("HTTP {status}"));
            return Err(Error::Internal(format!("华为云: {msg}")));
        }
        serde_json::from_str(&text).map_err(|e| Error::Internal(format!("华为云响应解析失败: {e}")))
    }
}

#[async_trait]
impl Provider for Huawei {
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        let ttl = if r.ttl == 0 { 300 } else { r.ttl };
        let kind = r.kind.as_str().to_string();
        let name = format!("{}.", r.fqdn);
        // name 为模糊匹配，须再精确比对
        let list = self
            .call(
                Method::GET,
                "/v2.1/recordsets",
                &[
                    ("name".to_string(), name.clone()),
                    ("type".to_string(), kind.clone()),
                ],
                "",
            )
            .await?;
        let rec = list["recordsets"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["name"].as_str() == Some(name.as_str())));
        match rec {
            Some(rec)
                if rec["records"][0].as_str() == Some(r.ip)
                    && rec["ttl"].as_i64() == Some(ttl as i64) =>
            {
                Ok(())
            }
            Some(rec) => {
                let zid = rec["zone_id"].as_str().unwrap_or_default();
                let rid = rec["id"].as_str().unwrap_or_default();
                let body =
                    json!({"name": name, "type": kind, "records": [r.ip], "ttl": ttl}).to_string();
                self.call(
                    Method::PUT,
                    &format!("/v2.1/zones/{zid}/recordsets/{rid}"),
                    &[],
                    &body,
                )
                .await
                .map(|_| ())
            }
            None => {
                let zone = format!("{}.", r.zone);
                let zs = self
                    .call(
                        Method::GET,
                        "/v2/zones",
                        &[("name".to_string(), r.zone.to_string())],
                        "",
                    )
                    .await?;
                let zid = zs["zones"]
                    .as_array()
                    .and_then(|a| a.iter().find(|z| z["name"].as_str() == Some(zone.as_str())))
                    .and_then(|z| z["id"].as_str())
                    .ok_or_else(|| Error::Internal(format!("华为云未找到域名 {zone} 的 Zone")))?;
                let body =
                    json!({"name": name, "type": kind, "records": [r.ip], "ttl": ttl, "weight": 1})
                        .to_string();
                self.call(
                    Method::POST,
                    &format!("/v2.1/zones/{zid}/recordsets"),
                    &[],
                    &body,
                )
                .await
                .map(|_| ())
            }
        }
    }
}
