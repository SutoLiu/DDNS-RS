use async_trait::async_trait;
use serde_json::{Value, json};

use super::sign::{hex, hmac_sha256, utc_now};
use super::{Provider, Upsert};
use crate::error::{Error, Result};

const API: &str = "https://bcd.baidubce.com";
const HOST: &str = "bcd.baidubce.com";
const EXPIRES: &str = "1800";

pub struct Baidu {
    client: reqwest::Client,
    ak: String,
    sk: String,
}

impl Baidu {
    pub fn new(client: reqwest::Client, ak: String, sk: String) -> Self {
        Self { client, ak, sk }
    }

    async fn call(&self, path: &str, body: &Value) -> Result<Value> {
        let prefix = format!("bce-auth-v1/{}/{}/{}", self.ak, utc_now(), EXPIRES);
        let canonical = format!("POST\n{path}\n\nhost:{HOST}");
        let key = hex(&hmac_sha256(self.sk.as_bytes(), &prefix));
        let signature = hex(&hmac_sha256(key.as_bytes(), &canonical));
        let resp = self
            .client
            .post(format!("{API}{path}"))
            .header("Authorization", format!("{prefix}/host/{signature}"))
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            let msg = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v["message"].as_str().map(str::to_string))
                .unwrap_or_else(|| format!("HTTP {status}"));
            return Err(Error::Internal(format!("百度云: {msg}")));
        }
        serde_json::from_str(&text).map_err(|e| Error::Internal(format!("百度云响应解析失败: {e}")))
    }
}

#[async_trait]
impl Provider for Baidu {
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        let ttl = if r.ttl == 0 { 300 } else { r.ttl };
        let kind = r.kind.as_str().to_string();
        let list = self
            .call(
                "/v1/domain/resolve/list",
                &json!({"domain": r.zone, "pageNum": 1, "pageSize": 1000}),
            )
            .await?;
        // 子域名 + 类型双匹配，避免双栈误改对方
        let rec = list["result"].as_array().and_then(|a| {
            a.iter().find(|x| {
                x["domain"].as_str() == Some(r.sub) && x["rdtype"].as_str() == Some(kind.as_str())
            })
        });
        match rec {
            Some(rec)
                if rec["rdata"].as_str() == Some(r.ip)
                    && rec["ttl"].as_i64() == Some(ttl as i64) =>
            {
                Ok(())
            }
            Some(rec) => {
                let body = json!({
                    "recordId": rec["recordId"], "domain": rec["domain"], "view": rec["view"],
                    "rdType": kind, "ttl": ttl, "rdata": r.ip, "zoneName": rec["zoneName"],
                });
                self.call("/v1/domain/resolve/edit", &body)
                    .await
                    .map(|_| ())
            }
            None => {
                let body = json!({"domain": r.sub, "rdType": kind, "ttl": ttl, "rdata": r.ip, "zoneName": r.zone});
                self.call("/v1/domain/resolve/add", &body).await.map(|_| ())
            }
        }
    }
}
