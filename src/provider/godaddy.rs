use async_trait::async_trait;
use serde_json::{Value, json};

use super::{Provider, Upsert};
use crate::error::{Error, Result};

const API: &str = "https://api.godaddy.com/v1";

pub struct Godaddy {
    client: reqwest::Client,
    key: String,
    secret: String,
}

impl Godaddy {
    pub fn new(client: reqwest::Client, key: String, secret: String) -> Self {
        Self { client, key, secret }
    }
}

#[async_trait]
impl Provider for Godaddy {
    /// PUT 全量替换该主机名下同类型记录
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        let ttl = if r.ttl == 0 { 600 } else { r.ttl };
        let kind = r.kind.as_str();
        let resp = self
            .client
            .put(format!("{API}/domains/{}/records/{kind}/{}", r.zone, r.sub))
            .header(
                "Authorization",
                format!("sso-key {}:{}", self.key, self.secret),
            )
            .json(&json!([{"data": r.ip, "name": r.sub, "ttl": ttl, "type": kind}]))
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            let msg = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v["message"].as_str().map(str::to_string))
                .unwrap_or_else(|| format!("HTTP {status}"));
            return Err(Error::Internal(format!("GoDaddy: {msg}")));
        }
        Ok(())
    }
}
