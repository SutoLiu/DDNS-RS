use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use reqwest::Method;
use serde_json::{Value, json};

use super::{Provider, Upsert};
use crate::error::{Error, Result};

const API: &str = "https://api.cloudflare.com/client/v4";

pub struct Cloudflare {
    client: reqwest::Client,
    token: String,
    proxied: bool,
    zones: Mutex<HashMap<String, String>>,
}

impl Cloudflare {
    pub fn new(client: reqwest::Client, token: String, proxied: bool) -> Self {
        Self {
            client,
            token,
            proxied,
            zones: Mutex::new(HashMap::new()),
        }
    }

    async fn zone_id(&self, zone: &str) -> Result<String> {
        if let Some(id) = self
            .zones
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(zone)
        {
            return Ok(id.clone());
        }
        let v = self
            .get(
                format!("{API}/zones"),
                &[("name", zone), ("status", "active"), ("per_page", "50")],
            )
            .await?;
        let id = v["result"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|r| r["id"].as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Internal(format!("Cloudflare 未找到域名 {zone} 的 Zone")))?;
        self.zones
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(zone.to_string(), id.clone());
        Ok(id)
    }

    async fn get(&self, url: String, query: &[(&str, &str)]) -> Result<Value> {
        let resp = self
            .client
            .get(url)
            .query(query)
            .bearer_auth(&self.token)
            .send()
            .await?;
        check(resp).await
    }

    async fn send(&self, method: Method, url: String, body: &Value) -> Result<()> {
        let resp = self
            .client
            .request(method, url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await?;
        check(resp).await.map(|_| ())
    }
}

#[async_trait]
impl Provider for Cloudflare {
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        let zid = self.zone_id(r.zone).await?;
        let ttl = if r.ttl == 0 { 1 } else { r.ttl }; // 1 表示由 Cloudflare 自动决定
        let list = self
            .get(
                format!("{API}/zones/{zid}/dns_records"),
                &[
                    ("type", r.kind.as_str()),
                    ("name", r.fqdn),
                    ("per_page", "50"),
                ],
            )
            .await?;
        let existing = list["result"].as_array().and_then(|a| a.first());
        // 回带既有备注，避免更新时被清空
        let body = json!({
            "type": r.kind.as_str(),
            "name": r.fqdn,
            "content": r.ip,
            "ttl": ttl,
            "proxied": self.proxied,
            "comment": existing.map(|rec| rec["comment"].clone()).unwrap_or(Value::Null),
        });
        match existing {
            Some(rec)
                if rec["content"].as_str() == Some(r.ip)
                    && rec["proxied"].as_bool() == Some(self.proxied)
                    && rec["ttl"].as_i64() == Some(ttl as i64) =>
            {
                Ok(())
            }
            Some(rec) => {
                let rid = rec["id"].as_str().unwrap_or_default();
                let url = format!("{API}/zones/{zid}/dns_records/{rid}");
                self.send(Method::PUT, url, &body).await
            }
            None => {
                let url = format!("{API}/zones/{zid}/dns_records");
                self.send(Method::POST, url, &body).await
            }
        }
    }
}

async fn check(resp: reqwest::Response) -> Result<Value> {
    let status = resp.status();
    let v: Value = resp.json().await?;
    if v["success"].as_bool() == Some(true) {
        return Ok(v);
    }
    let msg = v["errors"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|e| e["message"].as_str())
        .unwrap_or("未知错误");
    Err(Error::Internal(format!("Cloudflare {status}: {msg}")))
}
