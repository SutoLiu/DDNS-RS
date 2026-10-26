use async_trait::async_trait;
use serde_json::{Value, json};

use super::sign::num;
use super::{Provider, Upsert};
use crate::error::{Error, Result};

const API: &str = "https://api.porkbun.com/api/json/v3/dns";

pub struct Porkbun {
    client: reqwest::Client,
    key: String,
    secret: String,
}

impl Porkbun {
    pub fn new(client: reqwest::Client, key: String, secret: String) -> Self {
        Self { client, key, secret }
    }

    async fn call(&self, path: &str, mut body: Value) -> Result<Value> {
        body["apikey"] = json!(self.key);
        body["secretapikey"] = json!(self.secret);
        let v: Value = self
            .client
            .post(format!("{API}/{path}"))
            .json(&body)
            .send()
            .await?
            .json()
            .await?;
        if v["status"].as_str() != Some("SUCCESS") {
            let msg = v["status"].as_str().unwrap_or("未知错误");
            return Err(Error::Internal(format!("Porkbun: {msg}")));
        }
        Ok(v)
    }
}

#[async_trait]
impl Provider for Porkbun {
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        let ttl = if r.ttl == 0 { 600 } else { r.ttl };
        let kind = r.kind.as_str().to_string();
        let zone = r.zone.to_string();
        // Porkbun 以空串表示根域名的子域部分
        let sub = if r.sub == "@" { "" } else { r.sub };
        let found = self
            .call(
                &format!("retrieveByNameType/{zone}/{kind}/{sub}"),
                json!({}),
            )
            .await?;
        let rec = found["records"].as_array().and_then(|a| a.first());
        match rec {
            Some(rec)
                if rec["content"].as_str() == Some(r.ip)
                    && num(&rec["ttl"]) == Some(ttl as i64) =>
            {
                Ok(())
            }
            Some(_) => self
                .call(
                    &format!("editByNameType/{zone}/{kind}/{sub}"),
                    json!({"content": r.ip, "ttl": ttl.to_string()}),
                )
                .await
                .map(|_| ()),
            None => self
                .call(
                    &format!("create/{zone}"),
                    json!({"name": sub, "type": kind, "content": r.ip, "ttl": ttl.to_string()}),
                )
                .await
                .map(|_| ()),
        }
    }
}
