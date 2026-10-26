use async_trait::async_trait;
use serde_json::Value;

use super::{Provider, Upsert};
use crate::error::{Error, Result};

pub struct Callback {
    client: reqwest::Client,
    url: String,
    body: String,
}

impl Callback {
    pub fn new(client: reqwest::Client, url: String, body: String) -> Self {
        Self { client, url, body }
    }
}

pub fn render(tpl: &str, r: &Upsert<'_>) -> String {
    let ttl = if r.ttl == 0 { 600 } else { r.ttl };
    tpl.replace("#{ip}", r.ip)
        .replace("#{domain}", r.fqdn)
        .replace("#{recordType}", r.kind.as_str())
        .replace("#{ttl}", &ttl.to_string())
        .replace("#{timestamp}", &crate::now_secs().to_string())
}

#[async_trait]
impl Provider for Callback {
    /// 去重与重发由引擎调度，此处仅执行一次
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        let url = render(&self.url, r);
        let resp = if self.body.trim().is_empty() {
            self.client.get(&url).send().await?
        } else {
            let body = render(&self.body, r);
            // 合法 JSON 以 application/json 发送，否则按表单编码
            let ct = if serde_json::from_str::<Value>(&body).is_ok() {
                "application/json"
            } else {
                "application/x-www-form-urlencoded"
            };
            self.client
                .post(&url)
                .header("Content-Type", ct)
                .body(body)
                .send()
                .await?
        };
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let brief: String = text.chars().take(200).collect();
            return Err(Error::Internal(format!("Callback {status}: {brief}")));
        }
        Ok(())
    }
}
