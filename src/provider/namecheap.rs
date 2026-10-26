use async_trait::async_trait;

use super::{Provider, Upsert};
use crate::error::{Error, Result};

/// 仅支持 IPv4，IPv6 在配置校验层拦截
const API: &str = "https://dynamicdns.park-your-domain.com/update";

pub struct Namecheap {
    client: reqwest::Client,
    password: String,
}

impl Namecheap {
    pub fn new(client: reqwest::Client, password: String) -> Self {
        Self { client, password }
    }
}

#[async_trait]
impl Provider for Namecheap {
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        let resp = self
            .client
            .get(API)
            .query(&[
                ("host", r.sub),
                ("domain", r.zone),
                ("password", self.password.as_str()),
                ("ip", r.ip),
            ])
            .send()
            .await
            .map_err(|e| Error::from(e.without_url()))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(Error::Internal(format!("Namecheap HTTP {status}")));
        }
        if text.contains("<ErrCount>0</ErrCount>") {
            Ok(())
        } else {
            let brief: String = text.chars().take(200).collect();
            Err(Error::Internal(format!("Namecheap: {brief}")))
        }
    }
}
