use async_trait::async_trait;

use super::{Provider, Upsert};
use crate::error::{Error, Result};
use crate::ip::RecordKind;

/// dynv6 Update API：zone 传完整主机名，按记录类型分别写 ipv4 / ipv6
const API: &str = "https://dynv6.com/api/update";

pub struct Dynv6 {
    client: reqwest::Client,
    token: String,
}

impl Dynv6 {
    pub fn new(client: reqwest::Client, token: String) -> Self {
        Self { client, token }
    }
}

/// 查询参数契约，单独抽出便于验证 zone / token / 地址族映射
pub fn params<'a>(
    fqdn: &'a str,
    token: &'a str,
    kind: RecordKind,
    ip: &'a str,
) -> [(&'a str, &'a str); 3] {
    let (field, addr) = match kind {
        RecordKind::A => ("ipv4", ip),
        RecordKind::Aaaa => ("ipv6", ip),
    };
    [("zone", fqdn), ("token", token), (field, addr)]
}

#[async_trait]
impl Provider for Dynv6 {
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        // without_url 防止 token 随请求错误写进日志
        let resp = self
            .client
            .get(API)
            .query(&params(r.fqdn, self.token.as_str(), r.kind, r.ip))
            .send()
            .await
            .map_err(|e| Error::from(e.without_url()))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            let brief: String = text.chars().take(200).collect();
            return Err(Error::Internal(format!("dynv6 HTTP {status}: {brief}")));
        }
        Ok(())
    }
}
