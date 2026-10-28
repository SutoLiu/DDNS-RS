use async_trait::async_trait;
use serde_json::Value;

use super::sign::AliyunRpc;
use super::{Provider, Upsert};
use crate::error::Result;

const ENDPOINT: &str = "https://alidns.aliyuncs.com/";
const VERSION: &str = "2015-01-09";

/// 阿里云拒收 punycode 参数
fn to_unicode(s: &str) -> String {
    let (out, ok) = idna::domain_to_unicode(s);
    ok.map(|_| out).unwrap_or_else(|_| s.to_string())
}

pub struct Aliyun {
    client: reqwest::Client,
    ak: String,
    sk: String,
}

impl Aliyun {
    pub fn new(client: reqwest::Client, ak: String, sk: String) -> Self {
        Self { client, ak, sk }
    }

    async fn call(&self, action: &str, extra: &[(&str, String)]) -> Result<Value> {
        AliyunRpc {
            client: &self.client,
            ak: &self.ak,
            sk: &self.sk,
            endpoint: ENDPOINT,
            version: VERSION,
        }
        .call(reqwest::Method::GET, action, extra)
        .await
    }
}

#[async_trait]
impl Provider for Aliyun {
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        let (zone, sub, fqdn) = (to_unicode(r.zone), to_unicode(r.sub), to_unicode(r.fqdn));
        let ttl = if r.ttl == 0 { 600 } else { r.ttl };
        let kind = r.kind.as_str().to_string();
        let rr = if sub.is_empty() || sub == "@" {
            "@".to_string()
        } else {
            sub
        };
        // 根域名的记录在阿里云以 "@.zone" 形式查询
        let sub_domain = if rr == "@" { format!("@.{zone}") } else { fqdn };
        let found = self
            .call(
                "DescribeSubDomainRecords",
                &[
                    ("DomainName", zone.clone()),
                    ("SubDomain", sub_domain),
                    ("Type", kind.clone()),
                ],
            )
            .await?;
        let existing = found["DomainRecords"]["Record"]
            .as_array()
            .and_then(|a| a.first());
        match existing {
            Some(rec)
                if rec["Value"].as_str() == Some(r.ip)
                    && rec["TTL"].as_i64() == Some(ttl as i64) =>
            {
                Ok(())
            }
            Some(rec) => {
                let rid = rec["RecordId"].as_str().unwrap_or_default().to_string();
                self.call(
                    "UpdateDomainRecord",
                    &[
                        ("RecordId", rid),
                        ("RR", rr),
                        ("Type", kind),
                        ("Value", r.ip.to_string()),
                        ("TTL", ttl.to_string()),
                    ],
                )
                .await
                .map(|_| ())
            }
            None => self
                .call(
                    "AddDomainRecord",
                    &[
                        ("DomainName", zone),
                        ("RR", rr),
                        ("Type", kind),
                        ("Value", r.ip.to_string()),
                        ("TTL", ttl.to_string()),
                    ],
                )
                .await
                .map(|_| ()),
        }
    }
}
