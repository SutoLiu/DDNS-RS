use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde_json::Value;

use super::sign::AliyunRpc;
use super::{Provider, Upsert};
use crate::error::{Error, Result};

const ENDPOINT: &str = "https://esa.cn-hangzhou.aliyuncs.com/";
const VERSION: &str = "2024-09-10";
/// ESA 的 IP 记录为合并型 A/AAAA，v4 与 v6 逗号共存于同一条记录
const TYPE: &str = "A/AAAA";

pub struct Aliesa {
    client: reqwest::Client,
    ak: String,
    sk: String,
    sites: Mutex<HashMap<String, (i64, String)>>,
}

impl Aliesa {
    pub fn new(client: reqwest::Client, ak: String, sk: String) -> Self {
        Self {
            client,
            ak,
            sk,
            sites: Mutex::new(HashMap::new()),
        }
    }

    async fn call(
        &self,
        method: reqwest::Method,
        action: &str,
        extra: &[(&str, String)],
    ) -> Result<Value> {
        AliyunRpc {
            client: &self.client,
            ak: &self.ak,
            sk: &self.sk,
            endpoint: ENDPOINT,
            version: VERSION,
        }
        .call(method, action, extra)
        .await
    }

    async fn site(&self, zone: &str) -> Result<(i64, String)> {
        if let Some(s) = self
            .sites
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(zone)
        {
            return Ok(s.clone());
        }
        let v = self
            .call(
                reqwest::Method::GET,
                "ListSites",
                &[("SiteName", zone.to_string())],
            )
            .await?;
        // 过滤结果仍精确比对，防服务端返回近似站点
        let site = v["Sites"]
            .as_array()
            .and_then(|a| a.iter().find(|s| s["SiteName"].as_str() == Some(zone)))
            .ok_or_else(|| Error::Internal(format!("ESA 未找到域名 {zone} 的站点")))?;
        let s = (
            site["SiteId"].as_i64().unwrap_or_default(),
            site["AccessType"].as_str().unwrap_or_default().to_string(),
        );
        self.sites
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(zone.to_string(), s.clone());
        Ok(s)
    }
}

/// 替换本族地址、保留另一族（IPv6 含冒号），v4 在前
pub fn merge_ips(value: &str, ip: &str, v4: bool) -> String {
    let keep: Vec<&str> = value
        .split(',')
        .filter(|s| !s.is_empty() && s.contains(':') == v4)
        .collect();
    let mut out: Vec<&str> = if v4 { vec![ip] } else { vec![] };
    out.extend(keep);
    if !v4 {
        out.push(ip);
    }
    out.join(",")
}

#[async_trait]
impl Provider for Aliesa {
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        let (site_id, access) = self.site(r.zone).await?;
        let ttl = if r.ttl == 0 { 600 } else { r.ttl };
        let found = self
            .call(
                reqwest::Method::GET,
                "ListRecords",
                &[
                    ("SiteId", site_id.to_string()),
                    ("RecordName", r.fqdn.to_string()),
                    ("Type", TYPE.to_string()),
                ],
            )
            .await?;
        let rec = found["Records"].as_array().and_then(|a| a.first());
        let data = |ips: &str| format!("{{\"Value\":\"{ips}\"}}");
        match rec {
            Some(rec) => {
                // 响应字段大小写以服务端为准，两种写法都兼容
                let cur = rec["Data"]["Value"]
                    .as_str()
                    .or_else(|| rec["Data"]["value"].as_str())
                    .unwrap_or("");
                let merged = merge_ips(cur, r.ip, r.kind.as_str() == "A");
                let ttl_same = rec["Ttl"].as_i64() == Some(ttl as i64)
                    || rec["TTL"].as_i64() == Some(ttl as i64);
                if merged == cur && ttl_same {
                    return Ok(());
                }
                let rid = rec["RecordId"].as_i64().unwrap_or_default();
                self.call(
                    reqwest::Method::POST,
                    "UpdateRecord",
                    &[
                        ("RecordId", rid.to_string()),
                        ("Type", TYPE.to_string()),
                        ("Data", data(&merged)),
                        ("Ttl", ttl.to_string()),
                    ],
                )
                .await
                .map(|_| ())
            }
            None => {
                let mut extra = vec![
                    ("SiteId", site_id.to_string()),
                    ("RecordName", r.fqdn.to_string()),
                    ("Type", TYPE.to_string()),
                    ("Data", data(r.ip)),
                    ("Ttl", ttl.to_string()),
                ];
                // CNAME 接入的站点必须开启代理并指定业务名
                if access == "CNAME" {
                    extra.push(("Proxied", "true".into()));
                    extra.push(("BizName", "web".into()));
                }
                self.call(reqwest::Method::POST, "CreateRecord", &extra)
                    .await
                    .map(|_| ())
            }
        }
    }
}
