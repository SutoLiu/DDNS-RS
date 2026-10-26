use async_trait::async_trait;
use serde_json::{Value, json};

use super::sign::num;
use super::{Provider, Upsert};
use crate::error::{Error, Result};

const LIST: &str = "https://dnsapi.cn/Record.List";
const CREATE: &str = "https://dnsapi.cn/Record.Create";
const MODIFY: &str = "https://dnsapi.cn/Record.Modify";

pub struct Dnspod {
    client: reqwest::Client,
    id: String,
    token: String,
}

impl Dnspod {
    pub fn new(client: reqwest::Client, id: String, token: String) -> Self {
        Self { client, id, token }
    }

    /// 旧 API（dnsapi.cn），login_token 表单鉴权，code 1 成功
    async fn call(&self, url: &str, params: &[(&str, String)]) -> Result<Value> {
        let mut form: Vec<(&str, String)> = vec![
            ("login_token", format!("{},{}", self.id, self.token)),
            ("format", "json".into()),
        ];
        form.extend(params.iter().cloned());
        let v: Value = self
            .client
            .post(url)
            .form(&form)
            .send()
            .await?
            .json()
            .await?;
        match v["status"]["code"].as_str() {
            Some("1") => Ok(v),
            // Record.List 无记录返回码 10，映射空列表走创建
            Some("10") if url == LIST => Ok(json!({"records": []})),
            _ => Err(Error::Internal(format!(
                "DNSPod: {}",
                v["status"]["message"].as_str().unwrap_or("未知错误")
            ))),
        }
    }
}

#[async_trait]
impl Provider for Dnspod {
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        let ttl = if r.ttl == 0 { 600 } else { r.ttl };
        let kind = r.kind.as_str().to_string();
        // record_line 固定「默认」线路，查询同步过滤防误改其他线路
        let found = self
            .call(
                LIST,
                &[
                    ("domain", r.zone.to_string()),
                    ("sub_domain", r.sub.to_string()),
                    ("record_type", kind.clone()),
                    ("record_line", "默认".into()),
                ],
            )
            .await?;
        let rec = found["records"].as_array().and_then(|a| a.first());
        match rec {
            Some(rec)
                if rec["value"].as_str() == Some(r.ip) && num(&rec["ttl"]) == Some(ttl as i64) =>
            {
                Ok(())
            }
            Some(rec) => {
                let rid = num(&rec["id"]).map(|n| n.to_string()).unwrap_or_default();
                self.call(
                    MODIFY,
                    &[
                        ("domain", r.zone.to_string()),
                        ("sub_domain", r.sub.to_string()),
                        ("record_type", kind),
                        ("value", r.ip.to_string()),
                        ("ttl", ttl.to_string()),
                        ("record_id", rid),
                        ("record_line", "默认".into()),
                    ],
                )
                .await
                .map(|_| ())
            }
            None => self
                .call(
                    CREATE,
                    &[
                        ("domain", r.zone.to_string()),
                        ("sub_domain", r.sub.to_string()),
                        ("record_type", kind),
                        ("value", r.ip.to_string()),
                        ("ttl", ttl.to_string()),
                        ("record_line", "默认".into()),
                    ],
                )
                .await
                .map(|_| ()),
        }
    }
}
