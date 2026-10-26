use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use reqwest::Method;
use serde_json::{Value, json};

use super::sign::{hex, hmac_sha256, pe, sha256_hex, utc_datetime};
use super::{Provider, Upsert};
use crate::error::{Error, Result};

const API: &str = "https://open.volcengineapi.com";
const HOST: &str = "open.volcengineapi.com";
const VERSION: &str = "2018-08-01";
const SERVICE: &str = "DNS";
const REGION: &str = "cn-north-1";

pub struct Volcengine {
    client: reqwest::Client,
    ak: String,
    sk: String,
    zones: Mutex<HashMap<String, i64>>,
}

impl Volcengine {
    pub fn new(client: reqwest::Client, ak: String, sk: String) -> Self {
        Self {
            client,
            ak,
            sk,
            zones: Mutex::new(HashMap::new()),
        }
    }

    /// ListZones 为模糊搜索，须精确比对 ZoneName 取 ZID
    async fn zid(&self, zone: &str) -> Result<i64> {
        if let Some(z) = self
            .zones
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(zone)
        {
            return Ok(*z);
        }
        let v = self
            .call(Method::GET, "ListZones", &[("Key", zone.to_string())], "")
            .await?;
        let zid = v["Result"]["Zones"]
            .as_array()
            .and_then(|a| a.iter().find(|z| z["ZoneName"].as_str() == Some(zone)))
            .and_then(|z| z["ZID"].as_i64())
            .ok_or_else(|| Error::Internal(format!("火山引擎未找到域名 {zone} 的 Zone")))?;
        self.zones
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(zone.to_string(), zid);
        Ok(zid)
    }

    /// 类 AWS SigV4 签名；签名与实发须同一份排序查询串
    async fn call(
        &self,
        method: Method,
        action: &str,
        query: &[(&str, String)],
        body: &str,
    ) -> Result<Value> {
        let mut params: Vec<(String, String)> = vec![
            ("Action".into(), action.into()),
            ("Version".into(), VERSION.into()),
        ];
        params.extend(query.iter().map(|(k, v)| (k.to_string(), v.clone())));
        params.sort();
        let qs = params
            .iter()
            .map(|(k, v)| format!("{}={}", pe(k), pe(v)))
            .collect::<Vec<_>>()
            .join("&");
        let xdate = utc_datetime();
        let hash = sha256_hex(body);
        let canonical = format!(
            "{}\n/\n{qs}\ncontent-type:application/json\nhost:{HOST}\nx-content-sha256:{hash}\nx-date:{xdate}\n\ncontent-type;host;x-content-sha256;x-date\n{hash}",
            method.as_str()
        );
        let scope = format!("{}/{REGION}/{SERVICE}/request", &xdate[..8]);
        let string_to_sign = format!("HMAC-SHA256\n{xdate}\n{scope}\n{}", sha256_hex(&canonical));
        let k_date = hmac_sha256(self.sk.as_bytes(), &xdate[..8]);
        let k_region = hmac_sha256(&k_date, REGION);
        let k_service = hmac_sha256(&k_region, SERVICE);
        let k_signing = hmac_sha256(&k_service, "request");
        let signature = hex(&hmac_sha256(&k_signing, &string_to_sign));
        let auth = format!(
            "HMAC-SHA256 Credential={}/{scope}, SignedHeaders=content-type;host;x-content-sha256;x-date, Signature={signature}",
            self.ak
        );
        let req = self
            .client
            .request(method, format!("{API}/?{qs}"))
            .header("Content-Type", "application/json")
            .header("X-Date", &xdate)
            .header("X-Content-Sha256", &hash)
            .header("Authorization", auth);
        let req = if body.is_empty() {
            req
        } else {
            req.body(body.to_string())
        };
        let v: Value = req.send().await?.json().await?;
        if let Some(code) = v["ResponseMetadata"]["Error"]["Code"].as_str() {
            let msg = v["ResponseMetadata"]["Error"]["Message"]
                .as_str()
                .unwrap_or("");
            return Err(Error::Internal(format!("火山引擎 {code}: {msg}")));
        }
        Ok(v)
    }
}

#[async_trait]
impl Provider for Volcengine {
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        let zid = self.zid(r.zone).await?;
        let ttl = if r.ttl == 0 { 600 } else { r.ttl };
        let kind = r.kind.as_str().to_string();
        let list = self
            .call(
                Method::GET,
                "ListRecords",
                &[
                    ("ZID", zid.to_string()),
                    ("Type", kind.clone()),
                    ("Host", r.sub.to_string()),
                    ("SearchMode", "exact".into()),
                    ("PageNumber", "1".into()),
                    ("PageSize", "500".into()),
                ],
                "",
            )
            .await?;
        // 防御服务端差异，精确模式下再校验一次
        let rec = list["Result"]["Records"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["Host"].as_str() == Some(r.sub)));
        match rec {
            Some(rec)
                if rec["Value"].as_str() == Some(r.ip)
                    && rec["TTL"].as_i64() == Some(ttl as i64) =>
            {
                Ok(())
            }
            Some(rec) => {
                // 回带原线路，避免丢失自定义线路
                let body = json!({
                    "ZID": zid, "RecordID": rec["RecordID"], "Host": r.sub, "Type": kind,
                    "Value": r.ip, "TTL": ttl, "Line": rec["Line"].as_str().unwrap_or("default"),
                })
                .to_string();
                self.call(Method::POST, "UpdateRecord", &[], &body)
                    .await
                    .map(|_| ())
            }
            None => {
                let body = json!({
                    "ZID": zid, "Host": r.sub, "Type": kind,
                    "Value": r.ip, "TTL": ttl, "Line": "default",
                })
                .to_string();
                self.call(Method::POST, "CreateRecord", &[], &body)
                    .await
                    .map(|_| ())
            }
        }
    }
}
