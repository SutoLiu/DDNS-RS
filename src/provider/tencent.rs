use async_trait::async_trait;
use serde_json::{Value, json};

use super::sign::{hex, hmac_sha256, sha256_hex, utc_date};
use super::{Provider, Upsert};
use crate::error::{Error, Result};

const API: &str = "https://dnspod.tencentcloudapi.com";
const VERSION: &str = "2021-03-23";

pub struct Tencent {
    client: reqwest::Client,
    id: String,
    key: String,
}

impl Tencent {
    pub fn new(client: reqwest::Client, id: String, key: String) -> Self {
        Self { client, id, key }
    }

    async fn call(&self, action: &str, body: &Value) -> Result<Value> {
        let payload = serde_json::to_string(body)
            .map_err(|e| Error::Internal(format!("序列化请求失败: {e}")))?;
        let ts = crate::now_secs();
        let date = utc_date();
        let scope = format!("{date}/dnspod/tc3_request");
        let canonical = format!(
            "POST\n/\n\ncontent-type:application/json\nhost:dnspod.tencentcloudapi.com\nx-tc-action:{}\n\ncontent-type;host;x-tc-action\n{}",
            action.to_lowercase(),
            sha256_hex(&payload),
        );
        let string_to_sign = format!("TC3-HMAC-SHA256\n{ts}\n{scope}\n{}", sha256_hex(&canonical));
        let k_date = hmac_sha256(format!("TC3{}", self.key).as_bytes(), &date);
        let k_service = hmac_sha256(&k_date, "dnspod");
        let k_signing = hmac_sha256(&k_service, "tc3_request");
        let signature = hex(&hmac_sha256(&k_signing, &string_to_sign));
        let auth = format!(
            "TC3-HMAC-SHA256 Credential={}/{scope}, SignedHeaders=content-type;host;x-tc-action, Signature={signature}",
            self.id
        );
        let v: Value = self
            .client
            .post(API)
            .header("Content-Type", "application/json")
            .header("Authorization", auth)
            .header("X-TC-Action", action)
            .header("X-TC-Timestamp", ts.to_string())
            .header("X-TC-Version", VERSION)
            .body(payload)
            .send()
            .await?
            .json()
            .await?;
        if let Some(code) = v["Response"]["Error"]["Code"].as_str() {
            // 官方错误码「无记录」视为空列表，走创建
            if code == "ResourceNotFound.NoDataOfRecord" {
                return Ok(json!({"Response": {"RecordList": []}}));
            }
            let msg = v["Response"]["Error"]["Message"].as_str().unwrap_or("");
            return Err(Error::Internal(format!("腾讯云 {code}: {msg}")));
        }
        Ok(v)
    }
}

#[async_trait]
impl Provider for Tencent {
    async fn upsert(&self, r: &Upsert<'_>) -> Result<()> {
        let ttl = if r.ttl == 0 { 600 } else { r.ttl };
        let kind = r.kind.as_str().to_string();
        // 子域名字段为 Subdomain，根域名传 @
        let list = self
            .call(
                "DescribeRecordList",
                &json!({"Domain": r.zone, "Subdomain": r.sub, "RecordType": kind, "RecordLine": "默认"}),
            )
            .await?;
        let rec = list["Response"]["RecordList"]
            .as_array()
            .and_then(|a| a.first());
        match rec {
            Some(rec)
                if rec["Value"].as_str() == Some(r.ip)
                    && rec["TTL"].as_i64() == Some(ttl as i64) =>
            {
                Ok(())
            }
            Some(rec) => {
                let rid = rec["RecordId"].as_i64().unwrap_or_default();
                self.call(
                    "ModifyRecord",
                    &json!({"Domain": r.zone, "SubDomain": r.sub, "RecordType": kind,
                        "RecordLine": "默认", "Value": r.ip, "TTL": ttl, "RecordId": rid}),
                )
                .await
                .map(|_| ())
            }
            None => self
                .call(
                    "CreateRecord",
                    &json!({"Domain": r.zone, "SubDomain": r.sub, "RecordType": kind,
                        "RecordLine": "默认", "Value": r.ip, "TTL": ttl}),
                )
                .await
                .map(|_| ()),
        }
    }
}
