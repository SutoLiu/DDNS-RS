pub mod aliesa;
pub mod aliyun;
mod baidu;
pub mod callback;
mod cloudflare;
mod dnspod;
mod godaddy;
mod huawei;
mod namecheap;
mod porkbun;
pub mod sign;
mod tencent;
mod volcengine;

use async_trait::async_trait;

use crate::config::Provider as ProviderCfg;
use crate::error::Result;
use crate::ip::RecordKind;

pub struct Upsert<'a> {
    pub zone: &'a str,
    pub sub: &'a str,
    pub fqdn: &'a str,
    pub kind: RecordKind,
    pub ip: &'a str,
    pub ttl: u32,
}

#[async_trait]
pub trait Provider: Send + Sync {
    /// 记录已一致时直接返回
    async fn upsert(&self, req: &Upsert<'_>) -> Result<()>;
}

pub fn build(cfg: &ProviderCfg, client: reqwest::Client) -> Box<dyn Provider> {
    let t = |v: &str| v.trim().to_string();
    match cfg {
        ProviderCfg::Cloudflare { token, proxied } => {
            Box::new(cloudflare::Cloudflare::new(client, t(token), *proxied))
        }
        ProviderCfg::Aliyun {
            access_key_id,
            access_key_secret,
        } => Box::new(aliyun::Aliyun::new(
            client,
            t(access_key_id),
            t(access_key_secret),
        )),
        ProviderCfg::Aliesa {
            access_key_id,
            access_key_secret,
        } => Box::new(aliesa::Aliesa::new(
            client,
            t(access_key_id),
            t(access_key_secret),
        )),
        ProviderCfg::Tencent {
            secret_id,
            secret_key,
        } => Box::new(tencent::Tencent::new(client, t(secret_id), t(secret_key))),
        ProviderCfg::Dnspod { id, token } => Box::new(dnspod::Dnspod::new(client, t(id), t(token))),
        ProviderCfg::Huawei {
            access_key_id,
            secret_key,
        } => Box::new(huawei::Huawei::new(client, t(access_key_id), t(secret_key))),
        ProviderCfg::Baidu {
            access_key_id,
            secret_key,
        } => Box::new(baidu::Baidu::new(client, t(access_key_id), t(secret_key))),
        ProviderCfg::Volcengine {
            access_key_id,
            secret_key,
        } => Box::new(volcengine::Volcengine::new(
            client,
            t(access_key_id),
            t(secret_key),
        )),
        ProviderCfg::Porkbun {
            apikey,
            secretapikey,
        } => Box::new(porkbun::Porkbun::new(client, t(apikey), t(secretapikey))),
        ProviderCfg::Godaddy { key, secret } => {
            Box::new(godaddy::Godaddy::new(client, t(key), t(secret)))
        }
        ProviderCfg::Namecheap { password } => {
            Box::new(namecheap::Namecheap::new(client, t(password)))
        }
        ProviderCfg::Callback { url, body } => {
            Box::new(callback::Callback::new(client, t(url), t(body)))
        }
    }
}
