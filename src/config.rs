use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub port: u16,
    pub not_allow_wan: bool,
    /// 为空表示尚未初始化
    pub pwd_hash: String,
    pub site_title: String,
    pub lang: String,
    pub log_cap: usize,
    pub token_ttl: u64,
    pub entries: Vec<Entry>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 9999,
            not_allow_wan: false,
            pwd_hash: String::new(),
            site_title: "DDNS-RS".into(),
            lang: "zh-cn".into(),
            log_cap: 50,
            token_ttl: 1800,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Poll,
    Listen,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    pub name: String,
    pub enabled: bool,
    pub mode: Mode,
    pub interval: u64,
    pub watch: Vec<String>,
    pub zone: String,
    pub sub_domains: String,
    /// 0 表示服务商默认值
    pub ttl: u32,
    pub ipv4: Family,
    pub ipv6: Family,
    pub provider: Provider,
}

impl Default for Entry {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            mode: Mode::Poll,
            interval: 300,
            watch: Vec::new(),
            zone: String::new(),
            sub_domains: String::new(),
            ttl: 0,
            ipv4: Family::default(),
            ipv6: Family::default(),
            provider: Provider::default(),
        }
    }
}

impl Entry {
    pub fn subs(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .sub_domains
            .split(['\n', ',', ' ', '\t'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if v.is_empty() {
            v.push("@".into());
        }
        v.sort();
        v.dedup();
        v
    }

    pub fn fqdn(&self, sub: &str) -> String {
        if sub.is_empty() || sub == "@" {
            self.zone.clone()
        } else {
            format!("{sub}.{}", self.zone)
        }
    }

    /// 超出 eTLD+1 的标签挪到子域前部
    pub fn normalize(&mut self) {
        // 空来源块须在 zone 早退前剔除
        for f in [&mut self.ipv4, &mut self.ipv6] {
            f.sources.retain(|s| !s.is_blank());
        }
        self.zone = self.zone.trim().to_lowercase();
        let Some(root) = psl::domain_str(&self.zone) else {
            return;
        };
        let Some(extra) = self
            .zone
            .strip_suffix(root)
            .and_then(|r| r.strip_suffix('.'))
        else {
            return;
        };
        if extra.is_empty() {
            return;
        }
        let (root, extra) = (root.to_owned(), extra.to_owned());
        self.zone = root;
        let head = self.sub_domains.trim();
        self.sub_domains = if head.is_empty() || head == "@" {
            extra
        } else {
            format!("{extra},{head}")
        };
    }
}

/// IDN 转 punycode（服务商 API 仅接受 ASCII）
pub fn to_punycode(s: &str) -> String {
    idna::domain_to_ascii(s).unwrap_or_else(|_| s.to_string())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Family {
    pub enabled: bool,
    /// 有序来源块，逐块回退取首命中
    pub sources: Vec<Source>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Source {
    #[serde(rename = "netInterface")]
    NetInterface { name: Vec<String> },
    #[serde(rename = "url")]
    Url { url: Vec<String> },
    #[serde(rename = "cmd")]
    Cmd { cmd: String },
}

impl Source {
    pub fn is_blank(&self) -> bool {
        match self {
            Self::NetInterface { name } => name.iter().all(|s| s.trim().is_empty()),
            Self::Url { url } => url.iter().all(|s| s.trim().is_empty()),
            Self::Cmd { cmd } => cmd.trim().is_empty(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Provider {
    Cloudflare {
        token: String,
        #[serde(default)]
        proxied: bool,
    },
    Aliyun {
        access_key_id: String,
        access_key_secret: String,
    },
    Aliesa {
        access_key_id: String,
        access_key_secret: String,
    },
    Tencent {
        secret_id: String,
        secret_key: String,
    },
    Dnspod {
        id: String,
        token: String,
    },
    Huawei {
        access_key_id: String,
        secret_key: String,
    },
    Baidu {
        access_key_id: String,
        secret_key: String,
    },
    Volcengine {
        access_key_id: String,
        secret_key: String,
    },
    Porkbun {
        apikey: String,
        secretapikey: String,
    },
    Godaddy {
        key: String,
        secret: String,
    },
    Namecheap {
        password: String,
    },
    Callback {
        url: String,
        #[serde(default)]
        body: String,
    },
}

impl Default for Provider {
    fn default() -> Self {
        Provider::Aliyun {
            access_key_id: String::new(),
            access_key_secret: String::new(),
        }
    }
}

impl Provider {
    pub fn kind(&self) -> &'static str {
        match self {
            Provider::Cloudflare { .. } => "cloudflare",
            Provider::Aliyun { .. } => "aliyun",
            Provider::Aliesa { .. } => "aliesa",
            Provider::Tencent { .. } => "tencent",
            Provider::Dnspod { .. } => "dnspod",
            Provider::Huawei { .. } => "huawei",
            Provider::Baidu { .. } => "baidu",
            Provider::Volcengine { .. } => "volcengine",
            Provider::Porkbun { .. } => "porkbun",
            Provider::Godaddy { .. } => "godaddy",
            Provider::Namecheap { .. } => "namecheap",
            Provider::Callback { .. } => "callback",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Provider::Cloudflare { .. } => "Cloudflare",
            Provider::Aliyun { .. } => "阿里云",
            Provider::Aliesa { .. } => "阿里云 ESA",
            Provider::Tencent { .. } => "腾讯云",
            Provider::Dnspod { .. } => "DNSPod",
            Provider::Huawei { .. } => "华为云",
            Provider::Baidu { .. } => "百度云",
            Provider::Volcengine { .. } => "火山引擎",
            Provider::Porkbun { .. } => "Porkbun",
            Provider::Godaddy { .. } => "GoDaddy",
            Provider::Namecheap { .. } => "Namecheap",
            Provider::Callback { .. } => "Callback",
        }
    }

    /// 纯通知型：同址免强制重发（新增此类服务商在此登记）
    pub fn notify_only(&self) -> bool {
        matches!(self, Self::Callback { .. })
    }

    /// 凭据缺失项，留空即缺（新增服务商在此登记）
    pub fn missing(&self) -> Vec<&'static str> {
        let mut miss = Vec::new();
        let mut need = |v: &str, n: &'static str| {
            if v.trim().is_empty() {
                miss.push(n)
            }
        };
        match self {
            Self::Cloudflare { token, .. } => need(token, "API Token"),
            Self::Aliyun {
                access_key_id,
                access_key_secret,
            }
            | Self::Aliesa {
                access_key_id,
                access_key_secret,
            } => {
                need(access_key_id, "AccessKey ID");
                need(access_key_secret, "AccessKey Secret");
            }
            Self::Tencent {
                secret_id,
                secret_key,
            } => {
                need(secret_id, "SecretId");
                need(secret_key, "SecretKey");
            }
            Self::Dnspod { id, token } => {
                need(id, "ID");
                need(token, "Token");
            }
            Self::Huawei {
                access_key_id,
                secret_key,
            }
            | Self::Baidu {
                access_key_id,
                secret_key,
            }
            | Self::Volcengine {
                access_key_id,
                secret_key,
            } => {
                need(access_key_id, "Access Key ID");
                need(secret_key, "Secret Access Key");
            }
            Self::Porkbun {
                apikey,
                secretapikey,
            } => {
                need(apikey, "API Key");
                need(secretapikey, "Secret API Key");
            }
            Self::Godaddy { key, secret } => {
                need(key, "Key");
                need(secret, "Secret");
            }
            Self::Namecheap { password } => need(password, "Dynamic DNS Password"),
            Self::Callback { url, .. } => need(url, "URL"),
        }
        miss
    }
}

impl Config {
    pub async fn load(path: &Path) -> Result<Self> {
        match read_json(path).await? {
            Some(c) => Ok(c),
            None => {
                tracing::info!("config: 未找到配置，使用默认值");
                Ok(Self::default())
            }
        }
    }

    /// 只改口令并保留未知字段，解析失败拒绝写入防覆盖
    pub async fn reset_pwd_hash(path: &Path, hash: &str) -> Result<()> {
        let mut doc = match read_json::<serde_json::Value>(path).await? {
            Some(d) => d,
            None => {
                return write_json(
                    path.to_path_buf(),
                    &Config {
                        pwd_hash: hash.into(),
                        ..Self::default()
                    },
                )
                .await;
            }
        };
        doc.as_object_mut()
            .ok_or_else(|| Error::Internal(format!("{path:?} 根结构非对象，拒绝重置以防覆盖")))?
            .insert("pwd_hash".into(), hash.into());
        write_json(path.to_path_buf(), &doc).await
    }

    pub fn validate(&mut self) -> Result<()> {
        for e in &mut self.entries {
            e.normalize();
        }
        if self.site_title.trim().is_empty() {
            self.site_title = "DDNS-RS".into();
        }
        if !["zh-cn", "zh-tw", "en"].contains(&self.lang.as_str()) {
            self.lang = "zh-cn".into();
        }
        if !(50..=2000).contains(&self.log_cap) {
            self.log_cap = 50;
        }
        // 下限 60 秒防 0 值登录即过期
        self.token_ttl = self.token_ttl.max(60);
        if self.port == 0 {
            return Err(Error::Arg("监听端口须为 1-65535".into()));
        }
        if self.site_title.chars().count() > 64 {
            return Err(Error::Arg("网站标题过长（至多 64 字符）".into()));
        }
        for e in &self.entries {
            e.validate()?;
        }
        Ok(())
    }
}

impl Entry {
    pub fn validate(&self) -> Result<()> {
        let name = if self.name.trim().is_empty() {
            "未命名任务"
        } else {
            self.name.trim()
        };
        if self.mode == Mode::Poll && !(10..=86_400).contains(&self.interval) {
            return Err(Error::Arg(format!(
                "「{name}」轮询间隔需在 10-86400 秒之间"
            )));
        }
        if self.zone.trim().is_empty() {
            return Err(Error::Arg(format!("「{name}」缺少根域名")));
        }
        if !self.zone.contains('.') {
            return Err(Error::Arg(format!("「{name}」根域名格式不正确")));
        }
        for f in [&self.ipv4, &self.ipv6] {
            if f.enabled && f.sources.iter().all(Source::is_blank) {
                return Err(Error::Arg(format!("「{name}」取址来源不能为空")));
            }
        }
        if !self.ipv4.enabled && !self.ipv6.enabled {
            return Err(Error::Arg(format!("「{name}」至少启用 IPv4 或 IPv6")));
        }
        if matches!(self.provider, Provider::Namecheap { .. }) && self.ipv6.enabled {
            return Err(Error::Arg(format!("「{name}」Namecheap 不支持 IPv6 更新")));
        }
        let miss = self.provider.missing();
        if !miss.is_empty() {
            let label = self.provider.label();
            let gap = if label.starts_with(|c: char| c.is_ascii()) {
                " "
            } else {
                ""
            };
            return Err(Error::Arg(format!(
                "「{name}」缺少{gap}{label} {}",
                miss.join("、")
            )));
        }
        Ok(())
    }
}

pub struct ConfigStore {
    inner: tokio::sync::RwLock<Arc<Config>>,
    /// 串行保存，防并发覆盖或写坏临时文件
    lock: tokio::sync::Mutex<()>,
    path: PathBuf,
    /// entries 变化才递增，引擎据此重建运行态
    revision: AtomicU64,
}

impl ConfigStore {
    pub fn new(cfg: Config, path: PathBuf) -> Self {
        Self {
            inner: tokio::sync::RwLock::new(Arc::new(cfg)),
            lock: tokio::sync::Mutex::new(()),
            path,
            revision: AtomicU64::new(0),
        }
    }

    pub async fn get(&self) -> Arc<Config> {
        self.inner.read().await.clone()
    }

    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }

    /// 口令以落盘为准，只解析单字段容错结构差异；文件缺失回退内存值
    pub async fn pwd_hash(&self) -> Result<String> {
        Ok(match read_json::<serde_json::Value>(&self.path).await? {
            Some(v) => v["pwd_hash"].as_str().unwrap_or_default().to_string(),
            None => self.get().await.pwd_hash.clone(),
        })
    }

    /// 唯一写入门：口令以落盘为准，非法配置不触达套接字
    pub async fn replace(&self, mut next: Config) -> Result<bool> {
        let _g = self.lock.lock().await;
        next.pwd_hash = self.pwd_hash().await?;
        self.commit(next).await
    }

    /// 仅未初始化时写入，返回是否抢到初始化权
    pub async fn init_pwd_hash(&self, hash: String) -> Result<bool> {
        let _g = self.lock.lock().await;
        if !self.pwd_hash().await?.is_empty() {
            return Ok(false);
        }
        let mut next = (*self.get().await).clone();
        next.pwd_hash = hash;
        self.commit(next).await?;
        Ok(true)
    }

    pub async fn set_pwd_hash(&self, hash: String) -> Result<()> {
        let _g = self.lock.lock().await;
        let mut next = (*self.get().await).clone();
        next.pwd_hash = hash;
        self.commit(next).await?;
        Ok(())
    }

    /// 落盘成功才提交内存，entries 变化才递增 revision
    async fn commit(&self, next: Config) -> Result<bool> {
        let changed = self.get().await.entries != next.entries;
        write_json(self.path.clone(), &next).await?;
        *self.inner.write().await = Arc::new(next);
        if changed {
            self.revision.fetch_add(1, Ordering::Relaxed);
        }
        Ok(changed)
    }
}

/// 文件缺失返回 None，剥离 BOM；解析失败拒绝静默重建，须人工修复
async fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    let text = match tokio::fs::read_to_string(path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Internal(format!("读取 {path:?} 失败: {e}"))),
    };
    serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .map(Some)
        .map_err(|e| Error::Internal(format!("{path:?} 解析失败: {e}，请修复或删除该文件")))
}

async fn write_json<T: Serialize>(path: PathBuf, value: &T) -> Result<()> {
    let mut json = serde_json::to_string_pretty(value)
        .map_err(|e| Error::Internal(format!("序列化失败: {e}")))?;
    json.push('\n');
    tokio::task::spawn_blocking(move || write_atomic(&path, &json))
        .await
        .map_err(|e| Error::Internal(format!("保存任务失败: {e}")))?
}

fn write_atomic(path: &Path, body: &str) -> Result<()> {
    // 临时名带进程号，防并发写互踩
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let mut f = std::fs::File::create(&tmp)
        .map_err(|e| Error::Internal(format!("创建 {tmp:?} 失败: {e}")))?;
    f.write_all(body.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| Error::Internal(format!("写入 {tmp:?} 失败: {e}")))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| Error::Internal(format!("替换 {path:?} 失败: {e}")))
}
