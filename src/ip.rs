use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::config::Source;
use crate::net::Iface;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    A,
    Aaaa,
}

const CMD_TIMEOUT: Duration = Duration::from_secs(20);

impl RecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::A => "A",
            RecordKind::Aaaa => "AAAA",
        }
    }
}

pub fn iface_addr(list: &[Iface], pats: &[String], kind: RecordKind) -> Option<IpAddr> {
    pats.iter().find_map(|p| {
        list.iter()
            .filter(|i| crate::net::glob_match(p, &i.name))
            .find_map(|i| match kind {
                RecordKind::A => i.v4.map(IpAddr::V4),
                RecordKind::Aaaa => i.v6.map(IpAddr::V6),
            })
    })
}

/// 轮内取址上下文：网卡快照同轮共享，同源只执行一次（未命中亦缓存）
pub struct Resolver<'a> {
    ifaces: &'a [Iface],
    cache: HashMap<(Source, RecordKind), Option<IpAddr>>,
}

impl<'a> Resolver<'a> {
    pub fn new(ifaces: &'a [Iface]) -> Self {
        Self {
            ifaces,
            cache: HashMap::new(),
        }
    }

    pub async fn resolve(
        &mut self,
        client: &reqwest::Client,
        srcs: &[Source],
        kind: RecordKind,
    ) -> Option<IpAddr> {
        for s in srcs {
            let key = (s.clone(), kind);
            let hit = match self.cache.get(&key) {
                Some(v) => *v,
                None => {
                    let v = resolve_one(client, s, kind, self.ifaces).await;
                    self.cache.insert(key, v);
                    v
                }
            };
            if hit.is_some() {
                return hit;
            }
        }
        None
    }
}

async fn resolve_one(
    client: &reqwest::Client,
    src: &Source,
    kind: RecordKind,
    ifaces: &[Iface],
) -> Option<IpAddr> {
    match src {
        Source::NetInterface { name } => iface_addr(ifaces, name, kind),
        Source::Url { url } => {
            for u in url.iter().filter(|u| !u.trim().is_empty()) {
                if let Some(ip) = fetch(client, u).await.and_then(|t| pick(&t, kind)) {
                    return Some(ip);
                }
            }
            None
        }
        Source::Cmd { cmd } => tokio::time::timeout(CMD_TIMEOUT, shell(cmd).output())
            .await
            .ok()
            .and_then(|r| r.ok())
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .and_then(|out| pick(&out, kind)),
    }
}

async fn fetch(client: &reqwest::Client, url: &str) -> Option<String> {
    client
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .text()
        .await
        .ok()
}

/// 命令随句柄释放即终止，防超时后残留子进程
fn shell(cmd: &str) -> tokio::process::Command {
    #[cfg(windows)]
    let mut c = tokio::process::Command::new("powershell");
    #[cfg(windows)]
    c.args(["-NoProfile", "-Command", cmd]);
    #[cfg(not(windows))]
    let mut c = tokio::process::Command::new("sh");
    #[cfg(not(windows))]
    c.args(["-c", cmd]);
    c.kill_on_drop(true);
    c
}

pub fn pick(text: &str, kind: RecordKind) -> Option<IpAddr> {
    // v6 含内嵌 IPv4，须保留「.」；剥句读残留，mapped 归 v4 族
    let in_word = |c: char| match kind {
        RecordKind::A => c.is_ascii_digit() || c == '.',
        RecordKind::Aaaa => c.is_ascii_hexdigit() || c == ':' || c == '.',
    };
    text.split(|c| !in_word(c)).find_map(|s| {
        s.trim_matches('.')
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical())
            .filter(|ip| ip.is_ipv6() == matches!(kind, RecordKind::Aaaa))
    })
}
