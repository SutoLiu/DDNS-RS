use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::{Mutex, Notify};
use tokio::time::Instant;

use crate::config::{Config, ConfigStore, Entry, Mode, to_punycode};
use crate::ip::{RecordKind, Resolver};
use crate::net::{Iface, NetMonitor};
use crate::provider::{self, Upsert};

/// 每 N 次强制比对服务商，防外部改动不纠正
const COMPARE_EVERY: u32 = 5;
const FAIL_STREAK: u32 = 3;

#[derive(Serialize, Clone, Default)]
pub struct FamilyStatus {
    pub ip: String,
    pub state: State,
    pub message: String,
}

#[derive(Serialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum State {
    #[default]
    Idle,
    Ok,
    Err,
}

#[derive(Serialize, Clone)]
pub struct EntryStatus {
    pub name: String,
    pub provider: String,
    pub enabled: bool,
    pub mode: Mode,
    pub interval: u64,
    pub v4_enabled: bool,
    pub v6_enabled: bool,
    pub domains: Vec<String>,
    pub ipv4: FamilyStatus,
    pub ipv6: FamilyStatus,
}

impl EntryStatus {
    fn new(e: &Entry) -> Self {
        Self {
            name: if e.name.trim().is_empty() {
                e.zone.clone()
            } else {
                e.name.clone()
            },
            provider: e.provider.kind().to_string(),
            enabled: e.enabled,
            mode: e.mode,
            interval: e.interval,
            v4_enabled: e.enabled && e.ipv4.enabled,
            v6_enabled: e.enabled && e.ipv6.enabled,
            domains: e.subs().iter().map(|s| e.fqdn(s)).collect(),
            ipv4: FamilyStatus::default(),
            ipv6: FamilyStatus::default(),
        }
    }

    fn fam_mut(&mut self, k: RecordKind) -> &mut FamilyStatus {
        match k {
            RecordKind::A => &mut self.ipv4,
            RecordKind::Aaaa => &mut self.ipv6,
        }
    }
}

#[derive(Serialize, Clone)]
pub struct LogItem {
    pub time: u64,
    pub level: &'static str,
    pub msg: String,
}

#[derive(Serialize, Clone, Default)]
pub struct Status {
    pub busy: bool,
    pub listen_ok: bool,
    pub last_run: Option<u64>,
    pub version: &'static str,
    pub logs: Vec<LogItem>,
    pub entries: Vec<EntryStatus>,
}

enum Trigger {
    All,
    Listen(Vec<String>),
    Timer,
}

#[derive(Default)]
struct FamSlot {
    /// (上次地址, 剩余免比对次数)
    addr: Option<(IpAddr, u32)>,
    streak: u32,
}

#[derive(Default)]
struct FamState {
    v4: FamSlot,
    v6: FamSlot,
}

/// 随配置 revision 失效重建
#[derive(Default)]
struct RunState {
    fam: HashMap<usize, FamState>,
    due: HashMap<usize, Instant>,
    provs: HashMap<usize, Box<dyn provider::Provider>>,
}

pub struct Engine {
    cfg: Arc<ConfigStore>,
    status: Mutex<Status>,
    logs: Mutex<VecDeque<LogItem>>,
    kick: Notify,
    event: Notify,
    listen_ok: AtomicBool,
    monitor: tokio::sync::Mutex<MonitorSlot>,
    client: reqwest::Client,
    /// 禁代理并按地址族绑定出口，防代理污染
    echo: [reqwest::Client; 2],
}

/// 句柄与转发任务成对持有，Drop 时注销系统通知
#[derive(Default)]
struct MonitorSlot {
    mon: Option<Arc<NetMonitor>>,
    task: Option<tokio::task::JoinHandle<()>>,
    warned: bool,
}

fn echo_client(local: IpAddr) -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(concat!("ddns-rs/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(20))
        .no_proxy()
        .local_address(local)
        .build()
        .expect("构建回显客户端失败")
}

/// 滚动快照并返回增删改网口名，供 watch 过滤
fn iface_changed(snap: &mut Vec<Iface>, cur: &[Iface]) -> Vec<String> {
    let hit = cur
        .iter()
        .filter(|i| !snap.contains(i))
        .chain(
            snap.iter()
                .filter(|o| !cur.iter().any(|i| i.name == o.name)),
        )
        .map(|i| i.name.clone())
        .collect();
    *snap = cur.to_vec();
    hit
}

impl Engine {
    pub fn new(cfg: Arc<ConfigStore>) -> Arc<Self> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("ddns-rs/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(20))
            .build()
            .expect("构建 HTTP 客户端失败");
        let mut logs = VecDeque::new();
        logs.push_front(LogItem {
            time: crate::now_secs(),
            level: "info",
            msg: "欢迎使用 ddns-rs".into(),
        });
        logs.push_front(LogItem {
            time: crate::now_secs(),
            level: "info",
            msg: "主页 http://ddns-rs.suto.top".into(),
        });
        Arc::new(Self {
            cfg,
            status: Mutex::new(Status::default()),
            logs: Mutex::new(logs),
            kick: Notify::new(),
            event: Notify::new(),
            listen_ok: AtomicBool::new(crate::net::supported()),
            monitor: tokio::sync::Mutex::new(MonitorSlot::default()),
            client,
            echo: [
                echo_client(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                echo_client(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            ],
        })
    }

    pub fn kick(&self) {
        self.kick.notify_one();
    }

    pub async fn clear_logs(&self) {
        self.logs.lock().await.clear();
    }

    pub async fn status(&self) -> Status {
        let mut s = self.status.lock().await.clone();
        s.listen_ok = self.listen_ok.load(Ordering::Relaxed);
        s.version = env!("CARGO_PKG_VERSION");
        s.logs = self.logs.lock().await.clone().into();
        s
    }

    async fn log(&self, level: &'static str, msg: String) {
        match level {
            "error" => tracing::error!("{msg}"),
            "warn" => tracing::warn!("{msg}"),
            _ => tracing::info!("{msg}"),
        }
        // 先取上限再锁日志，避免持锁取配置锁
        let cap = self.cfg.get().await.log_cap;
        let mut logs = self.logs.lock().await;
        logs.push_front(LogItem {
            time: crate::now_secs(),
            level,
            msg,
        });
        logs.truncate(cap);
    }

    pub async fn run(self: Arc<Self>) {
        let mut rs = RunState::default();
        let mut rev = u64::MAX;
        let mut snap: Vec<Iface> = Vec::new();
        loop {
            // rev 初值 MAX 保证首轮全量
            let mut changed = false;
            let t = if self.cfg.revision() != rev {
                rev = self.cfg.revision();
                rs = RunState::default();
                changed = true;
                Trigger::All
            } else {
                let next = rs.due.values().copied().min();
                tokio::select! {
                    _ = async {
                        match next {
                            Some(t) => tokio::time::sleep_until(t).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => Trigger::Timer,
                    _ = self.kick.notified() => Trigger::All,
                    _ = self.event.notified() => Trigger::Listen(Vec::new()),
                }
            };
            let conf = self.cfg.get().await;
            // 唤醒代际可能已变，交回循环顶重建
            if self.cfg.revision() != rev {
                continue;
            }
            // 事件源启停仅在配置变更轮处理，避免失效重试忙循环
            if changed {
                self.sync_monitor(&conf).await;
            }
            // 快照须在事件源生效后取，防启动间隙漏检
            let ifaces = crate::net::ifaces();
            if changed {
                snap = ifaces.clone();
            }
            let t = match t {
                Trigger::Listen(_) => {
                    let hit = iface_changed(&mut snap, &ifaces);
                    if hit.is_empty() {
                        continue;
                    }
                    Trigger::Listen(hit)
                }
                other => other,
            };
            self.apply(&conf, &ifaces, &mut rs, t).await;
        }
    }

    async fn sync_monitor(self: &Arc<Self>, conf: &Config) {
        let need = conf
            .entries
            .iter()
            .any(|e| e.enabled && e.mode == Mode::Listen);
        let mut slot = self.monitor.lock().await;
        if need && slot.mon.is_none() {
            match NetMonitor::new() {
                Ok(m) => {
                    let m = Arc::new(m);
                    self.listen_ok.store(true, Ordering::Relaxed);
                    slot.warned = false;
                    self.log("info", "已启用地址变化事件监听".into()).await;
                    let (engine, mm) = (self.clone(), m.clone());
                    slot.task = Some(tokio::spawn(async move {
                        while mm.wait().await {
                            engine.event.notify_one();
                        }
                        engine.listen_ok.store(false, Ordering::Relaxed);
                        let mut slot = engine.monitor.lock().await;
                        slot.mon.take();
                        slot.task.take();
                        engine.kick.notify_one();
                    }));
                    slot.mon = Some(m);
                }
                Err(e) if !slot.warned => {
                    slot.warned = true;
                    self.listen_ok.store(false, Ordering::Relaxed);
                    self.log(
                        "warn",
                        format!("事件驱动不可用，监听任务按各自间隔轮询: {e}"),
                    )
                    .await;
                }
                Err(_) => {}
            }
        } else if !need && slot.mon.is_some() {
            if let Some(t) = slot.task.take() {
                t.abort();
            }
            slot.mon.take();
            self.log("info", "已停止地址变化事件监听".into()).await;
        }
    }

    async fn apply(&self, conf: &Config, ifaces: &[Iface], rs: &mut RunState, t: Trigger) {
        let started = crate::now_secs();
        let old = {
            let mut s = self.status.lock().await;
            s.busy = true;
            s.entries.clone()
        };
        let now = Instant::now();
        let listen_ok = self.listen_ok.load(Ordering::Relaxed);
        let mut res = Resolver::new(ifaces);
        let mut out = Vec::with_capacity(conf.entries.len());
        for (i, e) in conf.entries.iter().enumerate() {
            let run = e.enabled
                && match &t {
                    Trigger::All => true,
                    Trigger::Listen(hit) => {
                        e.mode == Mode::Listen
                            && (e.watch.is_empty()
                                || hit
                                    .iter()
                                    .any(|n| e.watch.iter().any(|p| crate::net::glob_match(p, n))))
                    }
                    Trigger::Timer => rs.due.get(&i).is_some_and(|d| *d <= now),
                };
            let mut st = if run || matches!(t, Trigger::All) {
                EntryStatus::new(e)
            } else {
                old.get(i).cloned().unwrap_or_else(|| EntryStatus::new(e))
            };
            if run {
                let prov = rs
                    .provs
                    .entry(i)
                    .or_insert_with(|| provider::build(&e.provider, self.client.clone()));
                let slot = rs.fam.entry(i).or_default();
                for (kind, fam) in [
                    (RecordKind::A, &mut slot.v4),
                    (RecordKind::Aaaa, &mut slot.v6),
                ] {
                    if let Err(msg) = self
                        .family(prov.as_ref(), e, kind, &mut res, fam, &mut st)
                        .await
                    {
                        self.log("error", format!("{} {}: {msg}", st.name, kind.as_str()))
                            .await;
                    }
                }
                let done = (!st.v4_enabled || st.ipv4.state == State::Ok)
                    && (!st.v6_enabled || st.ipv6.state == State::Ok);
                // clamp 防 Instant 加法溢出
                if e.mode == Mode::Poll || !listen_ok || !done {
                    rs.due
                        .insert(i, now + Duration::from_secs(e.interval.clamp(10, 86_400)));
                } else {
                    rs.due.remove(&i);
                }
            }
            out.push(st);
        }
        let mut s = self.status.lock().await;
        s.busy = false;
        s.last_run = Some(started);
        s.entries = out;
    }

    async fn family(
        &self,
        prov: &dyn provider::Provider,
        e: &Entry,
        kind: RecordKind,
        res: &mut Resolver<'_>,
        slot: &mut FamSlot,
        st: &mut EntryStatus,
    ) -> Result<(), String> {
        let (fam, cl) = match kind {
            RecordKind::A => (&e.ipv4, &self.echo[0]),
            RecordKind::Aaaa => (&e.ipv6, &self.echo[1]),
        };
        if !fam.enabled {
            return Ok(());
        }
        let Some(ip) = res.resolve(cl, &fam.sources, kind).await else {
            slot.streak += 1;
            let fst = st.fam_mut(kind);
            if slot.streak < FAIL_STREAK {
                fst.message = format!("未获取到地址(第{}次)", slot.streak);
                return Ok(());
            }
            fst.state = State::Err;
            fst.message = "未获取到地址".into();
            return Err("未获取到地址".into());
        };
        slot.streak = 0;
        let iptext = ip.to_string();
        if let Some((prev, left)) = slot.addr
            && prev == ip
            && (e.provider.notify_only() || left > 1)
        {
            slot.addr = Some((ip, left.saturating_sub(1)));
            let fst = st.fam_mut(kind);
            fst.ip = iptext;
            fst.state = State::Ok;
            fst.message = "地址未变化".into();
            return Ok(());
        }
        let zone = to_punycode(&e.zone);
        let mut err = None;
        for sub in e.subs() {
            let fqdn = e.fqdn(&sub);
            let fqdn_ascii = to_punycode(&fqdn);
            let sub_ascii = to_punycode(&sub);
            let req = Upsert {
                zone: &zone,
                sub: &sub_ascii,
                fqdn: &fqdn_ascii,
                kind,
                ip: &iptext,
                ttl: e.ttl,
            };
            if let Err(x) = prov.upsert(&req).await {
                err = Some(format!("{fqdn}: {x}"));
                break;
            }
        }
        let name = st.name.clone();
        let fst = st.fam_mut(kind);
        fst.ip = iptext;
        match err {
            Some(msg) => {
                slot.addr = None;
                fst.state = State::Err;
                fst.message = msg.clone();
                Err(msg)
            }
            None => {
                slot.addr = Some((ip, COMPARE_EVERY));
                fst.state = State::Ok;
                fst.message = "更新成功".into();
                let ip = fst.ip.clone();
                self.log("info", format!("{name} {} -> {ip}", kind.as_str()))
                    .await;
                Ok(())
            }
        }
    }
}
