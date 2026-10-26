use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::auth::{FailTrack, MasterKey, Token, check_strength, pwd_hash, pwd_verify};
use crate::config::{Config, ConfigStore};
use crate::engine::Engine;
use crate::error::{Error, Result};

#[derive(Clone)]
pub struct AppState {
    cfg: Arc<ConfigStore>,
    engine: Arc<Engine>,
    /// 改密后整体轮换，旧令牌全部失效
    mk: Arc<RwLock<MasterKey>>,
    fail: Arc<FailTrack>,
    /// 保存配置整体串行：绑定、落盘、递交监听严格同序
    set: Arc<Mutex<()>>,
    /// 换端口递交已绑定的新监听，队列无界避免停机互锁
    rebind: mpsc::UnboundedSender<Vec<TcpListener>>,
}

enum Ev {
    Stop,
    Rebind(Vec<TcpListener>),
    /// 监听任务未被要求退出却结束
    Lost(std::result::Result<std::io::Result<()>, JoinError>),
}

pub async fn serve(cfg: Arc<ConfigStore>, engine: Arc<Engine>) -> Result<()> {
    let port = cfg.get().await.port;
    if port == 0 {
        return Err(Error::Internal("监听端口不能为 0，请检查配置".into()));
    }
    let (rebind, mut rx) = mpsc::unbounded_channel();
    let state = AppState {
        cfg,
        engine,
        mk: Arc::new(RwLock::new(MasterKey::new())),
        fail: Arc::new(FailTrack::new(5, 300)),
        set: Arc::new(Mutex::new(())),
        rebind,
    };
    let stop = CancellationToken::new();
    tokio::spawn(watch_signals(stop.clone()));
    let app = routes(state);
    let mut listeners = bind_any(port)
        .await
        .ok_or_else(|| Error::Internal(format!("绑定端口 {port} 失败")))?;
    loop {
        let quit = CancellationToken::new();
        let mut set = spawn_serve(listeners, app.clone(), quit.clone());
        let ev = tokio::select! {
            _ = stop.cancelled() => Ev::Stop,
            Some(l) = rx.recv() => Ev::Rebind(l),
            Some(r) = set.join_next() => Ev::Lost(r),
        };
        // 新端口已绑定，收尾期间新连接在 backlog 排队；监听异常在此一并暴露
        quit.cancel();
        while let Some(r) = set.join_next().await {
            serve_check(r)?;
        }
        match ev {
            Ev::Stop => return Ok(()),
            Ev::Rebind(l) => listeners = l,
            Ev::Lost(r) => {
                // 退出令牌未下发，任务提前结束必属异常
                serve_check(r)?;
                return Err(Error::Internal("监听意外结束".into()));
            }
        }
    }
}

fn serve_check(r: std::result::Result<std::io::Result<()>, JoinError>) -> Result<()> {
    match r {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(Error::Internal(format!("服务异常退出: {e}"))),
        Err(e) => Err(Error::Internal(format!("服务任务异常: {e}"))),
    }
}

/// 一组监听共用退出令牌，任一任务结束即随 JoinSet 一并收拢
fn spawn_serve(
    listeners: Vec<TcpListener>,
    app: Router,
    quit: CancellationToken,
) -> JoinSet<std::io::Result<()>> {
    log_listen(
        listeners[0]
            .local_addr()
            .expect("已绑定监听必有本地地址")
            .port(),
    );
    let mut set = JoinSet::new();
    for l in listeners {
        let (app, q) = (app.clone(), quit.clone());
        set.spawn(async move {
            axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>())
                .with_graceful_shutdown(async move { q.cancelled().await })
                .await
        });
    }
    set
}

/// 双栈绑定：Linux/Android 的 :: 已含 IPv4，Windows v6-only 需与 0.0.0.0 并存
async fn bind_any(port: u16) -> Option<Vec<TcpListener>> {
    let mut v = Vec::new();
    for ip in [
        IpAddr::from(Ipv6Addr::UNSPECIFIED),
        IpAddr::from(Ipv4Addr::UNSPECIFIED),
    ] {
        if let Ok(l) = TcpListener::bind(SocketAddr::new(ip, port)).await {
            v.push(l);
        }
    }
    if v.is_empty() { None } else { Some(v) }
}

/// 常驻监听退出信号，防换轮间隙漏收
async fn watch_signals(stop: CancellationToken) {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("注册 SIGTERM 监听失败");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("收到退出信号，正在停止服务");
    stop.cancel();
}

fn log_listen(port: u16) {
    let mut ips = vec![IpAddr::from([127, 0, 0, 1])];
    ips.extend(
        crate::net::ifaces()
            .into_iter()
            .flat_map(|i| [i.v4.map(IpAddr::V4), i.v6.map(IpAddr::V6)])
            .flatten(),
    );
    ips.sort();
    ips.dedup();
    for ip in ips {
        tracing::info!("服务已启动: http://{}", SocketAddr::new(ip, port));
    }
}

fn routes(state: AppState) -> Router {
    let authed = Router::new()
        .route("/api/status", get(status))
        .route("/api/config", get(get_config).post(set_config))
        .route("/api/interfaces", get(interfaces))
        .route("/api/run", post(run_now))
        .route("/api/logs/clear", post(clear_logs))
        .route("/api/password", post(change_password))
        .layer(middleware::from_fn_with_state(state.clone(), auth));
    Router::new()
        .route(
            "/",
            get(|h: HeaderMap| async move { asset(HTML, "text/html; charset=utf-8", &h) }),
        )
        .route(
            "/index.css",
            get(|h: HeaderMap| async move { asset(CSS, "text/css; charset=utf-8", &h) }),
        )
        .route(
            "/index.js",
            get(|h: HeaderMap| async move { asset(JS, "text/javascript; charset=utf-8", &h) }),
        )
        .route("/api/login", post(login))
        .route("/api/setup", get(setup_state).post(setup))
        .route("/api/site", get(site_title))
        .merge(authed)
        .layer(middleware::from_fn_with_state(state.clone(), wan_guard))
        .layer(middleware::from_fn(sec_headers))
        .with_state(state)
}

const HTML: &str = include_str!("../assets/index.html");
const CSS: &str = include_str!("../assets/index.css");
const JS: &str = include_str!("../assets/index.js");

fn asset(body: &'static str, ct: &'static str, req: &HeaderMap) -> Response {
    let mut h = DefaultHasher::new();
    body.hash(&mut h);
    let etag = format!("\"{:x}\"", h.finish());
    if req
        .get(header::IF_NONE_MATCH)
        .is_some_and(|v| v.as_bytes() == etag.as_bytes())
    {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response();
    }
    (
        [
            (header::CONTENT_TYPE, ct),
            (header::ETAG, etag.as_str()),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

async fn auth(State(st): State<AppState>, req: Request, next: Next) -> Result<Response> {
    let cred = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(Error::Auth)?;
    let active = req.headers().contains_key("x-auth-active");
    let ttl = st.cfg.get().await.token_ttl;
    let fresh = Token::renew(
        cred,
        &st.mk.read().unwrap_or_else(|e| e.into_inner()),
        active,
        ttl,
    )?;
    let mut res = next.run(req).await;
    if let Some(fresh) = fresh {
        res.headers_mut().insert(
            "x-auth-token",
            fresh.parse().expect("base64url 必为合法头值"),
        );
    }
    Ok(res)
}

async fn wan_guard(State(st): State<AppState>, req: Request, next: Next) -> Result<Response> {
    if st.cfg.get().await.not_allow_wan {
        let lan = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_some_and(|c| crate::net::is_lan(c.0.ip()));
        if !lan {
            return Err(Error::Forbidden(
                "已开启「禁止公网访问」，仅允许局域网访问".into(),
            ));
        }
    }
    Ok(next.run(req).await)
}

/// 会话凭据在前端，CSP 收口注入面
const SEC_HEADERS: [(&str, &str); 4] = [
    (
        "content-security-policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
    ),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "no-referrer"),
];

async fn sec_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    for (k, v) in SEC_HEADERS {
        res.headers_mut()
            .insert(HeaderName::from_static(k), HeaderValue::from_static(v));
    }
    res
}

#[derive(Deserialize)]
struct LoginReq {
    pass: String,
}

async fn setup_state(State(st): State<AppState>) -> Result<Json<Value>> {
    Ok(Json(
        json!({ "required": st.cfg.pwd_hash().await?.is_empty() }),
    ))
}

#[derive(Deserialize)]
struct SetupReq {
    pass: String,
}

/// 仅限本机/局域网，防公网抢占（远程先 --reset-password）
async fn setup(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<SetupReq>,
) -> Result<Json<Value>> {
    if !crate::net::is_lan(peer.ip()) {
        return Err(Error::Forbidden(
            "首次初始化仅允许本机或局域网访问，远程请先用 --reset-password 设置密码".into(),
        ));
    }
    check_strength(&req.pass)?;
    if !st.cfg.pwd_hash().await?.is_empty() {
        return Err(Error::Arg("已完成初始化，请直接登录".into()));
    }
    let pass = req.pass;
    let hash = tokio::task::spawn_blocking(move || pwd_hash(&pass))
        .await
        .map_err(|e| Error::Internal(format!("密码处理失败: {e}")))??;
    if !st.cfg.init_pwd_hash(hash).await? {
        return Err(Error::Arg("已完成初始化，请直接登录".into()));
    }
    let ttl = st.cfg.get().await.token_ttl;
    let mk = st.mk.read().unwrap_or_else(|e| e.into_inner());
    Ok(Json(json!({ "token": Token::issue(&mk, ttl).to_b64() })))
}

async fn login(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginReq>,
) -> Result<Json<Value>> {
    let ip = peer.ip().to_canonical().to_string();
    let hash = st.cfg.pwd_hash().await?;
    if hash.is_empty() {
        return Err(Error::Arg("尚未设置密码，请先完成初始化".into()));
    }
    st.fail.try_acquire(&ip)?;
    let pass = req.pass;
    let ok = tokio::task::spawn_blocking(move || pwd_verify(&hash, &pass))
        .await
        .map_err(|e| Error::Internal(format!("密码处理失败: {e}")))?;
    if !ok {
        return Err(Error::Arg("密码错误".into()));
    }
    st.fail.clear(&ip);
    let ttl = st.cfg.get().await.token_ttl;
    let mk = st.mk.read().unwrap_or_else(|e| e.into_inner());
    Ok(Json(json!({
        "token": Token::issue(&mk, ttl).to_b64()
    })))
}

async fn status(State(st): State<AppState>) -> Json<crate::engine::Status> {
    Json(st.engine.status().await)
}

async fn site_title(State(st): State<AppState>) -> Json<Value> {
    let cfg = st.cfg.get().await;
    Json(json!({ "title": &cfg.site_title, "lang": &cfg.lang }))
}

async fn interfaces() -> Json<Value> {
    Json(json!(
        crate::net::ifaces()
            .into_iter()
            .map(|i| json!({"name": i.name, "v4": i.v4, "v6": i.v6}))
            .collect::<Vec<_>>()
    ))
}

/// 前端配置视图：口令哈希不下发
fn web_config(mut cfg: Config) -> Json<Config> {
    cfg.pwd_hash = String::new();
    Json(cfg)
}

async fn get_config(State(st): State<AppState>) -> Json<Config> {
    web_config((*st.cfg.get().await).clone())
}

async fn set_config(
    State(st): State<AppState>,
    Json(mut cfg): Json<Config>,
) -> Result<Json<Config>> {
    // 先校验后绑定：绑定是副作用，非法配置不得触达套接字
    cfg.validate()?;
    // 绑定、落盘、递交监听同锁串行，防并发保存时最终监听与配置端口倒置
    let _g = st.set.lock().await;
    // 换端口先持新监听再提交：真实绑定即就绪保证，失败则零变更
    let held = if cfg.port != st.cfg.get().await.port {
        Some(
            bind_any(cfg.port)
                .await
                .ok_or_else(|| Error::Arg(format!("绑定端口 {} 失败（可能被占用）", cfg.port)))?,
        )
    } else {
        None
    };
    let changed = st.cfg.replace(cfg).await?;
    if changed {
        st.engine.kick();
    }
    // 递交后响应仍走旧连接，axum 优雅停机保证在途请求完成
    if let Some(l) = held {
        st.rebind
            .send(l)
            .map_err(|_| Error::Internal("服务正在停止".into()))?;
    }
    Ok(web_config((*st.cfg.get().await).clone()))
}

async fn run_now(State(st): State<AppState>) -> Json<Value> {
    st.engine.kick();
    Json(json!({ "ok": true }))
}

async fn clear_logs(State(st): State<AppState>) -> Json<Value> {
    st.engine.clear_logs().await;
    Json(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct PwdReq {
    old: String,
    new: String,
}

async fn change_password(
    State(st): State<AppState>,
    Json(req): Json<PwdReq>,
) -> Result<Json<Value>> {
    check_strength(&req.new)?;
    let hash = st.cfg.pwd_hash().await?;
    let old = req.old;
    let ok = tokio::task::spawn_blocking(move || pwd_verify(&hash, &old))
        .await
        .map_err(|e| Error::Internal(format!("密码处理失败: {e}")))?;
    if !ok {
        return Err(Error::Arg("原密码错误".into()));
    }
    let new = req.new;
    let new_hash = tokio::task::spawn_blocking(move || pwd_hash(&new))
        .await
        .map_err(|e| Error::Internal(format!("密码处理失败: {e}")))??;
    st.cfg.set_pwd_hash(new_hash).await?;
    *st.mk.write().unwrap_or_else(|e| e.into_inner()) = MasterKey::new();
    Ok(Json(json!({ "ok": true })))
}
