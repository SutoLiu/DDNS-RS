use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq)]
pub struct Iface {
    pub name: String,
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

/// 「禁止公网访问」准入判定；IPv4-mapped 先归一
pub fn is_lan(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// POSIX fnmatch 风格通配（* ? [...]，! 取反、a-z 区间）
pub fn glob_match(pat: &str, text: &str) -> bool {
    fn m(p: &[u8], s: &[u8]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(b'*') => (0..=s.len()).any(|i| m(&p[1..], &s[i..])),
            Some(b'?') => !s.is_empty() && m(&p[1..], &s[1..]),
            Some(b'[') => {
                let (i, neg) = if p.get(1) == Some(&b'!') {
                    (2, true)
                } else {
                    (1, false)
                };
                // 集合首位的 ] 为字面量；未闭合的 [ 整体按字面量
                let start = if p.get(i) == Some(&b']') { i + 1 } else { i };
                let Some(off) = p[start..].iter().position(|&c| c == b']') else {
                    return !s.is_empty() && s[0] == b'[' && m(&p[1..], &s[1..]);
                };
                let end = start + off;
                if s.is_empty() {
                    return false;
                }
                let set = &p[i..end];
                let mut hit = false;
                let mut j = 0;
                while j < set.len() {
                    if j + 2 < set.len() && set[j + 1] == b'-' {
                        hit |= (set[j]..=set[j + 2]).contains(&s[0]);
                        j += 3;
                    } else {
                        hit |= set[j] == s[0];
                        j += 1;
                    }
                }
                hit != neg && m(&p[end + 1..], &s[1..])
            }
            Some(&c) => !s.is_empty() && s[0] == c && m(&p[1..], &s[1..]),
        }
    }
    m(pat.as_bytes(), text.as_bytes())
}

fn usable_v4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified()
}

/// 仅接受全局单播 2000::/3
fn usable_v6(ip: Ipv6Addr) -> bool {
    !ip.is_loopback()
        && !ip.is_unicast_link_local()
        && !ip.is_unspecified()
        && (ip.octets()[0] & 0xE0) == 0x20
}

#[cfg(unix)]
mod ifaddrs {
    use super::{Iface, usable_v4, usable_v6};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[allow(unsafe_code)]
    pub fn ifaces() -> Vec<Iface> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Vec::new();
        }
        let mut map: std::collections::HashMap<String, Iface> = std::collections::HashMap::new();
        let mut cur = head;
        while !cur.is_null() {
            unsafe {
                let (a, n) = ((*cur).ifa_addr, (*cur).ifa_name);
                if !a.is_null() && !n.is_null() {
                    let name = std::ffi::CStr::from_ptr(n).to_string_lossy().into_owned();
                    let slot = map.entry(name.clone()).or_insert_with(|| Iface {
                        name,
                        v4: None,
                        v6: None,
                    });
                    match (*a).sa_family as i32 {
                        libc::AF_INET => {
                            let sin = &*(a as *const libc::sockaddr_in);
                            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                            if slot.v4.is_none() && usable_v4(ip) {
                                slot.v4 = Some(ip);
                            }
                        }
                        libc::AF_INET6 => {
                            let sin6 = &*(a as *const libc::sockaddr_in6);
                            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                            if slot.v6.is_none() && usable_v6(ip) {
                                slot.v6 = Some(ip);
                            }
                        }
                        _ => {}
                    }
                }
                cur = (*cur).ifa_next;
            }
        }
        unsafe { libc::freeifaddrs(head) }
        let mut v: Vec<_> = map
            .into_values()
            .filter(|i| i.v4.is_some() || i.v6.is_some())
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }
}

/// 平台是否具备地址事件监听能力；须与下方 imp 门控一致
pub const fn supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "android", windows))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use std::fs::File;
    use std::os::fd::FromRawFd;

    use tokio::io::unix::AsyncFd;

    pub use super::ifaddrs::ifaces;

    pub struct NetMonitor(AsyncFd<File>);

    impl NetMonitor {
        #[allow(unsafe_code)]
        pub fn new() -> std::io::Result<Self> {
            // libc 未导出 RTMGRP_* 常量，取值 1 << (RTNLGRP_* - 1)（linux/rtnetlink.h）
            const GROUPS: u32 = (1 << 4) | (1 << 8);
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    libc::NETLINK_ROUTE,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let file = unsafe { File::from_raw_fd(fd) };
            // sockaddr_nl 含私有填充字段，须先清零
            let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            addr.nl_family = libc::AF_NETLINK as u16;
            addr.nl_groups = GROUPS;
            if unsafe {
                libc::bind(
                    fd,
                    std::ptr::addr_of!(addr).cast(),
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self(unsafe { AsyncFd::register(file)? }))
        }

        /// 返回 false 表示监听已失效
        pub async fn wait(&self) -> bool {
            let mut buf = [0u8; 8192];
            loop {
                let Ok(mut guard) = self.0.readable().await else {
                    return false;
                };
                // try_io 在 WouldBlock 时原子清就绪，避免排空间隙丢事件
                match guard.try_io(|fd| std::io::Read::read(&mut fd.get_ref(), &mut buf)) {
                    Ok(Ok(0)) => return false,
                    Ok(Ok(_)) => continue,
                    // 内核缓冲溢出：消息已丢，返回事件由引擎全量比对找回
                    Ok(Err(e)) if e.raw_os_error() == Some(libc::ENOBUFS) => return true,
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Ok(Err(e)) => {
                        tracing::warn!("netlink: 读取失败, 停止地址监听: {e}");
                        return false;
                    }
                    Err(_) => return true,
                }
            }
        }
    }
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
mod imp {
    pub use super::ifaddrs::ifaces;

    pub struct NetMonitor;

    impl NetMonitor {
        pub fn new() -> std::io::Result<Self> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "当前平台不支持地址事件监听",
            ))
        }

        // new 失败后不会到达，仅为统一签名
        pub async fn wait(&self) -> bool {
            false
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::{Iface, usable_v4, usable_v6};
    use std::ffi::c_void;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::ptr::{null, null_mut};
    use std::sync::LazyLock;

    use tokio::sync::Notify;

    const AF_UNSPEC: u16 = 0;
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 23;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    /// GetAdaptersAddresses 过滤：跳过 anycast(0x2)、多播(0x4)、DNS 服务器(0x8)地址
    const GAA_SKIP: u32 = 0x2 | 0x4 | 0x8;

    /// 地址变化回调在系统线程触发，经静态 Notify 唤醒异步侧
    static ADDR_CHANGE: LazyLock<Notify> = LazyLock::new(Notify::new);

    #[allow(unsafe_code)]
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        #[link_name = "GetAdaptersAddresses"]
        fn get_adapters(
            family: u32,
            flags: u32,
            reserved: *const c_void,
            buf: *mut Adapter,
            size: *mut u32,
        ) -> u32;
        #[link_name = "NotifyUnicastIpAddressChange"]
        fn notify_unicast_change(
            family: u16,
            cb: Option<extern "system" fn(*const c_void, *const c_void, u32)>,
            ctx: *const c_void,
            initial: u8,
            handle: *mut *mut c_void,
        ) -> u32;
        #[link_name = "CancelMibChangeNotify2"]
        fn cancel_notify(handle: *mut c_void) -> u32;
    }

    pub struct NetMonitor(*mut c_void);

    // 句柄仅在 Drop 中注销，可跨线程持有
    #[allow(unsafe_code)]
    unsafe impl Send for NetMonitor {}
    #[allow(unsafe_code)]
    unsafe impl Sync for NetMonitor {}

    impl NetMonitor {
        #[allow(unsafe_code)]
        pub fn new() -> std::io::Result<Self> {
            let mut handle = null_mut();
            // AF_UNSPEC 同时订阅 IPv4/IPv6 地址增删改
            let r = unsafe {
                notify_unicast_change(AF_UNSPEC, Some(on_change), null(), 0, &mut handle)
            };
            if r != 0 {
                return Err(std::io::Error::from_raw_os_error(r as i32));
            }
            Ok(Self(handle))
        }

        pub async fn wait(&self) -> bool {
            ADDR_CHANGE.notified().await;
            true
        }
    }

    impl Drop for NetMonitor {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            unsafe { cancel_notify(self.0) };
        }
    }

    extern "system" fn on_change(_: *const c_void, _: *const c_void, _: u32) {
        ADDR_CHANGE.notify_one();
    }

    /// IP_ADAPTER_ADDRESSES 前缀布局：8 字节头 + 指针序列
    #[repr(C)]
    struct Adapter {
        _head: u64,
        next: *mut Adapter,
        _adapter_name: *const u8,
        first_unicast: *mut Unicast,
        _anycast: *const c_void,
        _multicast: *const c_void,
        _dns: *const c_void,
        _suffix: *const u16,
        _description: *const u16,
        friendly_name: *const u16,
    }

    /// IP_ADAPTER_UNICAST_ADDRESS 前缀布局
    #[repr(C)]
    struct Unicast {
        _head: u64,
        next: *mut Unicast,
        sockaddr: *const u8,
    }

    // 编译期锁定字段偏移，防结构体改动引入越界读
    const _: () = assert!(std::mem::offset_of!(Adapter, next) == 8);
    const _: () = assert!(
        std::mem::offset_of!(Adapter, first_unicast) == 8 + 2 * std::mem::size_of::<usize>()
    );
    const _: () = assert!(
        std::mem::offset_of!(Adapter, friendly_name) == 8 + 8 * std::mem::size_of::<usize>()
    );
    const _: () =
        assert!(std::mem::offset_of!(Unicast, sockaddr) == 8 + std::mem::size_of::<usize>());

    #[repr(C)]
    struct SockaddrIn {
        family: u16,
        _port: u16,
        addr: [u8; 4],
    }

    #[repr(C)]
    struct SockaddrIn6 {
        family: u16,
        _port: u16,
        _flow: u32,
        addr: [u8; 16],
    }

    #[allow(unsafe_code)]
    pub fn ifaces() -> Vec<Iface> {
        let mut len: u32 = 15 * 1024;
        let mut buf = vec![0u8; len as usize];
        for _ in 0..4 {
            let r = unsafe {
                get_adapters(
                    AF_UNSPEC as u32,
                    GAA_SKIP,
                    null(),
                    buf.as_mut_ptr().cast(),
                    &mut len,
                )
            };
            if r == 0 {
                return collect(buf.as_ptr().cast());
            }
            if r != ERROR_BUFFER_OVERFLOW {
                return Vec::new();
            }
            buf.resize(len as usize, 0);
        }
        Vec::new()
    }

    #[allow(unsafe_code)]
    fn collect(head: *const Adapter) -> Vec<Iface> {
        let mut v = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            let a = unsafe { &*cur };
            let mut f = Iface {
                name: wcs(a.friendly_name),
                v4: None,
                v6: None,
            };
            let mut u = a.first_unicast;
            while !u.is_null() {
                let ua = unsafe { &*u };
                let sa = ua.sockaddr;
                if !sa.is_null() {
                    match unsafe { *(sa as *const u16) } {
                        AF_INET if f.v4.is_none() => {
                            let ip = Ipv4Addr::from(unsafe { (*(sa as *const SockaddrIn)).addr });
                            if usable_v4(ip) {
                                f.v4 = Some(ip);
                            }
                        }
                        AF_INET6 if f.v6.is_none() => {
                            let ip = Ipv6Addr::from(unsafe { (*(sa as *const SockaddrIn6)).addr });
                            if usable_v6(ip) {
                                f.v6 = Some(ip);
                            }
                        }
                        _ => {}
                    }
                }
                u = ua.next;
            }
            if f.v4.is_some() || f.v6.is_some() {
                v.push(f);
            }
            cur = a.next;
        }
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    #[allow(unsafe_code)]
    fn wcs(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0usize;
        unsafe {
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    use super::Iface;

    pub struct NetMonitor;

    impl NetMonitor {
        pub fn new() -> std::io::Result<Self> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "当前平台不支持地址事件监听",
            ))
        }

        // new 失败后不会到达，仅为统一签名
        pub async fn wait(&self) -> bool {
            false
        }
    }

    pub fn ifaces() -> Vec<Iface> {
        Vec::new()
    }
}

pub use imp::{NetMonitor, ifaces};
