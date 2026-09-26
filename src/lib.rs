//! qi-bunny(奇小兔)—— AI 智能体开发辅助工具:开源库的搜索与更新加速
//!
//! 本 crate 为共享库,由两个二进制复用:
//!   - qi-bunny     托盘后台模式(GUI 子系统,无控制台窗口)
//!   - qi-bunny-cli 命令行模式(控制台子系统,start/fetch/clean 子命令)
//!
//! 原理(Hosts 模式):
//!   1. 多路 DoH + UDP DNS 收集各域名全部候选 IP
//!   2. 真实 TLS 握手测速择优,只写验证可用的 IP
//!   3. 最优 IP 写入系统 hosts 标记块;退出自动恢复
//!
//! 需要 管理员(root) 权限运行以写入 hosts。

pub mod address;
pub mod cert;
pub mod dns;
pub mod hosts;
pub mod mirror;
#[cfg(windows)]
pub mod notify;
pub mod probe;
pub mod proxy;
pub mod sources;
pub mod tray;

use std::sync::atomic::AtomicBool;

/// 静默开关:托盘后台模式(无控制台)置为 true,所有日志输出变为空操作
pub static QUIET: AtomicBool = AtomicBool::new(false);

/// 常规日志(托盘模式下静默)
#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        if !$crate::QUIET.load(std::sync::atomic::Ordering::SeqCst) { println!($($arg)*); }
    };
}

/// 错误日志(托盘模式下静默)
#[macro_export]
macro_rules! logerr {
    ($($arg:tt)*) => {
        if !$crate::QUIET.load(std::sync::atomic::Ordering::SeqCst) { eprintln!($($arg)*); }
    };
}

/// 加速的 GitHub 域名清单(主域 + GitHub 常用资源域)
pub const DOMAINS: &[&str] = &[
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "github.io",
    "assets.github.com",
];

/// last-known-good 缓存文件路径(exe 同目录,固定名:
/// 托盘/CLI 两个二进制必须共用同一份缓存)
fn lastgood_path() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match exe.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join("qi-bunny.good"),
        _ => std::path::PathBuf::from("qi-bunny.good"),
    }
}

/// 追加记录成功 IP(域名\tIP),每域名只保留最新 1 条,文件最大 64 行。
/// 只留最优:缓存只是"下次启动的起跑线",探测每轮都会重新验证;
/// 留多条反而让劣化 IP 轮流占坑,拖慢换优速度。
fn save_lastgood(entries: &[(String, String)]) {
    use std::io::Write;
    let path = lastgood_path();
    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .map(|c| c.lines().map(String::from).collect())
        .unwrap_or_default();
    for (domain, ip) in entries {
        let record = format!("{}\t{}", domain, ip);
        lines.retain(|l| l != &record);
        // 移除该域名其它旧记录,只保留本次探测的最优 IP
        let prefix = format!("{}\t", domain);
        lines.retain(|l| !l.starts_with(&prefix));
        lines.push(record);
    }
    if let Ok(mut f) = std::fs::File::create(&path) {
        let tail = lines.len().saturating_sub(64);
        for l in &lines[tail..] {
            let _ = writeln!(f, "{}", l);
        }
    }
}

/// 读取 last-known-good:返回 (域名 -> IP 列表)
fn load_lastgood() -> Vec<(String, Vec<String>)> {
    use std::io::BufRead;
    let mut map: Vec<(String, Vec<String>)> = Vec::new();
    if let Ok(f) = std::fs::File::open(lastgood_path()) {
        for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
            if let Some((domain, ip)) = line.split_once('\t') {
                if let Some(entry) = map.iter_mut().find(|(d, _)| d == domain) {
                    if !entry.1.contains(&ip.to_string()) {
                        entry.1.push(ip.to_string());
                    }
                } else {
                    map.push((domain.to_string(), vec![ip.to_string()]));
                }
            }
        }
    }
    map
}

/// 汇总某域名的三路候选池(去重,last-known-good 优先):
/// 缓存 + DNS(DoH+UDP, A/AAAA) + 第三方源(meta 采样 + ipaddress.com)
/// 全部动态获取,不内置静态兜底 IP(流传过广的静态 IP 信誉差,易被
/// GitHub 风控拦截返回 "Whoa there!" 403 页)。
/// `lastgood` 由调用方传入(见 load_lastgood),多域名并行时只读一次文件
pub fn candidate_pool_with(domain: &str, lastgood: &[(String, Vec<String>)]) -> Vec<String> {
    let mut pool: Vec<String> = Vec::new();
    let push = |ip: String, pool: &mut Vec<String>| {
        // 过滤回环/未指定地址:hosts 模式下这些地址指向本机反代,一旦混入
        // 候选池会造成"代理探测自身"的自环,且污染源可能是历史缓存文件
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
            if addr.is_loopback() || addr.is_unspecified() {
                return;
            }
        } else {
            return; // 非法 IP 文本一律不入围
        }
        if !pool.contains(&ip) {
            pool.push(ip);
        }
    };
    if let Some((_, goods)) = lastgood.iter().find(|(d, _)| d == domain) {
        for ip in goods.clone() {
            push(ip, &mut pool);
        }
    }
    for ip in dns::candidates(domain) {
        push(ip, &mut pool);
    }
    for ip in sources::collect(domain) {
        push(ip, &mut pool);
    }
    pool
}

/// 读取 last-known-good(公开供 proxy 模块刷新候选池使用)
pub fn load_lastgood_pub() -> Vec<(String, Vec<String>)> {
    load_lastgood()
}

/// 记录探测成功的上游 IP 到 last-good 缓存(公开供 proxy 模块学习:
/// 缓存记录的是"可直连的真实上游 IP",绝非 hosts 里的 127.0.0.1)
pub fn learn_good(entries: &[(String, String)]) {
    save_lastgood(entries);
}

/// 单域名便捷版:自行读一次 last-good 缓存
pub fn candidate_pool(domain: &str) -> Vec<String> {
    candidate_pool_with(domain, &load_lastgood())
}

/// 前置权限检查:验证 hosts 文件可写(Windows 需管理员),不可写时立即报错,
/// 避免测速数分钟后才在写入阶段失败
fn check_hosts_writable() -> Result<(), String> {
    let path = hosts::hosts_path();
    match std::fs::OpenOptions::new().append(true).open(&path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            Err("hosts 文件不可写:请以管理员身份运行(右键 -> 以管理员身份运行)".into())
        }
        Err(e) => Err(format!("无法访问 hosts 文件({}):{}", path.display(), e)),
    }
}

/// 状态详情:一行式摘要(供托盘状态行与 CLI status 复用)。
/// 反代是否运行(127.0.0.1:443 可连)+ 链路实测(HTTP 80 探测上游),
/// 返回 (反代运行?, 链路摘要);链路摘要空串表示未测(加速未开启)。
pub fn status_detail() -> (bool, String) {
    // 反代运行状态:443 端口可连即运行中(托盘进程或本进程监听均占用端口)
    // 常量地址解析失败时跳过对应检测(不 panic,状态行显示未开启即可)
    let addr_443: Option<std::net::SocketAddr> = "127.0.0.1:443".parse().ok();
    let proxy_up = addr_443.is_some_and(|a| {
        std::net::TcpStream::connect_timeout(&a, std::time::Duration::from_millis(300)).is_ok()
    });

    // 链路实测:走 HTTP 80(github.com 会 301 到 https),请求经
    // hosts -> 本机反代 -> 上游,与浏览器链路一致;TLS 无法在无证书校验的
    // 前提下手写,HTTPS 完整校验由托盘自检(ureq)覆盖
    let link = (|| -> Option<String> {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect_timeout(
            &"127.0.0.1:80".parse().ok()?,
            std::time::Duration::from_millis(1500),
        )
        .ok()?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok()?;
        s.write_all(b"HEAD / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n")
            .ok()?;
        let mut buf = [0u8; 256];
        let n = s.read(&mut buf).ok()?;
        let resp = String::from_utf8_lossy(&buf[..n]);
        let code = resp.lines().next()?.split_whitespace().nth(1)?.to_string();
        Some(code)
    })();

    (proxy_up, link.unwrap_or_default())
}

/// 解析+探测候选池+启动本机反代+写 hosts(127.0.0.1),返回写入的 (域名, IP)
/// 列表;失败返回错误说明。托盘/CLI 两种模式共用。
///
/// SNI 反代模式:hosts 指向 127.0.0.1,流量先进本机代理,由代理按每条
/// 连接动态挑选健康上游 IP(详见 proxy.rs)。
pub fn enable_proxy() -> Result<Vec<(String, String)>, String> {
    log!("[*] 采集候选 IP 并做真实 TLS 握手验证…");

    // 1) 前置权限检查,不可写直接失败
    check_hosts_writable()?;

    // 1.5) 本地 CA 未信任时自动导入受信任根(MITM 加速前提,一次性):
    // 此路径已要求管理员权限,certutil -addstore 可静默完成,无需人工
    // cert 子命令;失败不阻塞加速(浏览器报证书错误时再提示)
    if matches!(cert::ca_trust_status(), cert::TrustStatus::Missing) {
        log!("[*] 本地 CA 未信任,自动导入系统受信任根…");
        match cert::install_ca_to_trust() {
            Ok(()) => log!("[+] 本地 CA 已自动安装到受信任的根证书颁发机构。"),
            Err(e) => logerr!("[!] 本地 CA 自动安装失败({}),浏览器将报证书错误;可手动运行 qi-bunny-cli cert", e),
        }
    }

    // 2) 启动本机反代(幂等):后台立即开始首轮全量探测
    let domains: Vec<String> = DOMAINS.iter().map(|s| s.to_string()).collect();
    proxy::start(&domains)?;

    // 3) 等首轮探测出结果(有任一域名就绪即可,细节由代理侧动态择路兜底)
    let ready = proxy::ready_domains(&domains, std::time::Duration::from_secs(45));
    if ready == 0 {
        // 首轮探测超时(候选多时逐域名探测可能超出等待窗口)不代表网络坏:
        // 反代保持运行、后台继续探测,hosts 降级写真实解析 IP 保住可达性——
        // 绝不能停掉反代还留着 127.0.0.1 劫持,那是"开启代理反而断网"的根源。
        // 探测出健康池后由托盘自检自动升回反代模式。
        logerr!("[!] 反代候选探测暂无结果,降级直连模式(hosts 写真实 IP),后台继续探测…");
        let mut entries: Vec<(String, String)> = Vec::new();
        for d in &domains {
            if let Some(ip) = candidate_pool(d).into_iter().next() {
                entries.push((d.clone(), ip));
            }
        }
        if entries.is_empty() {
            // 连 DNS 解析都拿不到 IP:此时不写 hosts(保持系统默认解析),
            // 反代继续在后台探测,不留下断网状态
            logerr!("[!] 暂无任何可用 IP,hosts 未写入(走系统默认解析),后台继续探测。");
            return Err("暂无可用 IP,请检查网络(防火墙/代理软件)后重试".into());
        }
        hosts::write_block(&entries).map_err(|e| format!("写入 hosts 失败:{}(需要管理员权限)", e))?;
        flush_dns_cache();
        log!(
            "[+] 已写入 {} 条直连 hosts 记录(降级模式);探测就绪后自动升级为反代加速。",
            entries.len()
        );
        return Ok(entries);
    }

    // 4) hosts 全部指向 127.0.0.1,流量交本机反代接管
    let entries: Vec<(String, String)> = domains
        .iter()
        .map(|d| (d.clone(), "127.0.0.1".to_string()))
        .collect();
    hosts::write_block(&entries).map_err(|e| {
        proxy::stop(); // 反代已启动但 hosts 写失败,避免留下无 hosts 指向的空转代理
        format!("写入 hosts 失败:{}(需要管理员权限)", e)
    })?;
    flush_dns_cache();
    // 注意:不把 127.0.0.1 存入 last-good 缓存——缓存记录的是"可直连的
    // 上游 IP",真实上游由 proxy 模块探测成功后自行学习(见 proxy::learn_good)
    log!(
        "[+] 已写入 {} 条 hosts 记录(指向本机反代),代理已开启。",
        entries.len()
    );
    Ok(entries)
}

/// 刷新系统 DNS 缓存(Windows: ipconfig /flushdns;其他平台无需/忽略)。
/// 新写入的 hosts 记录只有清掉缓存后才会立即生效,否则浏览器可能仍用旧解析。
/// hosts.rs 的写块/移块封装在内容变化后自动调用,调用方无需手动刷。
pub fn flush_dns_cache() {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: 避免闪出控制台窗口
        let _ = std::process::Command::new("ipconfig")
            .arg("/flushdns")
            .creation_flags(0x0800_0000)
            .output();
    }
}

/// 移除 hosts 标记块并停止本机反代,取消代理。托盘/CLI 两种模式共用。
pub fn disable_proxy() {
    let removed = hosts::remove_block();
    proxy::stop();
    if removed {
        log!("[+] 已移除 hosts 记录,代理已取消。");
    } else {
        log!("[*] 未发现本工具的 hosts 记录。");
    }
}

/// 直连兜底:为全部域名解析真实 IP 并写入 hosts(流量不经反代),用于加速
/// 链路失效时优先保住可达性——代理可以慢,但绝不能反过来把网断掉。
/// 返回写入条数(0 = 连 DNS 解析都拿不到 IP,或 hosts 写入失败)。
pub fn write_direct_fallback() -> usize {
    let mut entries: Vec<(String, String)> = Vec::new();
    for d in DOMAINS.iter() {
        if let Some(ip) = candidate_pool(d).into_iter().next() {
            entries.push((d.to_string(), ip));
        }
    }
    if entries.is_empty() {
        return 0;
    }
    if hosts::write_block(&entries).is_ok() {
        flush_dns_cache();
        entries.len()
    } else {
        0
    }
}
