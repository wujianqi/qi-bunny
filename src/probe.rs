//! IP 连通性探测模块
//!
//! DoH 返回的 IP 不一定可用(部分 IP 段被网络环境针对性阻断),必须用
//! 真实 TLS 握手验证后才能写入 hosts,否则"代理开启但打不开"。

use rustls::pki_types::ServerName;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{mpsc, Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const TCP_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_TIMEOUT: Duration = Duration::from_secs(8);
/// 并行探测的线程上限:候选池很大时(第三方源可能返回几十个 IP)防止瞬间
/// 打满连接数/线程数,分批探测。64 并发下单批 48 个候选一轮完成,
/// 最坏耗时 = 单个探测超时(13s),而非几百秒。
const PROBE_CONCURRENCY: usize = 64;

/// 探测结果:IP 可用 + TLS 握手耗时(越小越优)
#[derive(Debug, Clone, Copy)]
pub struct ProbeOk {
    pub ip_index: usize,
    pub elapsed_ms: u128,
}

/// 并行探测候选 IP,返回全部可完成 TLS 握手的(按耗时升序)。
/// `domain` 用于 TLS SNI/证书校验(如 "github.com")。
pub fn probe_all(domain: &str, ips: &[String]) -> Vec<ProbeOk> {
    let (tx, rx) = mpsc::channel::<ProbeOk>();
    let mut handles = Vec::new();

    // 分批探测,批内并行、批间串行,把并发线程数限制在 PROBE_CONCURRENCY 内;
    // 用全局下标枚举,保证 ip_index 与传入池严格对应
    for (start, batch) in ips.chunks(PROBE_CONCURRENCY).enumerate() {
        for (offset, ip) in batch.iter().enumerate() {
            let ip_index = start * PROBE_CONCURRENCY + offset;
            let tx = tx.clone();
            let domain = domain.to_string();
            let ip = ip.clone();
            handles.push(thread::spawn(move || {
                if let Some(elapsed) = probe_once(&domain, &ip) {
                    let _ = tx.send(ProbeOk { ip_index, elapsed_ms: elapsed });
                }
            }));
        }
    }
    drop(tx);

    let mut results: Vec<ProbeOk> = rx.into_iter().collect();
    for h in handles {
        let _: Result<(), Box<dyn std::any::Any + Send>> = h.join();
    }
    results.sort_by_key(|r| r.elapsed_ms);
    results
}

/// 胜者复核:对已选出的 IP 再次做完整 TLS 验证。
/// 与 probe_once 相同路径(真实握手+HTTP 响应),仅返回布尔值。
pub fn recheck(domain: &str, ip: &str) -> bool {
    probe_once(domain, ip).is_some()
}

/// 共享 TLS 客户端配置(根证书库构建开销大,进程内只建一次;ClientConfig 内部
/// 自带会话/密钥缓存,并发握手共享同一 Arc 是 rustls 推荐用法)
fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            )
        })
        .clone()
}

/// 公开共享的客户端 TLS 配置(转发器连上游用:webpki 根校验真 GitHub 证书)
pub fn tls_config_pub() -> Arc<rustls::ClientConfig> {
    tls_config()
}

/// 对单 IP 做完整 TLS 1.3/1.2 握手验证,返回握手耗时(ms);失败返回 None。
fn probe_once(domain: &str, ip: &str) -> Option<u128> {
    let start = Instant::now();

    // TCP 连接(带超时)
    let addr = (ip, 443u16).to_socket_addrs().ok()?.next()?;
    let mut stream = TcpStream::connect_timeout(&addr, TCP_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(TLS_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(TLS_TIMEOUT)).ok()?;

    // TLS 握手(rustls,webpki 根证书,校验证书域名 = 真实性验证)
    let server_name = ServerName::try_from(domain.to_string()).ok()?;
    let mut conn = rustls::ClientConnection::new(tls_config(), server_name).ok()?;
    let mut tls = rustls::Stream::new(&mut conn, &mut stream);

    // 发 GET(带浏览器 UA)并读响应头+部分响应体:HEAD 与真实浏览有差异,
    // 且拦截页("Whoa there!"/restricted)伪装成 200,必须看内容才能识别
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        domain
    );
    tls.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    // 最多读 4KB:响应头 + 拦截页特征出现的位置足够覆盖;超时即收手
    while buf.len() < 4096 {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let head = String::from_utf8_lossy(&buf);

    // 必须是真实 HTTP 响应,且状态码可用:
    // 403 是 GitHub 的滥用拦截页("Whoa there!"),说明该 IP 已被 GitHub
    // 按信誉拉黑——TLS 能握手但内容被替换,不能写入 hosts
    let status_line = head.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if !status_line.starts_with("HTTP/") || status == 0 || status == 403 {
        // 403 说明该 IP 被 GitHub 风控拦截(TLS 通但内容被替换),剔除并在
        // 非静默模式下记录,便于定位"代理开着但页面打不开"的场景
        if status == 403 {
            eprintln!("[!] {} 被 GitHub 拦截(403),已从候选池剔除", ip);
        }
        return None;
    }
    // 内容级校验:拦截页/冒牌页可能伪装成 200/301,必须按域名检查响应特征
    //  - 通用:GitHub 风控页与运营商劫持页的关键词,任何域名出现即剔除
    //  - 特定:raw/codeload 必须像文件服务,github.io 必须像 Pages 服务——
    //    返回的是 GitHub 登录页/错误页等"不匹配内容"说明流量被替换,剔除
    const BLOCK_MARKS: &[&str] = &[
        "Access to this site has been restricted",
        "Whoa there!",
        "has been restricted",
        "antispam",
        // Fastly 边缘节点(185.199.x.x,GitHub Pages CDN)持有 *.github.com
        // 通配符证书,TLS 能通;但对非 Pages 域名返回 "unknown domain" 错误页
        // (404/421,不是 403)——上面的状态码过滤拦不住它,必须按内容剔除
        "Fastly error: unknown domain",
    ];
    if BLOCK_MARKS.iter().any(|m| head.contains(m)) {
        eprintln!("[!] {} 返回拦截页(伪装 {:?}),已剔除", ip, status);
        return None;
    }
    // 域名身份特征:探测请求打的是该 IP 的 443,响应内容必须来自对应服务,
    // 否则是被劫持/替换的内容(探测用 rustls 校验证书域名,已保证对端持有
    // 正牌证书;这里拦截的是风控页替换后的正文与非法镜像)
    if domain.starts_with("raw.") || domain.starts_with("codeload") {
        // 文件服务:正常响应是 200/302/404,不可能是 GitHub 登录页
        if head.contains("Sign in to GitHub") || head.contains("<title>GitHub</title>") {
            eprintln!("[!] {} 返回内容与文件服务不符(冒牌页),已剔除", ip);
            return None;
        }
    }
    if domain.ends_with("github.io") && status == 404 {
        // Pages 服务对根路径请求必有内容(404 页也是 Pages 自己出的),
        // 404 配合非 Pages 特征说明内容被替换;这里保守仅拦截明确冒牌
        if head.contains("nginx") || head.contains("Apache") {
            eprintln!("[!] {} 返回内容与 Pages 服务不符,已剔除", ip);
            return None;
        }
    }

    Some(start.elapsed().as_millis())
}
