//! 本机 SNI 反向代理模块(加速核心,对齐 Watt Toolkit 架构)
//!
//! 与旧"hosts 直指真实 IP"模式的本质区别:
//!   - hosts 改写为 127.0.0.1,所有 GitHub 域名的 HTTPS 流量先进本机;
//!   - 本机解析 TLS ClientHello 的 SNI 得知目标域名,**透传**整条 TLS 流量
//!     到健康的上游 IP(不终结 TLS,证书校验仍由浏览器完成,无需装根证书);
//!   - 每条连接动态挑选上游:连不上立即换下一个,失败的 IP 被记失败分;
//!   - 后台周期用真实 TLS 握手探测候选池,淘汰劣化 IP、自动补充新候选。
//!
//! 效果:单 IP 中途被限速/拉黑只影响当前连接,下一个请求自动切换,
//! 不再出现"测速通过、用着用着全挂"的问题。

use crate::{log, logerr};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::cmp::Reverse;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
/// 本机监听端口:HTTPS 流量(Hosts 指向)与 HTTP 流量(保持 http:// 链接可用)
const HTTPS_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;

/// 上游 TCP 连接超时(短超时:连不上立刻换下一个候选)
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_millis(2500);
/// 读取客户端首个报文(ClientHello / HTTP 头)的超时
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// 候选池为空时等待首次探测完成的时长
const POOL_WAIT: Duration = Duration::from_secs(8);
/// 后台探测周期
const PROBE_INTERVAL: Duration = Duration::from_secs(120);
/// 池空域名的快速重试间隔(参照 Watt Toolkit:探测全挂时高频补池,不让域名长时间无服务)
const EMPTY_POOL_RETRY: Duration = Duration::from_secs(15);
/// 池内健康候选少于该数时,触发重新采集候选
const MIN_HEALTHY: usize = 4;
// ---------- 候选池存储 ----------

/// 单个上游候选:IP + 失败分(运行期连接失败累计)+ 最近探测延迟
/// + 试用标记(应急快速通道入池,尚未被真实转发验证)
/// + 真实流量 EWMA 记分(成功率 0..1000,延迟 ms)
#[derive(Debug, Clone)]
struct Cand {
    ip: String,
    fails: u32,
    latency_ms: u128,
    /// true = 应急入池的试用 IP:1 轮探测通过即并入(池深≤1 时的快速通道);
    /// 真实转发成功即转正,失败立即踢出。正常合并的候选恒为 false
    probation: bool,
    /// 真实转发成功率的 EWMA(0=全失败,1000=全成功);None=尚无真实流量
    /// 样本(此时按探测延迟排序)。新样本权重 α=0.3
    ewma_ok: Option<u32>,
    /// 真实转发耗时的 EWMA(ms,含连接+响应头);None=尚无样本
    ewma_ms: Option<u128>,
    /// 熔断窗口内的最近失败时刻(时间窗口计数:窗口内连续失败达阈值
    /// 即时踢出,不等探测周期)——成功会清空计数,瞬时抖动不误伤
    recent_fails: Vec<Instant>,
}

/// EWMA 新样本权重:越小越平滑(历史占比越高),0.3 约等于近 3-4 次
/// 请求主导评分——单次抖动不翻转排序,连续劣化 3 次内沉底
const EWMA_ALPHA_NUM: u32 = 3;
const EWMA_ALPHA_DEN: u32 = 10;

/// 用新样本更新候选的 EWMA 记分(成功 s=true 时 ok=1000,失败 ok=0)
fn ewma_update(c: &mut Cand, s: bool, elapsed_ms: u128) {
    let ok_new: u32 = if s { 1000 } else { 0 };
    match (c.ewma_ok, c.ewma_ms) {
        (Some(ok), Some(ms)) => {
            c.ewma_ok = Some((ok * (EWMA_ALPHA_DEN - EWMA_ALPHA_NUM) + ok_new * EWMA_ALPHA_NUM) / EWMA_ALPHA_DEN);
            c.ewma_ms = Some((ms * (EWMA_ALPHA_DEN - EWMA_ALPHA_NUM) as u128 + elapsed_ms * EWMA_ALPHA_NUM as u128) / EWMA_ALPHA_DEN as u128);
        }
        // 首个样本:直接采用(不与假想的 500 中立值混合)
        _ => {
            c.ewma_ok = Some(ok_new);
            c.ewma_ms = Some(elapsed_ms);
        }
    }
}

#[derive(Default)]
struct Store {
    pools: HashMap<String, Vec<Cand>>,
}

fn store() -> &'static Mutex<Store> {
    static S: OnceLock<Mutex<Store>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Store::default()))
}

/// 防止同一域名的刷新任务重叠执行
fn in_progress() -> &'static Mutex<HashSet<String>> {
    static S: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashSet::new()))
}

/// 加锁(锁中毒时恢复内部状态继续用:这些互斥量只保护内存缓存,
/// 持锁线程 panic 后数据仍自洽,直接取走比永久卡死好)
fn lock<'a, T>(m: &'a Mutex<T>) -> std::sync::MutexGuard<'a, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------- 生命周期 ----------

static RUNNING: AtomicBool = AtomicBool::new(false);

fn listeners() -> &'static Mutex<Vec<TcpListener>> {
    static S: OnceLock<Mutex<Vec<TcpListener>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Vec::new()))
}

/// 启动本机反代:监听 443/80,按需为 `domains` 建候选池并开始后台探测。
/// 已在运行时直接返回 Ok(幂等,供"手动刷新"复用)。
pub fn start(domains: &[String]) -> Result<(), String> {
    if RUNNING.load(Ordering::SeqCst) {
        return Ok(());
    }

    // 443 是本方案的硬前提;被占用时给出可操作的提示
    let listener = TcpListener::bind(("127.0.0.1", HTTPS_PORT)).map_err(|e| {
        format!(
            "本机 {} 端口监听失败:{}\n    端口可能被其他代理工具占用(如 Watt Toolkit/加速器),请先关闭后重试",
            HTTPS_PORT, e
        )
    })?;
    let http_listener = TcpListener::bind(("127.0.0.1", HTTP_PORT)).ok(); // 80 可选,失败不致命

    RUNNING.store(true, Ordering::SeqCst);

    {
        let mut ls = lock(listeners());
        ls.push(listener);
        if let Some(hl) = http_listener.as_ref() {
            if let Ok(clone) = hl.try_clone() {
                ls.push(clone);
            }
        }
    }

    // 初始化空池(内容由探测线程填充)
    {
        let mut s = lock(store());
        for d in domains {
            s.pools.entry(d.clone()).or_default();
        }
    }

    // HTTPS 接受循环(用 listeners 里的第一个;后续 stop 时统一 drop)
    {
        let ls = lock(listeners());
        let l = ls[0].try_clone().map_err(|e| format!("复制监听套接字失败:{}", e))?;
        thread::spawn(move || accept_loop(l, true));
    }
    // HTTP 接受循环(可选)
    if let Some(hl) = http_listener {
        let l = hl.try_clone().ok();
        if let Some(l) = l {
            thread::spawn(move || accept_loop(l, false));
        }
    }

    // 后台探测线程:立即做第一轮全量探测,之后周期维护
    let domains: Vec<String> = domains.to_vec();
    let d1 = domains.clone();
    thread::spawn(move || prober_loop(d1));
    // Standby 刷选线程:独立于主池持续采集验证候选,只做单向合并
    thread::spawn(move || standby_loop(domains));

    log!("[+] 本机反代已启动(127.0.0.1:{}/{}),后台探测运行中", HTTPS_PORT, HTTP_PORT);
    Ok(())
}

/// 停止本机反代:终止后台探测、唤醒并退出 accept 循环(accept 用的是
/// 监听套接字的克隆,需自连一次使其从阻塞中返回,循环内检查标志后退出)。
pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
    lock(listeners()).clear();
    // 自连唤醒两个端口的 accept(连接会被 accept 后因 RUNNING=false 立即关闭)
    for port in [HTTPS_PORT, HTTP_PORT] {
        let _ = TcpStream::connect(("127.0.0.1", port));
    }
    log!("[+] 本机反代已停止。");
}

/// 是否正在运行
pub fn is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// 单域名池况快照(状态查询用)
#[derive(Debug, Clone)]
pub struct PoolStat {
    pub domain: String,
    /// 候选总数 / 健康数(fails==0)
    pub total: usize,
    pub healthy: usize,
    /// 健康候选 (IP, 延迟ms) 按延迟升序,最多前 5 个
    pub top: Vec<(String, u128)>,
}

/// 读取当前候选池快照(代理未运行时池为空,各域名 total=0)。
/// CLI status 用它展示"反代模式下的实际上游健康度"。
pub fn pool_snapshot(domains: &[String]) -> Vec<PoolStat> {
    let s = lock(store());
    domains
        .iter()
        .map(|d| {
            let pool = s.pools.get(d);
            let mut healthy: Vec<&Cand> = pool
                .map(|v| v.iter().filter(|c| c.fails == 0).collect())
                .unwrap_or_default();
            healthy.sort_by_key(|c| c.latency_ms);
            PoolStat {
                domain: d.clone(),
                total: pool.map(|v| v.len()).unwrap_or(0),
                healthy: healthy.len(),
                top: healthy
                    .iter()
                    .take(5)
                    .map(|c| (c.ip.clone(), c.latency_ms))
                    .collect(),
            }
        })
        .collect()
}

/// 等待候选池就绪:最多等 `timeout`,返回已就绪(池非空)的域名数。
/// enable_proxy 用它确认首轮探测成果,全空时 upstream 侧无法工作。
pub fn ready_domains(domains: &[String], timeout: Duration) -> usize {
    let deadline = Instant::now() + timeout;
    loop {
        let ready = {
            let s = lock(store());
            domains
                .iter()
                .filter(|d| s.pools.get(*d).map(|v| !v.is_empty()).unwrap_or(false))
                .count()
        };
        if ready > 0 || Instant::now() >= deadline {
            return ready;
        }
        thread::sleep(Duration::from_millis(200));
    }
}

// ---------- 连接接受与转发(MITM:TLS 终结 + 逐请求转发) ----------
//
// 对齐 Watt/FastGithub 架构:本机用本地 CA 动态签发叶子证书终结 TLS,
// 解密后的明文 HTTP 请求逐个转发到健康上游(见 forward_request):
//   - 上游 IP 与客户端 TLS 会话解耦,403/超时只影响单个请求,换 IP 重发即可;
//   - 证书校验由浏览器对本地叶子证书完成(需信任 qi-bunny CA,见 cert.rs)。

/// 接受循环:HTTPS 连接做 MITM 终结,HTTP 连接直接逐请求转发。
fn accept_loop(listener: TcpListener, https: bool) {
    for stream in listener.incoming() {
        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }
        let Ok(client) = stream else { continue };
        // 客户端首报文有超时,防止挂着不发包的连接占线程
        client.set_read_timeout(Some(HELLO_TIMEOUT)).ok();
        thread::spawn(move || {
            let _ = if https {
                handle_https_mitm(client)
            } else {
                handle_http_plain(client)
            };
        });
    }
}

/// MITM TLS 接收器(进程内共享):按 SNI 现场签发叶子证书
fn mitm_tls_config() -> Option<&'static Arc<rustls::ServerConfig>> {
    static CFG: OnceLock<Option<Arc<rustls::ServerConfig>>> = OnceLock::new();
    CFG.get_or_init(|| {
        // CA 加载失败则重建一次;仍失败放弃 TLS 加速(返回 None):
        // 不该因证书问题让整个代理起不来,HTTPS 连接将由调用方直接关闭
        let ca = match crate::cert::LocalCa::load_or_create() {
            Ok(ca) => ca,
            Err(e) => {
                logerr!("[!] 本地 CA 初始化失败:{},尝试重建…", e);
                match crate::cert::LocalCa::load_or_create() {
                    Ok(ca) => ca,
                    Err(e) => {
                        logerr!("[!] 本地 CA 重建仍失败:{},TLS 加速不可用", e);
                        return None;
                    }
                }
            }
        };
        Some(crate::cert::server_tls_config(crate::cert::LeafCache::new_arc(ca)))
    })
    .as_ref()
}

/// 处理 HTTPS 连接:TLS 终结(本地签证书)→ 明文 HTTP 逐请求转发
fn handle_https_mitm(client: TcpStream) -> io::Result<()> {
    let mut client = client;
    client.set_nodelay(true).ok();

    // TLS 配置不可用(CA 初始化失败):直接关闭连接,不 panic
    let Some(server_cfg) = mitm_tls_config() else {
        return Ok(());
    };
    let server_cfg = server_cfg.clone();
    let mut conn = match rustls::ServerConnection::new(server_cfg) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    let mut tls = rustls::Stream::new(&mut conn, &mut client);

    // 逐请求循环:一条客户端连接(HTTP keep-alive)上可能有多个请求,
    // 每个请求独立转发、独立择路——这正是比透传稳的核心
    while let Some(domain_req) = read_http_request(&mut tls).unwrap_or_default() {
        let resp = forward_request(&domain_req);
        if tls.write_all(&resp).is_err() {
            break;
        }
        // Connection: close 由对端声明时结束循环(read_http_request 已解析)
        if domain_req.close {
            break;
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    Ok(())
}

/// 处理明文 HTTP 连接(80 端口):逐请求转发
fn handle_http_plain(mut client: TcpStream) -> io::Result<()> {
    client.set_nodelay(true).ok();
    while let Some(domain_req) = read_http_request(&mut client).unwrap_or_default() {
        let resp = forward_request(&domain_req);
        if client.write_all(&resp).is_err() {
            break;
        }
        if domain_req.close {
            break;
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    Ok(())
}

/// 解析出的单个 HTTP 请求(明文,来自 TLS 终结或 80 端口)
struct PlainRequest {
    /// 请求行 + 全部头部(含 Host),转发时原样使用
    head: Vec<u8>,
    /// 请求体(POST 等;GitHub 页面请求多为空)
    body: Vec<u8>,
    /// 目标域名(Host 头,已小写去端口)
    domain: String,
    /// 对端是否要求关闭连接
    close: bool,
}

/// 从流中读一个完整 HTTP 请求(头 + 按 Content-Length 的体)。
/// 简化:不支持 chunked 请求体(GitHub 页面请求不用;浏览器上传走别的端口)。
fn read_http_request<S: Read>(stream: &mut S) -> io::Result<Option<PlainRequest>> {
    // 读到头部结束(\r\n\r\n)
    let mut head = Vec::with_capacity(2048);
    let mut buf = [0u8; 1024];
    loop {
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        let n = stream.read(&mut buf)?;
        if n == 0 {
            if head.is_empty() {
                return Ok(None); // 干净关闭
            }
            break; // 半截请求:按有头无体处理
        }
        head.extend_from_slice(&buf[..n]);
        if head.len() > 64 * 1024 {
            return Ok(None); // 异常大头部,放弃
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let _method = parts.next().unwrap_or("GET");
    let _path = parts.next().unwrap_or("/");

    let mut domain = String::new();
    let mut close = false;
    let mut content_length = 0usize;
    let mut connection_seen = false;
    for line in lines {
        if let Some(v) = line
            .strip_prefix("Host:")
            .or_else(|| line.strip_prefix("host:"))
        {
            domain = v.trim().split(':').next().unwrap_or("").to_ascii_lowercase();
        }
        if let Some(v) = line
            .strip_prefix("Connection:")
            .or_else(|| line.strip_prefix("connection:"))
        {
            connection_seen = true;
            if v.to_ascii_lowercase().contains("close") {
                close = true;
            }
        }
        if let Some(v) = line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
        {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    if domain.is_empty() {
        return Ok(None);
    }
    // HTTP/1.1 默认 keep-alive;仅当对端显式 close 才关
    if !connection_seen {
        close = false;
    }

    // 读请求体
    let mut body = Vec::new();
    if content_length > 0 && content_length <= 8 * 1024 * 1024 {
        // 头部里可能已带上体的开头;这里简化:头部 \r\n\r\n 之后的部分
        if let Some(pos) = find_head_end(&head) {
            let consumed = pos + 4;
            if head.len() > consumed {
                body.extend_from_slice(&head[consumed..]);
            }
        }
        while body.len() < content_length {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buf[..n]);
        }
        body.truncate(content_length);
    }

    // head 只保留请求头本身(截掉 \r\n\r\n 之后混入的体字节),
    // 否则转发重建时会多出一个空行,上游按协议错误回 400 Bad Request
    if let Some(pos) = find_head_end(&head) {
        head.truncate(pos + 4);
    }

    Ok(Some(PlainRequest {
        head,
        body,
        domain,
        close,
    }))
}

/// 找头部结束位置(\r\n\r\n 的起点)
fn find_head_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|w| w == b"\r\n\r\n")
}

// ---------- 逐请求转发器(对齐 Watt ConnectCallback:每请求独立择路) ----------

/// 单请求转发预算:单 IP 上游整体(连接+发+收响应头)超时
const UPSTREAM_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// 单请求最多尝试的候选 IP 数(全部失败后回 DNS 递补再来一轮)
const FORWARD_MAX_IPS: usize = 4;

/// 转发单个明文 HTTP 请求到 GitHub 上游:多候选 IP 依次尝试,
/// 失败(连不上/超时/5xx/拦截页)自动换下一个 IP 重试——403 风控、
/// 单 IP 抖动在这里被"消化"掉,浏览器只看到最终成功或标准 5xx。
/// 返回完整 HTTP 响应字节(头+体,Content-Length 或到 EOF)。
fn forward_request(req: &PlainRequest) -> Vec<u8> {
    let domain = &req.domain;
    // HTTPS 终结出来的明文请求,转发到上游仍走 443 TLS;80 端口的走 80
    let https = true;

    // 等候选池就绪(与旧透传一致:首轮探测可能未完成)
    wait_pool(domain);

    let mut last_resp: Vec<u8> = Vec::new();
    let mut tried: HashSet<String> = HashSet::new();
    for _ in 0..FORWARD_MAX_IPS {
        // 同一请求内不重复尝试同一 IP:池里健康候选很少时,
        // 4 轮重试全打在同一个坏 IP 上会把浏览器耐心耗光(表现为超时 000)
        let Some(ip) = (0..FORWARD_MAX_IPS).find_map(|_| {
            pick_upstream(domain).filter(|ip| tried.insert(ip.clone()))
        }) else {
            break; // 池空或全部已试过,走兜底
        };
        let t0 = Instant::now();
        match send_request_to_ip(&ip, domain, https, req) {
            Ok(resp) => {
                let elapsed = t0.elapsed().as_millis();
                // 拦截页特征(200 伪装)同样换 IP 重试:这是"Access to this
                // site has been restricted"在转发层的最后防线
                if is_block_page(&resp) {
                    mark_fail(domain, &ip);
                    last_resp = resp;
                    continue;
                }
                // 上游 5xx 换 IP 重试:单 IP 的 502/503 多为该出口被限流,
                // 不是 GitHub 全局故障——还有候选就该再试(对齐 Watt
                // ConnectCallback 的"坏出口即换"策略);全部候选都 5xx
                // 才把最后的响应交给客户端
                if is_upstream_5xx(&resp) && last_resp.is_empty() {
                    record_sample(domain, &ip, false, elapsed);
                    mark_fail(domain, &ip);
                    last_resp = resp;
                    continue;
                }
                // 真实转发成功:试用 IP 在此转正,健康候选失败分清零
                record_sample(domain, &ip, true, elapsed);
                mark_success(domain, &ip);
                return resp;
            }
            Err(e) => {
                record_sample(domain, &ip, false, t0.elapsed().as_millis());
                mark_fail(domain, &ip);
                logerr!("[*] {} 上游 {} 转发失败({}),换下一个候选", domain, ip, e);
            }
        }
    }
    // 健康候选全部失败:DNS 现场解析递补(先验证再转发,避免交出拦截页)
    for ip in crate::dns::candidates(domain) {
        if crate::probe::recheck(domain, &ip) {
            if let Ok(resp) = send_request_to_ip(&ip, domain, https, req) {
                if !is_block_page(&resp) {
                    return resp;
                }
            }
        }
    }
    if last_resp.is_empty() {
        last_resp = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
    }
    last_resp
}

/// 把单个请求经 TLS 发到指定上游 IP,读回完整响应。
/// 上游 TLS 校验证书域名(webpki 根),保证连的是真 GitHub。
fn send_request_to_ip(
    ip: &str,
    domain: &str,
    https: bool,
    req: &PlainRequest,
) -> Result<Vec<u8>, String> {
    if https {
        // 暖连接优先:LIFO 借用最新入池者(最可能还活着),keep-alive 发送。
        // 暖连接已死(被上游/中间设备关闭)在此静默降级冷连——错误不外抛,
        // 避免转发层把"连接池陈旧"误记成该 IP 故障
        if let Some(mut warm) = warm_take(domain, ip) {
            match write_and_read_reusable(&mut warm.tls, req) {
                Ok((resp, true)) => {
                    warm_put(domain, ip, warm.tls);
                    return Ok(resp);
                }
                Ok((resp, false)) => return Ok(resp), // close 语义响应,连接用完即弃
                Err(_) => {
                    warm_evict_idle(); // 死连接顺手清理,继续走冷连
                }
            }
        }
        // 冷连:握手后也用 keep-alive,响应按分帧收齐则连接入池复用
        let mut tls = tls_connect(domain, ip)?;
        match write_and_read_reusable(&mut tls, req) {
            Ok((resp, true)) => {
                warm_put(domain, ip, tls);
                Ok(resp)
            }
            Ok((resp, false)) => Ok(resp),
            Err(e) => Err(e),
        }
    } else {
        // 80 端口保持旧行为:直连 + close 语义
        let addr = format!("{}:{}", ip, 80)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("bad ip")?;
        let mut stream = TcpStream::connect_timeout(&addr, UPSTREAM_CONNECT_TIMEOUT)
            .map_err(|e| e.to_string())?;
        stream.set_nodelay(true).ok();
        stream.set_read_timeout(Some(UPSTREAM_REQUEST_TIMEOUT)).ok();
        stream.set_write_timeout(Some(UPSTREAM_REQUEST_TIMEOUT)).ok();
        write_and_read_response(&mut stream, req)
    }
}

/// keep-alive 版请求读写:发请求(保留上游连接)并读完整响应;
/// 返回 (响应, 连接是否可复用)——仅当响应按 Content-Length/chunked
/// 分帧收齐时可复用(close 语义/读满 EOF 的响应无法保证流位置对齐)。
fn write_and_read_reusable<S: Read + Write>(
    stream: &mut S,
    req: &PlainRequest,
) -> Result<(Vec<u8>, bool), String> {
    // 重建请求头:与 close 版一致,仅 Connection 换成 keep-alive
    let mut out = Vec::with_capacity(req.head.len() + req.body.len() + 64);
    let head_text = String::from_utf8_lossy(&req.head);
    let mut first = true;
    for line in head_text.lines() {
        if first {
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
            first = false;
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if line.is_empty() || lower.starts_with("host:") || lower.starts_with("connection:") || lower.starts_with("keep-alive:") {
            continue;
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Host: {}\r\n", req.domain).as_bytes());
    out.extend_from_slice(b"Connection: keep-alive\r\n");
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&req.body);

    stream
        .write_all(&out)
        .map_err(|e| format!("发送请求失败:{}", e))?;

    let (resp, framed) = read_full_response_framed(stream)?;
    Ok((resp, framed))
}

/// 组装转发请求(重写 Host 与 Connection,带体)并读完整响应
fn write_and_read_response<S: Read + Write>(stream: &mut S, req: &PlainRequest) -> Result<Vec<u8>, String> {
    // 重建请求头:原样保留绝大部分,仅重写 Host/Connection
    let mut out = Vec::with_capacity(req.head.len() + req.body.len() + 64);
    let head_text = String::from_utf8_lossy(&req.head);
    let mut first = true;
    for line in head_text.lines() {
        if first {
            // 请求行原样(GET /path HTTP/1.1)
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
            first = false;
            continue;
        }
        let lower = line.to_ascii_lowercase();
        // head 保留到 \r\n\r\n,lines() 会在结尾产生空行——必须跳过,
        // 否则空行提前终止请求头,后面的 Host/Connection 全被上游当成 body
        if line.is_empty() || lower.starts_with("host:") || lower.starts_with("connection:") || lower.starts_with("keep-alive:") {
            continue; // 下面统一重写
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Host: {}\r\n", req.domain).as_bytes());
    out.extend_from_slice(b"Connection: close\r\n");
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&req.body);

    stream
        .write_all(&out)
        .map_err(|e| format!("发送请求失败:{}", e))?;

    read_full_response(stream)
}

/// 读完整 HTTP 响应:优先按头部声明的分帧终止,
///   - Content-Length:读够头 + N 字节即止;
///   - Transfer-Encoding: chunked:读到终止块(0 长度块)即止;
///   - 都没有:按 Connection: close 语义读到 EOF。
///
/// 上游若忽略 close 语义保持连接,这里也不会白等到超时才丢掉已收数据。
fn read_full_response<S: Read>(stream: &mut S) -> Result<Vec<u8>, String> {
    let mut resp = Vec::with_capacity(16 * 1024);
    let mut buf = [0u8; 16 * 1024];
    let mut head_end: Option<usize> = None;
    loop {
        // 头部已完整且按其分帧判定已到体末尾 → 提前收工
        if let Some(pos) = head_end {
            let head = String::from_utf8_lossy(&resp[..pos]);
            let lower = head.to_ascii_lowercase();
            if let Some(cl) = extract_header(&lower, "content-length:")
                .and_then(|v| v.trim().parse::<usize>().ok())
            {
                if resp.len() >= pos + 4 + cl {
                    break;
                }
            } else if lower.contains("transfer-encoding:") && lower.contains("chunked") {
                // 终止块:0 长度块出现在尾部("0\r\n\r\n",可能带 trailer 前先见 \r\n)
                if resp.ends_with(b"0\r\n\r\n") {
                    break;
                }
            }
            // 无 CL 无 chunked:只能读到 EOF
        }
        match stream.read(&mut buf) {
            Ok(0) => break, // EOF:close 语义正常结束
            Ok(n) => {
                resp.extend_from_slice(&buf[..n]);
                if head_end.is_none() {
                    head_end = find_head_end(&resp);
                }
                if resp.len() > 32 * 1024 * 1024 {
                    break; // 防失控上限
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                // 超时:头都不完整或体未按分帧收齐才算失败,否则按已有数据交付
                if head_end.is_none() {
                    return Err("上游响应超时".into());
                }
                break;
            }
            Err(e) => return Err(format!("读响应失败:{}", e)),
        }
    }
    if resp.is_empty() {
        return Err("上游 0 字节响应".into());
    }
    Ok(resp)
}

/// 读完整响应并判定连接可否复用(keep-alive):按 Content-Length/chunked
/// 分帧收齐 → (响应, true);靠 EOF 才收齐(close 语义)→ (响应, false)。
/// 内部逻辑与 read_full_response 相同,仅额外追踪分帧终止是否命中。
fn read_full_response_framed<S: Read>(stream: &mut S) -> Result<(Vec<u8>, bool), String> {
    let mut resp = Vec::with_capacity(16 * 1024);
    let mut buf = [0u8; 16 * 1024];
    let mut head_end: Option<usize> = None;
    let mut framed_end = false;
    loop {
        if let Some(pos) = head_end {
            let head = String::from_utf8_lossy(&resp[..pos]);
            let lower = head.to_ascii_lowercase();
            if let Some(cl) = extract_header(&lower, "content-length:")
                .and_then(|v| v.trim().parse::<usize>().ok())
            {
                if resp.len() >= pos + 4 + cl {
                    framed_end = true;
                    break;
                }
            } else if lower.contains("transfer-encoding:") && lower.contains("chunked") {
                if resp.ends_with(b"0\r\n\r\n") {
                    framed_end = true;
                    break;
                }
            }
        }
        match stream.read(&mut buf) {
            Ok(0) => break, // EOF:close 语义,不可复用
            Ok(n) => {
                resp.extend_from_slice(&buf[..n]);
                if head_end.is_none() {
                    head_end = find_head_end(&resp);
                }
                if resp.len() > 32 * 1024 * 1024 {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                if head_end.is_none() {
                    return Err("上游响应超时".into());
                }
                break;
            }
            Err(e) => return Err(format!("读响应失败:{}", e)),
        }
    }
    if resp.is_empty() {
        return Err("上游 0 字节响应".into());
    }
    Ok((resp, framed_end))
}

/// 从(已小写的)响应头文本里取指定头的值
fn extract_header(lower_head: &str, name: &str) -> Option<String> {
    lower_head.lines().find_map(|l| {
        l.strip_prefix(name).map(|v| v.trim().split(',').next().unwrap_or("").to_string())
    })
}

/// 拦截页判定(与 probe.rs 的 BLOCK_MARKS 一致,转发层最后一道防线)
fn is_block_page(resp: &[u8]) -> bool {
    let text = String::from_utf8_lossy(&resp[..resp.len().min(8192)]);
    text.contains("Access to this site has been restricted")
        || text.contains("Whoa there!")
        || text.contains("has been restricted")
}

/// 上游 5xx 判定:读响应头第一行的状态码,50x 即视为该出口劣化
fn is_upstream_5xx(resp: &[u8]) -> bool {
    let head = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| &resp[..p])
        .unwrap_or(&resp[..resp.len().min(1024)]);
    let text = String::from_utf8_lossy(head);
    let status = text.lines().next().unwrap_or("");
    status.starts_with("HTTP/1.1 5") || status.starts_with("HTTP/1.0 5") || status.starts_with("HTTP/2 5")
}

// ---------- 上游选择与打分 ----------

/// 等待候选池就绪(首轮探测进行中时最多等 POOL_WAIT)
fn wait_pool(domain: &str) {
    let deadline = Instant::now() + POOL_WAIT;
    while Instant::now() < deadline {
        {
            let s = lock(store());
            if s.pools.get(domain).map(|v| !v.is_empty()).unwrap_or(false) {
                return;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// 轮询打散窗口:只在延迟最优的前 N 个健康候选中轮询选路——既保持低延迟,
/// 又避免全部连接压到同一个 IP(单 IP 高并发是触发 GitHub 403 风控的典型模式)
const SPREAD_WINDOW: usize = 3;

/// 连接级轮询计数器:每次选路 +1,实现候选间的负载打散
static PICK_TICK: AtomicUsize = AtomicUsize::new(0);

// ---------- 上游暖连接池(按 domain+ip 索引的 TLS 长连接) ----------

/// 单条暖连接:已握手的 TLS 流(owns TCP + ClientConnection)+ 入池时刻
struct WarmConn {
    tls: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
    born: Instant,
}

/// 暖池:键 = (domain, ip),值 = 该上游的空闲长连接列表(LIFO 复用)
fn warm_pool() -> &'static Mutex<HashMap<(String, String), Vec<WarmConn>>> {
    static S: OnceLock<Mutex<HashMap<(String, String), Vec<WarmConn>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 每个上游最多缓存的空闲连接数(对齐 Watt HTTP/2 多路复用的并发承载:
/// HTTP/1.1 一连接一请求,浏览器打开页面数十并发,3 条暖池瞬间耗尽即排队
/// 超时被计为失败——扩到 8 条缓解高并发瓶颈)
const WARM_MAX_PER_KEY: usize = 8;
/// 空闲连接的最长保留时间:GitHub/中间设备的 keep-alive 超时通常 60s 级,
/// 超过即淘汰(复用一条已被上游关掉的连接只会白白失败一次)
const WARM_MAX_IDLE: Duration = Duration::from_secs(50);
/// 全局暖池连接总数上限(8 域名 × 8 已够用,防失控)
const WARM_MAX_TOTAL: usize = 64;

/// 归还一条可复用连接(LIFO,超限/超总容量则丢最旧的)
fn warm_put(domain: &str, ip: &str, tls: rustls::StreamOwned<rustls::ClientConnection, TcpStream>) {
    let mut pool = lock(warm_pool());
    let key = (domain.to_string(), ip.to_string());
    let list = pool.entry(key).or_default();
    list.push(WarmConn { tls, born: Instant::now() });
    // 容量修剪:单键超限丢最旧;全局超限按入池时间淘汰最旧
    if list.len() > WARM_MAX_PER_KEY {
        list.remove(0);
    }
    let total: usize = pool.values().map(|v| v.len()).sum();
    if total > WARM_MAX_TOTAL {
        let mut all: Vec<((String, String), Instant)> = pool
            .iter()
            .flat_map(|(k, v)| v.iter().map(move |w| (k.clone(), w.born)))
            .collect();
        all.sort_by_key(|(_, b)| *b);
        let excess = total - WARM_MAX_TOTAL;
        for (key, _) in all.into_iter().take(excess) {
            if let Some(v) = pool.get_mut(&key) {
                v.remove(0);
            }
        }
    }
}

/// 借走一条暖连接(LIFO:最新入池的最可能还活着)
fn warm_take(domain: &str, ip: &str) -> Option<WarmConn> {
    let mut pool = lock(warm_pool());
    pool.get_mut(&(domain.to_string(), ip.to_string()))?.pop()
}

/// 淘汰过期暖连接(空闲超时);返回清理的条数
fn warm_evict_idle() -> usize {
    let mut pool = lock(warm_pool());
    let mut removed = 0;
    for v in pool.values_mut() {
        let before = v.len();
        v.retain(|w| w.born.elapsed() < WARM_MAX_IDLE);
        removed += before - v.len();
    }
    pool.retain(|_, v| !v.is_empty());
    removed
}

/// 后台暖池维护:淘汰过期连接 + 为健康 IP 预热(每域名给延迟最优的前
/// 2 个 IP 各保 1 条暖连接,请求到来时零握手直接发)
fn warm_maintain(domains: &[String]) {
    warm_evict_idle();
    for d in domains {
        // 取当前延迟最优的前 2 个健康 IP
        let ips: Vec<String> = {
            let s = lock(store());
            let mut h: Vec<&Cand> = s.pools.get(d).map(|v| v.iter().filter(|c| c.fails == 0).collect()).unwrap_or_default();
            h.sort_by_key(|c| c.latency_ms);
            h.iter().take(2).map(|c| c.ip.clone()).collect()
        };
        for ip in ips {
            // 该上游已有暖连接则跳过(预热的目的是"至少 1 条在手")
            let has = lock(warm_pool()).contains_key(&(d.to_string(), ip.clone()));
            if has {
                continue;
            }
            // 后台静默握手:失败不打扰主流程(说明该 IP 当前连不通,
            // 由转发失败/探测路径负责处理)
            if let Ok(tls) = tls_connect(d, &ip) {
                warm_put(d, &ip, tls);
            }
        }
    }
}

/// SNI 随机化(对齐 Watt WithRandom):GitHub 系域名证书均为通配符
/// (*.github.com / *.githubusercontent.com),在主机名最左侧加随机标签,
/// 证书校验依然通过,但 DPI 无法按 SNI 精确匹配发 RST。
/// 探测路径(probe.rs)必须用真实域名(它是"能否服务用户"的判定),
/// 仅转发路径(tls_connect)做伪装。
fn sni_disguise(domain: &str) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut label = String::with_capacity(8);
    for _ in 0..8 {
        label.push(CHARS[fastrand_idx()] as char);
    }
    format!("{}.{}", label, domain)
}

/// 轻量伪随机(无需额外依赖:进程内原子计数 + 混淆)
fn fastrand_idx() -> usize {
    static TICK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let t = TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut x = t.wrapping_mul(0x9E3779B97F4A7C15) ^ std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    (x % 36) as usize
}

/// 对上游建立 TLS 连接(握手完成),供暖池预热与冷连路径共用。
/// SNI 伪装优先(随机子域),握手被 RST 时回退真实域名重试一次——
/// 通配符证书使两种 SNI 都能通过 webpki 校验。
fn tls_connect(domain: &str, ip: &str) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    let addr = format!("{}:{}", ip, 443)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("bad ip")?;
    let mut stream = TcpStream::connect_timeout(&addr, UPSTREAM_CONNECT_TIMEOUT).map_err(|e| e.to_string())?;
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(UPSTREAM_REQUEST_TIMEOUT)).ok();
    stream.set_write_timeout(Some(UPSTREAM_REQUEST_TIMEOUT)).ok();

    // 伪装 SNI 握手:先在裸流上 complete_io 驱动完整握手,失败(典型为
    // RST)即回退真实域名 SNI 重试同一连接
    if let Ok(sni) = rustls::pki_types::ServerName::try_from(sni_disguise(domain)) {
        if let Ok(mut conn) = rustls::ClientConnection::new(crate::probe::tls_config_pub(), sni) {
            if conn.complete_io(&mut stream).is_ok() {
                return Ok(rustls::StreamOwned::new(conn, stream));
            }
        }
    }
    // 回退:真实域名 SNI(部分上游不接受陌生子域时的保底)
    let server_name = rustls::pki_types::ServerName::try_from(domain.to_string()).map_err(|e| e.to_string())?;
    let mut conn = rustls::ClientConnection::new(crate::probe::tls_config_pub(), server_name)
        .map_err(|e| e.to_string())?;
    conn.complete_io(&mut stream).map_err(|e| e.to_string())?;
    Ok(rustls::StreamOwned::new(conn, stream))
}


/// 如已被踢出后才返回的迟到结果)
fn record_sample(domain: &str, ip: &str, ok: bool, elapsed_ms: u128) {
    let mut s = lock(store());
    if let Some(pool) = s.pools.get_mut(domain) {
        if let Some(c) = pool.iter_mut().find(|c| c.ip == ip) {
            ewma_update(c, ok, elapsed_ms);
        }
    }
}

/// 从健康池选上游:有真实流量样本(EWMA)的候选按"成功率降序、耗时升序"
/// 排,无样本的新候选按探测延迟排并插在 EWMA 全绿者之后——真实流量是
/// "现在通"的证据,优先级高于探测延迟这种陈旧数据;健康池空时回退取
/// 失败分最低者(给劣化 IP 恢复机会)。
fn pick_upstream(domain: &str) -> Option<String> {
    let s = lock(store());
    let pool = s.pools.get(domain)?;
    let mut healthy: Vec<&Cand> = pool.iter().filter(|c| c.fails == 0).collect();
    healthy.sort_by(|a, b| {
        let key = |c: &Cand| (c.ewma_ok.unwrap_or(1000), Reverse(c.ewma_ms.unwrap_or(u128::MAX)));
        key(b).cmp(&key(a)).then_with(|| c0_lat(a).cmp(&c0_lat(b)))
    });
    let chosen = if healthy.is_empty() {
        pool.iter().min_by_key(|c| c.fails)
    } else {
        let window = healthy.len().min(SPREAD_WINDOW);
        let idx = PICK_TICK.fetch_add(1, Ordering::Relaxed) % window;
        Some(healthy[idx])
    };
    chosen.map(|c| c.ip.clone())
}

/// 无样本候选的排序键(探测延迟);有样本者返回 0 保证排在其 EWMA 组内
fn c0_lat(c: &Cand) -> u128 {
    if c.ewma_ok.is_none() { c.latency_ms } else { 0 }
}

/// 失败事件通知:mark_fail 通过它唤醒 standby 线程立即补池(事件驱动,
/// 平时主池健康则 standby 完全静默,零探测流量)
fn fail_event() -> &'static (Mutex<Vec<String>>, Condvar) {
    static S: OnceLock<(Mutex<Vec<String>>, Condvar)> = OnceLock::new();
    S.get_or_init(|| (Mutex::new(Vec::new()), Condvar::new()))
}

/// 熔断时间窗口:窗口内的失败才累计,超窗自动清零(瞬时抖动不误伤)
const TRIP_WINDOW: Duration = Duration::from_secs(60);
/// 窗口内失败达到该次数即熔断踢出(不等探测周期/FAIL_KICK)
const TRIP_THRESHOLD: usize = 3;

/// 记录上游连接失败:失败分 +1,达到阈值踢出候选;试用 IP(应急快速通道
/// 入池、未经完整确认)失败一次立即踢出——试用资格由真实转发严格检验;
/// 熔断窗口(60s 内 3 败)内连续失败的 IP 即时踢出,不等探测周期——
/// 坏 IP 的失败代价从"最多 FAIL_KICK 次转发"压到窗口阈值;
/// 同时通知 standby 线程该域名需要紧急补池(只入队不等待,转发路径零阻塞)
fn mark_fail(domain: &str, ip: &str) {
    let mut s = lock(store());
    if let Some(pool) = s.pools.get_mut(domain) {
        if let Some(c) = pool.iter_mut().find(|c| c.ip == ip) {
            if c.probation {
                // 试用 IP:真实转发失败即证明验证不足,立即出局,不给第二次
                pool.retain(|c| c.ip != ip);
                drop(s);
                let (q, cv) = fail_event();
                let mut q = lock(q);
                if !q.iter().any(|d| d == domain) {
                    q.push(domain.to_string());
                }
                cv.notify_all();
                return;
            }
            c.fails = c.fails.saturating_add(1);
            // 时间窗口熔断:只保留窗口内失败时刻,达阈值即出局
            let now = Instant::now();
            c.recent_fails.retain(|t| now.duration_since(*t) < TRIP_WINDOW);
            c.recent_fails.push(now);
        }
        pool.retain(|c| c.fails < FAIL_KICK && c.recent_fails.len() < TRIP_THRESHOLD);
    }
    drop(s);
    // 事件驱动补池:去重入队,唤醒 standby
    let (q, cv) = fail_event();
    let mut q = lock(q);
    if !q.iter().any(|d| d == domain) {
        q.push(domain.to_string());
    }
    cv.notify_all();
}

/// 记录上游转发成功:试用 IP 转正(真实流量验证通过),健康候选失败分清零
/// ——比衰减更直接,转发成功即证明当前可用,让被瞬时抖动误伤的候选
/// 立即回到健康轮询窗口
fn mark_success(domain: &str, ip: &str) {
    let mut s = lock(store());
    if let Some(pool) = s.pools.get_mut(domain) {
        if let Some(c) = pool.iter_mut().find(|c| c.ip == ip) {
            c.probation = false;
            c.fails = 0;
            c.recent_fails.clear();
        }
    }
}

/// 失败分阈值:连续达到即从池中剔除(后台探测会补充新候选)
const FAIL_KICK: u32 = 3;

// ---------- 候选采集与后台探测(上游健康池) ----------

/// 为单域名刷新候选池:多路候选(缓存+DNS+第三方源)并行 TLS 探测,
/// 保留全部握手成功者(按延迟升序),失败分清零(探测通过即视为健康)。
fn refresh_pool(domain: &str) -> Vec<Cand> {
    // 候选池硬上限:多路源(尤其第三方历史库)可能灌入上百条记录,而探测
    // 是分批串行的,池子过大会让首轮探测耗时失控(表现为"代理开了但一直
    // 没就绪")。超限时优先保留 last-good 与 DNS 结果——它们已在池子头部。
    const MAX_POOL: usize = 48;
    let lastgood = crate::load_lastgood_pub();
    let mut pool = crate::candidate_pool_with(domain, &lastgood);
    if pool.is_empty() {
        return Vec::new();
    }
    pool.truncate(MAX_POOL);

    // 复用 probe 模块的真实 TLS 握手测速(过滤 403 滥用拦截等假握手)
    let mut cands: Vec<Cand> = crate::probe::probe_all(domain, &pool)
        .into_iter()
        .map(|p| Cand {
            ip: pool[p.ip_index].clone(),
            fails: 0,
            latency_ms: p.elapsed_ms,
            probation: false,
            ewma_ok: None,
            ewma_ms: None,
            recent_fails: Vec::new(),
        })
        .collect();
    cands.sort_by_key(|c| c.latency_ms);
    // 延迟过滤:探测 8s 内能握手即算成功,但 8s 级的 IP 对浏览器等同不可用
    // (TLS 握手超过客户端耐心,重试链路 10s+ 后直接失败)。优先只留 3s 内
    // 的快 IP;快 IP 不足 MIN_HEALTHY 时用慢 IP 补足池深——转发层每请求
    // 独立择路,候选多一点,单 IP 劣化时才有得换(只留 1 个 = 无冗余)。
    const MAX_OK_LATENCY_MS: u128 = 3000;
    let fast: Vec<Cand> = cands
        .iter()
        .filter(|c| c.latency_ms <= MAX_OK_LATENCY_MS)
        .cloned()
        .collect();
    if fast.len() >= MIN_HEALTHY {
        cands = fast;
    }
    // 探测成功的上游学习到 last-good 缓存:下次启动优先参选,
    // DNS/第三方源全部失效时也有可用起点(只存真实上游,绝非 127.0.0.1)
    if !cands.is_empty() {
        let entries: Vec<(String, String)> = cands
            .iter()
            .take(3)
            .map(|c| (domain.to_string(), c.ip.clone()))
            .collect();
        crate::learn_good(&entries);
    }
    cands
}

/// 后台探测主循环:立即全量探测;之后每 PROBE_INTERVAL 维护一轮。
/// 池内健康候选不足时(被淘汰过多)重新采集外部候选补充。
/// 稳定优先:健康候选充足且无失败时跳过重测,间隔指数退避(2→4→8 分钟,
/// 封顶 30 分钟);出现失败立即回到最短间隔复检——"稳定就不乱刷"。
fn prober_loop(domains: Vec<String>) {
    // 首轮:逐域名探测(后台线程,不阻塞连接接受;连接侧会等池就绪)
    for d in &domains {
        let cands = refresh_pool(d);
        let n = cands.len();
        lock(store()).pools.insert(d.clone(), cands);
        if n == 0 {
            logerr!("[!] {} 首轮探测无可用 IP,稍后自动重试", d);
        } else {
            log!("[*] {} 候选就绪:{} 个可用上游", d, n);
        }
    }

    while RUNNING.load(Ordering::SeqCst) {
        // 有域名候选池为空(探测全挂/采集失败)时用短间隔快速重试,
        // 不必等满 PROBE_INTERVAL——否则该域名服务中断长达 2 分钟
        let empty_pool = {
            let s = lock(store());
            domains.iter().any(|d| s.pools.get(d).map(|v| v.is_empty()).unwrap_or(true))
        };
        let interval = if empty_pool { EMPTY_POOL_RETRY } else { PROBE_INTERVAL };
        // 分段休眠,保证 stop() 能及时退出
        let mut waited = Duration::ZERO;
        // 连续"零失败"轮数(自适应退避用):链路全绿时逐轮拉长探测间隔
        let mut calm_rounds = 0usize;
        while waited < interval && RUNNING.load(Ordering::SeqCst) {
            let step = Duration::from_secs(2).min(interval - waited);
            thread::sleep(step);
            waited += step;
        }
        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }

        for d in &domains {
            if !RUNNING.load(Ordering::SeqCst) {
                break;
            }
            // 防重叠:同域名上一轮刷新未结束则跳过
            {
                let mut ip = lock(in_progress());
                if !ip.insert(d.clone()) {
                    continue;
                }
            }
            let healthy = {
                let s = lock(store());
                s.pools
                    .get(d)
                    .map(|v| v.iter().filter(|c| c.fails == 0).count())
                    .unwrap_or(0)
            };
            // 稳定就不动:健康候选充足且上一轮以来转发流量一直成功,说明链路
            // 工作正常——周期全量重测+整池重排反而引入抖动(连接被换到另一个
            // "更快"的 IP、正在传输的流被拆)。只在本轮有失败发生时才需要
            // 重新探测:失败分 > 0 意味着有 IP 劣化,需要复检换血;零失败则
            // 把本轮的探测预算省掉,池子保持原样。
            let any_fails = {
                let s = lock(store());
                s.pools
                    .get(d)
                    .map(|v| v.iter().any(|c| c.fails > 0))
                    .unwrap_or(false)
            };
            // 连续全绿轮数:越多越说明链路稳定,探测间隔可以拉得越长
            // (2min -> 4min -> 8min,封顶 30min);一旦出现失败立即回 2min
            if healthy >= MIN_HEALTHY && !any_fails {
                calm_rounds = (calm_rounds + 1).min(8);
                let backoff = (PROBE_INTERVAL * (1u32 << calm_rounds.min(4))).min(Duration::from_secs(1800));
                log!(
                    "[*] {} 链路稳定({} 个健康上游,连续 {} 轮无失败),{} 后复检",
                    d, healthy, calm_rounds, format_dur(backoff)
                );
                // 用退避后的间隔快进本轮等待:直接累计到 waited 上
                let skip = backoff.min(PROBE_INTERVAL);
                waited += skip; // 影响外层 while 的剩余等待
                continue;
            }
            calm_rounds = 0;
            if healthy < MIN_HEALTHY {
                // 健康候选不足:重新采集外部候选(慢路径)
                let cands = refresh_pool(d);
                let n = cands.len();
                if n > 0 {
                    lock(store()).pools.insert(d.clone(), cands);
                    log!("[*] {} 候选池已刷新({} 个可用上游)", d, n);
                }
            } else {
                // 常规维护:对现有健康候选重新做完整探测(含 HTTP 状态码校验,
                // 403 滥用拦截的 IP 在此被剔除),按真实延迟重新排序。
                // 探测失败的候选直接出局,防止"TLS 通但被拦截"的 IP 依
                // 靠连接层存活长期占据健康池。
                let ips: Vec<String> = {
                    let s = lock(store());
                    s.pools
                        .get(d)
                        .map(|v| v.iter().filter(|c| c.fails == 0).map(|c| c.ip.clone()).collect())
                        .unwrap_or_default()
                };
                if ips.is_empty() {
                    continue;
                }
                let mut cands: Vec<Cand> = crate::probe::probe_all(d, &ips)
                    .into_iter()
                    .map(|p| Cand {
                        ip: ips[p.ip_index].clone(),
                        fails: 0,
                        latency_ms: p.elapsed_ms,
                        probation: false,
                        ewma_ok: None,
                        ewma_ms: None,
                        recent_fails: Vec::new(),
                    })
                    .collect();
                cands.sort_by_key(|c| c.latency_ms);
                // 探测通过的全部替换池内容(而非仅并入成功者),让被拦截者
                // 立即失去健康资格;探测全挂(网络抖动)时保留旧池,避免误清空
                if !cands.is_empty() {
                    lock(store()).pools.insert(d.clone(), cands);
                }
            }
            lock(in_progress()).remove(d);
        }
        // 暖池维护(每轮):淘汰空闲超时连接,为各域名延迟最优的健康 IP
        // 预热连接——请求到来时零握手直发,单 IP 死亡时切换也是毫秒级
        warm_maintain(&domains);
    }
}

// ---------- Standby 刷选:独立于主池的后台持续采集 ----------

/// Standby 扫描周期:持续刷候选的节奏(独立线程,不与主池探测争预算)
const STANDBY_INTERVAL: Duration = Duration::from_secs(90);
/// 单个 standby IP 的重复验证通过次数:连续 N 轮探测都成功才可合并入主池,
/// 过滤"瞬时抖动幸存"的劣质 IP(单次握手通过但下一秒就被干扰)
const STANDBY_CONFIRM_ROUNDS: u32 = 2;
/// 单域名单轮 standby 扫描的候选上限(与主池 MAX_POOL 同量级,控制探测耗时)
const STANDBY_MAX_CANDS: usize = 24;

/// Standby 候选:IP + 连续验证通过轮数(独立记分,与主池 fails 体系无关)
#[derive(Debug, Clone)]
struct Standby {
    ip: String,
    latency_ms: u128,
    confirm: u32,
}

/// 各域名独立的 standby 候选空间(与主池分离:刷选过程绝不触碰主池,
/// 只有验证充分后才做单向合并,不影响正在服务的稳定 IP)
fn standby_store() -> &'static Mutex<HashMap<String, Vec<Standby>>> {
    static S: OnceLock<Mutex<HashMap<String, Vec<Standby>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 单轮 standby 扫描:独立采集(lastgood+DNS+第三方源)→ 探测 → 连续记分。
/// 只读写 standby_store,不触碰主池。
fn standby_scan(domain: &str) {
    // 采集:排除当前主池里已有的 IP——standby 只找"新鲜的替补",不重复验证主力
    let main_ips: Vec<String> = {
        let s = lock(store());
        s.pools.get(domain).map(|v| v.iter().map(|c| c.ip.clone()).collect()).unwrap_or_default()
    };
    let lastgood = crate::load_lastgood_pub();
    let cands: Vec<String> = crate::candidate_pool_with(domain, &lastgood)
        .into_iter()
        .filter(|ip| !main_ips.contains(ip))
        .take(STANDBY_MAX_CANDS)
        .collect();

    // 探测:复用 probe 模块(真实 TLS 握手 + 拦截页过滤)
    let ok: HashSet<&str> = crate::probe::probe_all(domain, &cands)
        .into_iter()
        .map(|p| cands[p.ip_index].as_str())
        .collect();

    let mut sb = lock(standby_store());
    let entry = sb.entry(domain.to_string()).or_default();
    // 已通过者累加记分,未通过者立即出局(连续通过才有资格)
    for st in entry.iter_mut() {
        if ok.contains(st.ip.as_str()) {
            st.confirm = st.confirm.saturating_add(1);
        }
    }
    entry.retain(|st| ok.contains(st.ip.as_str()));
    // 新通过的 IP 入 standby(第 1 轮,尚不可合并)
    for (i, ip) in cands.iter().enumerate() {
        if ok.contains(ip.as_str()) && !entry.iter().any(|st| &st.ip == ip) {
            if let Some(p) = crate::probe::probe_all(domain, std::slice::from_ref(&cands[i])).first() {
                entry.push(Standby { ip: ip.clone(), latency_ms: p.elapsed_ms, confirm: 1 });
            }
        }
    }
    entry.sort_by_key(|st| st.latency_ms);
}

/// 把 standby 里验证充分的 IP 并入主池,按池深分档:
/// - 池深 > 1:只合并连续 STANDBY_CONFIRM_ROUNDS 轮通过的候选(稳态标准)
/// - 池深 ≤ 1(应急):1 轮探测通过即临时并入,标 probation,由真实转发
///   验证——成功转正,失败立即踢出。最坏恢复时间从"2 轮确认"的分钟级
///   压到一次采集+探测的十几秒级
/// 合并仍是"追加":现有主池条目(含健康节点)一律不改动、不重排、不清零。
fn promote_standby(domain: &str) -> usize {
    // 应急判定:主池健康候选 ≤ 1 时启用快速通道
    let urgent = {
        let s = lock(store());
        s.pools
            .get(domain)
            .map(|v| v.iter().filter(|c| c.fails == 0).count() <= 1)
            .unwrap_or(true)
    };
    let need = if urgent { 1 } else { STANDBY_CONFIRM_ROUNDS };
    let ready: Vec<Standby> = {
        let mut sb = lock(standby_store());
        match sb.get_mut(domain) {
            Some(entry) => {
                let (ready, rest): (Vec<_>, Vec<_>) = entry.drain(..).partition(|st| st.confirm >= need);
                *entry = rest;
                ready
            }
            None => Vec::new(),
        }
    };
    if ready.is_empty() {
        return 0;
    }
    let mut s = lock(store());
    let pool = s.pools.entry(domain.to_string()).or_default();
    let mut promoted = 0;
    for st in ready {
        if pool.iter().any(|c| c.ip == st.ip) {
            continue; // 已在主池(可能在扫描间隙被其他路径加入)
        }
        pool.push(Cand {
            ip: st.ip.clone(),
            fails: 0,
            latency_ms: st.latency_ms,
            // 仅应急通道入池的是试用 IP;稳态合并走完整确认,无需试用
            probation: urgent,
            ewma_ok: None,
            ewma_ms: None,
            recent_fails: Vec::new(),
        });
        promoted += 1;
    }
    pool.sort_by_key(|c| c.latency_ms);
    promoted
}

/// Standby 后台线程主循环(事件驱动):
/// - mark_fail 的失败事件会唤醒本线程,只对失败域名立即采集+探测补池,
///   平时主池健康则完全静默——零探测流量,不向网络暴露批量探测特征;
/// - 无事件时低频兜底扫描全部域名(防"从未有流量"的域名候选陈旧)。
/// 与 prober_loop 完全独立:主池的探测/刷新/踢出逻辑不受影响。
fn standby_loop(domains: Vec<String>) {
    // 首轮等一等:让主池先把首轮探测做完,避免启动时与 prober 抢采集带宽
    thread::sleep(Duration::from_secs(10));
    let (q, cv) = fail_event();
    let mut pending: Vec<String> = domains.clone(); // 兜底:首轮全量扫一遍
    while RUNNING.load(Ordering::SeqCst) {
        // 等待失败事件;无事件则按兜底周期超时醒来做低频全量扫描
        {
            let mut queue = lock(q);
            if queue.is_empty() && pending.is_empty() {
                let (waited, _) = cv.wait_timeout(queue, STANDBY_INTERVAL).unwrap_or_else(|poisoned| {
                    // 锁中毒时取回内部队列继续用(只保护内存缓存,数据仍自洽)
                    poisoned.into_inner()
                });
                queue = waited;
            }
            // 取走本轮要处理的域名(失败事件优先;无事件时兜底全量)
            if !queue.is_empty() {
                pending = std::mem::take(&mut *queue);
            } else if pending.is_empty() {
                pending = domains.clone();
            }
        }
        for d in &pending {
            if !RUNNING.load(Ordering::SeqCst) {
                break;
            }
            // 防重叠:prober 正在刷新该域名时跳过(避免采集/探测互相挤兑)
            {
                let mut ip = lock(in_progress());
                if !ip.insert(d.clone()) {
                    continue;
                }
            }
            standby_scan(d);
            let n = promote_standby(d);
            if n > 0 {
                log!("[*] {} standby 补充 {} 个已验证候选(现役 IP 未受影响)", d, n);
            }
            lock(in_progress()).remove(d);
        }
        pending.clear();
    }
}

/// 时长的人性化显示(日志用)
fn format_dur(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 60 {
        format!("{} 分钟", s / 60)
    } else {
        format!("{} 秒", s)
    }
}

// ---------- 测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn find_head_end_finds_crlf_crlf() {
        assert_eq!(find_head_end(b"HTTP/1.1 200 OK\r\nX: 1\r\n\r\nbody"), Some(21));
        assert_eq!(find_head_end(b"no header here"), None);
    }

    #[test]
    fn extract_header_reads_value() {
        let head = "HTTP/1.1 200 OK\r\nContent-Length: 123\r\nTransfer-Encoding: chunked\r\n".to_ascii_lowercase();
        assert_eq!(extract_header(&head, "content-length:").unwrap(), "123");
        assert_eq!(extract_header(&head, "transfer-encoding:").unwrap(), "chunked");
        assert_eq!(extract_header(&head, "x-missing:"), None);
    }

    #[test]
    fn read_response_content_length_terminates_without_eof() {
        // 上游不关连接、保持挂起:读满 Content-Length 后应立即返回,不等到超时
        let body = "0123456789";
        let wire = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", body.len(), body);
        let resp = read_full_response(&mut Cursor::new(wire.into_bytes())).unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 200 OK"));
        assert!(resp.ends_with(b"0123456789"));
    }

    #[test]
    fn read_response_chunked_terminates_on_last_chunk() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n0\r\n\r\n";
        let resp = read_full_response(&mut Cursor::new(wire.to_vec())).unwrap();
        assert!(resp.ends_with(b"0\r\n\r\n"));
    }

    #[test]
    fn read_response_close_semantics_reads_to_eof() {
        // 无 CL 无 chunked:读到 EOF 才算完整
        let wire = b"HTTP/1.1 200 OK\r\n\r\nhello";
        let resp = read_full_response(&mut Cursor::new(wire.to_vec())).unwrap();
        assert!(resp.ends_with(b"hello"));
    }

    #[test]
    fn read_response_empty_is_error() {
        assert!(read_full_response(&mut Cursor::new(Vec::new())).is_err());
    }

    #[test]
    fn read_request_parses_host_and_body() {
        // 拼一个「头部 + 体分两段到达」的流
        let mut stream = Vec::new();
        stream.extend_from_slice(b"POST /api HTTP/1.1\r\nHost: github.com\r\nContent-Length: 5\r\n\r\nhel");
        stream.extend_from_slice(b"lo!");
        let req = read_http_request(&mut Cursor::new(stream)).unwrap().unwrap();
        assert_eq!(req.domain, "github.com");
        assert_eq!(req.body, b"hello");
        assert!(!req.close);
    }

    #[test]
    fn read_request_without_host_is_rejected() {
        let wire = b"GET / HTTP/1.1\r\nUser-Agent: t\r\n\r\n";
        assert!(read_http_request(&mut Cursor::new(wire.to_vec())).unwrap().is_none());
    }

    #[test]
    fn read_request_eof_without_data_is_none() {
        assert!(read_http_request(&mut Cursor::new(Vec::new())).unwrap().is_none());
    }

    #[test]
    fn read_request_keepalive_default() {
        // HTTP/1.1 未写 Connection 头 → 默认 keep-alive,不关连接
        let wire = b"GET / HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
        let req = read_http_request(&mut Cursor::new(wire.to_vec())).unwrap().unwrap();
        assert!(!req.close);
        assert_eq!(req.domain, "api.github.com");
    }

    #[test]
    fn read_request_close_honored() {
        let wire = b"GET / HTTP/1.1\r\nHost: codeload.github.com\r\nConnection: close\r\n\r\n";
        let req = read_http_request(&mut Cursor::new(wire.to_vec())).unwrap().unwrap();
        assert!(req.close);
    }

    #[test]
    fn read_request_rejects_oversized_head() {
        // 64KB 上限:超长头直接放弃,不挂死
        let mut wire = b"GET / HTTP/1.1\r\nHost: github.com\r\n".to_vec();
        wire.extend(std::iter::repeat_n(b'x', 70 * 1024));
        wire.extend_from_slice(b"\r\n\r\n");
        assert!(read_http_request(&mut Cursor::new(wire)).unwrap().is_none());
    }

    #[test]
    fn block_page_detected() {
        assert!(is_block_page(b"HTTP/1.1 200 OK\r\n\r\nWhoa there! slow down"));
        assert!(is_block_page(b"HTTP/1.1 200 OK\r\n\r\nAccess to this site has been restricted"));
        assert!(!is_block_page(b"HTTP/1.1 200 OK\r\n\r\n<!doctype html>GitHub"));
    }

    #[test]
    fn upstream_5xx_detected() {
        assert!(is_upstream_5xx(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"));
        assert!(is_upstream_5xx(b"HTTP/1.1 503 Service Unavailable\r\n\r\nbody"));
        assert!(!is_upstream_5xx(b"HTTP/1.1 200 OK\r\n\r\n"));
        assert!(!is_upstream_5xx(b"HTTP/1.1 301 Moved\r\n\r\n"));
        assert!(!is_upstream_5xx(b"HTTP/1.1 404 Not Found\r\n\r\n"));
    }

    #[test]
    fn forwarded_request_rewrites_host_and_connection() {
        // 只重写 Host/Connection,其余头原样保留
        let req = PlainRequest {
            head: b"GET /rust-lang/rust HTTP/1.1\r\nHost: github.com\r\nAccept: */*\r\n\r\n".to_vec(),
            body: Vec::new(),
            domain: "github.com".into(),
            close: false,
        };
        // 借 write_and_read_response 的组装逻辑:发到一个本地回显流不便,
        // 这里直接断言它的输入重建路径——用最小上游(本地 TCP 回显)验证
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).unwrap();
            // 回显请求作为响应体,外加合法响应头
            let body = buf[..n].to_vec();
            let mut resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
            resp.extend_from_slice(&body);
            s.write_all(&resp).ok();
        });
        let mut up = TcpStream::connect(addr).unwrap();
        let resp = write_and_read_response(&mut up, &req).unwrap();
        server.join().unwrap();
        let text = String::from_utf8_lossy(&resp);
        let echo = text.split_once("\r\n\r\n").unwrap().1;
        assert!(echo.contains("Host: github.com\r\n"));
        assert!(echo.contains("Connection: close\r\n"));
        assert!(echo.contains("Accept: */*\r\n"));
        assert!(!echo.contains("keep-alive"));
    }
}
