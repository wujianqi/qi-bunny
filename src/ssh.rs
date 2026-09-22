//! 代码库管理模式(SSH 本地反向代理)
//!
//! hosts 加速只覆盖 HTTPS(git clone/pull 的 https 远端),而 SSH 远端
//! (git@github.com)走 22 端口——加速 IP 的 22 端口往往不通,导致无法提交。
//! 本模块的处理:
//!   1. 从候选池中探测 22 端口可用的 github.com IP
//!   2. 有 → 本地 127.0.0.1:2222 转发到该 IP:22,改写 ~/.ssh/config
//!   3. 无(22 全被阻断)→ 回退 GitHub 官方 SSH-over-HTTPS:ssh.github.com:443
//!   4. 关闭时还原 ssh config,转发线程自动退出

use crate::hosts;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

/// SSH_CONFIG 标记块(区别于 hosts 块)
const CFG_BEGIN: &str = "# qi-bunny ssh begin";
const CFG_END: &str = "# qi-bunny ssh end";
/// 旧版标记(github-proxy 时期),clean 时兼容清理
const CFG_LEGACY_BEGIN: &str = "# github-proxy ssh begin";
const CFG_LEGACY_END: &str = "# github-proxy ssh end";

/// 本地 SSH 反向代理监听端口(2222;9418/22 避让)
const SSH_PROXY_PORT: u16 = 2222;

/// 转发器状态
static FORWARD_ACTIVE: AtomicBool = AtomicBool::new(false);
/// 监听器持有者:disable 时 take 并 drop,accept 循环随即退出
static FORWARD_LISTENER: Mutex<Option<TcpListener>> = Mutex::new(None);

/// ssh config 路径(~/.ssh/config)
fn ssh_config_path() -> std::path::PathBuf {
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home).join(".ssh").join("config")
}

/// 代码库管理模式是否已开启(预留状态查询;托盘经 SshStatus 事件跟踪)
#[allow(dead_code)]
pub fn is_active() -> bool {
    FORWARD_ACTIVE.load(Ordering::SeqCst)
}

/// 从候选池中找出 22 端口可直连的 IP(并行 TCP 探测 + SSH banner 校验)。
/// 仅 TCP 握手成功不够——部分网络放行 SYN 但拦截数据,必须读到
/// "SSH-" 开头的 banner 才算真正可用,否则应走 443 回退。
fn pick_ip_with_port22(ips: &[String]) -> Option<String> {
    let (tx, rx) = mpsc::channel::<(String, u128)>();
    for ip in ips {
        let tx = tx.clone();
        let ip = ip.clone();
        thread::spawn(move || {
            let start = std::time::Instant::now();
            // to_socket_addrs 同时兼容 IPv4 与 IPv6 字面量(手动拼 "ip:22" 对 IPv6 会解析失败)
            let addr = match (ip.as_str(), 22u16).to_socket_addrs() {
                Ok(mut it) => match it.next() {
                    Some(a) => a,
                    None => return,
                },
                Err(_) => return,
            };
            if let Ok(s) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                let mut s = s;
                let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
                let mut buf = [0u8; 8];
                use std::io::Read;
                match s.read(&mut buf) {
                    // SSH 服务器连接后立即发 banner("SSH-2.0-…")
                    Ok(n) if n > 0 && buf.starts_with(b"SSH-") => {
                        let _ = tx.send((ip, start.elapsed().as_millis()));
                    }
                    _ => {} // 数据被拦,视为不可用
                }
            }
        });
    }
    drop(tx);
    // 等全部探测结束,取最快成功的
    let mut best: Option<(String, u128)> = None;
    for (ip, ms) in rx {
        if best.as_ref().map(|(_, m)| ms < *m).unwrap_or(true) {
            best = Some((ip, ms));
        }
    }
    best.map(|(ip, _)| ip)
}

/// 开启代码库管理模式。`ips` 为 github.com 的候选 IP 池(调用方汇总)。
pub fn enable_ssh(ips: &[String]) -> Result<&'static str, String> {
    // 幂等:先关旧的
    disable_ssh();

    if let Some(ip) = pick_ip_with_port22(ips) {
        // 本地转发器: 127.0.0.1:2222 -> ip:22
        let listener = TcpListener::bind(("127.0.0.1", SSH_PROXY_PORT))
            .map_err(|e| format!("绑定本地 {} 端口失败:{}", SSH_PROXY_PORT, e))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("设置非阻塞失败:{}", e))?;

        FORWARD_ACTIVE.store(true, Ordering::SeqCst);
        *FORWARD_LISTENER
            .lock()
            .map_err(|_| "转发器状态锁中毒".to_string())? = Some(listener);

        // 转发线程:非阻塞 accept 轮询,便于收到停止信号后干净退出
        thread::spawn(move || {
            loop {
                if !FORWARD_ACTIVE.load(Ordering::SeqCst) {
                    break;
                }
                match FORWARD_LISTENER
                    .lock()
                    .ok()
                    .and_then(|g| g.as_ref().and_then(|l| l.accept().ok()))
                {
                    Some((client, _)) => {
                        let target = ip.clone();
                        thread::spawn(move || {
                            forward_pair(client, &target);
                        });
                    }
                    None => {
                        thread::sleep(Duration::from_millis(120));
                    }
                }
            }
        });

        // 改写 ssh config: github.com -> 127.0.0.1:2222
        let body = format!(
            "Host github.com\n  Hostname 127.0.0.1\n  Port {}\n  User git\n",
            SSH_PROXY_PORT
        );
        write_ssh_config(&body)
            .map_err(|e| format!("写 ssh config 失败:{}(需要用户目录写权限)", e))?;
        Ok("已开启(本地转发)")
    } else {
        // 22 全被阻断 -> 回退官方 SSH-over-HTTPS
        let body = "Host github.com\n  Hostname ssh.github.com\n  Port 443\n  User git\n";
        write_ssh_config(body)
            .map_err(|e| format!("写 ssh config 失败:{}(需要用户目录写权限)", e))?;
        FORWARD_ACTIVE.store(true, Ordering::SeqCst);
        Ok("已开启(443 回退)")
    }
}

/// 关闭代码库管理模式:停止转发器 + 还原 ssh config(含旧版标记残留)。幂等。
pub fn disable_ssh() {
    FORWARD_ACTIVE.store(false, Ordering::SeqCst);
    if let Ok(mut g) = FORWARD_LISTENER.lock() {
        *g = None; // drop 监听器,accept 轮询退出
    }
    let path = ssh_config_path();
    let _ = hosts::remove_marked_block(&path, CFG_BEGIN, CFG_END);
    let _ = hosts::remove_marked_block(&path, CFG_LEGACY_BEGIN, CFG_LEGACY_END);
}

/// 关闭并报告是否发生了实际改动(clean 子命令用)
pub fn disable_and_report() -> bool {
    let had = has_config_block();
    disable_ssh();
    had
}

/// 双向转发,任一方断开即结束。
fn forward_pair(client: TcpStream, target_ip: &str) {
    // to_socket_addrs 兼容 IPv4/IPv6 字面量;带超时防止上游长时间无响应挂住线程
    let upstream = match (target_ip, 22u16)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
        .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok())
    {
        Some(s) => s,
        None => return,
    };
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);
    let mut c = client;
    let mut u = upstream;
    let mut c2 = match c.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut u2 = match u.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let t1 = thread::spawn(move || std::io::copy(&mut c2, &mut u));
    let t2 = thread::spawn(move || std::io::copy(&mut u2, &mut c));
    // 任一方向结束即终止(简化处理:等待两个方向自然结束)
    let _ = t1.join();
    let _ = t2.join();
}

/// 写 ssh config 标记块(确保 ~/.ssh 目录存在)
fn write_ssh_config(body: &str) -> std::io::Result<()> {
    let path = ssh_config_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    hosts::write_marked_block(&path, CFG_BEGIN, CFG_END, body)
}

/// 代码库管理模式是否已写入配置(自检用;含旧版标记)
pub fn has_config_block() -> bool {
    let path = ssh_config_path();
    hosts::has_marked_block(&path, CFG_BEGIN) || hosts::has_marked_block(&path, CFG_LEGACY_BEGIN)
}

/// 验证 SSH 链路:执行 `ssh -T -o BatchMode=yes git@github.com`,
/// 返回 (成功?, 输出摘要)。GitHub 对认证成功返回 "Hi xxx!" / 
/// "successfully authenticated";未配 key 时返回 "Permission denied" ——
/// 两者都说明 SSH 握手已到达 GitHub 认证层,链路本身是通的。
pub fn verify() -> (bool, String) {
    // ssh 参数两平台一致;Windows 下加 CREATE_NO_WINDOW 避免托盘模式闪控制台
    const SSH_ARGS: [&str; 8] = [
        "-T",
        "-o",
        "BatchMode=yes", // 禁交互提示,防无 key 时挂起等输入
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "git@github.com",
    ];
    let mut cmd = std::process::Command::new("ssh");
    cmd.args(SSH_ARGS);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW: 托盘模式下避免闪出控制台窗口
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    verify_out(cmd.output())
}

/// 解析 ssh -T 输出(verify 的共用尾段)
fn verify_out(out: std::io::Result<std::process::Output>) -> (bool, String) {
    match out {
        Ok(o) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            let ok = text.contains("successfully authenticated")
                || text.contains("Hi ")
                || text.contains("Permission denied"); // 已到 GitHub 认证层 = 链路通
            (ok, text.lines().next().unwrap_or("").to_string())
        }
        Err(e) => (false, format!("ssh 命令执行失败:{}", e)),
    }
}
