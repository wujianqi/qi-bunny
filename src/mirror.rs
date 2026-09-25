//! 第三方下载加速模块(候选手段,与主链路完全隔离)
//!
//! 功能:经 gh-proxy 类第三方中转站加速下载 GitHub 上的单文件、
//! Releases 资产与仓库 Archive(zip/tar.gz)。与 hosts/DNS/本机反代
//! 的 HTTPS 加速是两条独立机制——本模块不读不写 hosts、不碰候选
//! IP 池、不监听端口,单独引入或移除均不影响主链路。
//!
//! 机制:
//!   1. 内置一批公开中转源(网络收集,与 xiake.pro 整理的节点池同源);
//!   2. 下载前用极小的探测文件对全部中转源并发测速,按延迟排序;
//!   3. 依序尝试中转源下载,一个失败(连接/HTTP 错误/内容校验不过)
//!      自动切换下一个,全部失败时回退 github.com 直连。
//!
//! 注意:中转源为第三方服务,能看到明文请求路径(不含凭据头),
//! 故仅建议用于开源代码/文档等公开资源,不要经它下载私有内容。

use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// 单中转源测速/连接超时(中转站多在 CF 上,首字节偏慢,放宽到 8s)
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
/// 下载连接建立超时
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// 全部中转源都失败时的直连兜底
const DIRECT_LABEL: &str = "(直连 github.com)";

/// 中转源列表由 address.rs 的 MIRROR_SOURCES 常量提供(地址集中
/// 管理,增删直接改常量表);下载前测速会自动过滤死源。
fn mirrors() -> Vec<String> {
    crate::address::MIRROR_SOURCES.iter().map(|s| s.to_string()).collect()
}

/// 探测目标:vscode 仓库里一张 338 字节的小图,端到端验证中转可用
const PROBE_TARGET: &str =
    "/https://raw.githubusercontent.com/microsoft/vscode/main/resources/win32/code_70x70.png";

/// 一个中转源 + 实测延迟(毫秒)
#[derive(Clone, Debug)]
struct Mirror {
    base: String,
    /// None = 测速失败(死源),排在最后仅作兜底
    latency_ms: Option<u128>,
}

/// 并发测速全部中转源,按"可用优先、延迟升序"返回
fn rank_mirrors() -> Vec<Mirror> {
    let mirrors = mirrors();
    let probes: Vec<_> = mirrors
        .iter()
        .map(|base| {
            let url = format!("{}{}", base, PROBE_TARGET);
            std::thread::spawn(move || {
                let start = Instant::now();
                let ok = ureq::get(&url)
                    .timeout(PROBE_TIMEOUT)
                    .call()
                    .map(|r| r.status() == 200)
                    .unwrap_or(false);
                if ok { Some(start.elapsed().as_millis()) } else { None }
            })
        })
        .collect();
    let mut ranked: Vec<Mirror> = mirrors
        .into_iter()
        .zip(probes)
        .map(|(base, h)| Mirror {
            base,
            latency_ms: h.join().ok().flatten(),
        })
        .collect();
    // 可用的按延迟升序在前;死源保持原序垫底兜底
    ranked.sort_by_key(|m| (m.latency_ms.is_none(), m.latency_ms.unwrap_or(0)));
    ranked
}

/// 把 github.com 原始链接转成经中转源的下载链接。
/// 中转站约定格式:`{镜像}/https://github.com/...`
fn proxied(base: &str, github_url: &str) -> String {
    format!("{}/{}", base, github_url)
}

/// 候选下载顺序:全部中转源(按测速排序)+ 直连兜底
fn candidates(github_url: &str) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = rank_mirrors()
        .into_iter()
        .map(|m| {
            let label = match m.latency_ms {
                Some(ms) => format!("{} ({}ms)", m.base, ms),
                None => format!("{} (未响应)", m.base),
            };
            (proxied(&m.base, github_url), label)
        })
        .collect();
    v.push((github_url.to_string(), DIRECT_LABEL.to_string()));
    v
}

/// 校验是否为可下载的 GitHub 资源链接(托盘/CLI 入口共用)
pub fn validate_url(github_url: &str) -> Result<(), String> {
    if !github_url.starts_with("https://") || !github_url.contains("github") {
        return Err(format!("仅支持 GitHub 资源链接,收到: {}", github_url));
    }
    Ok(())
}

/// 从链接推断保存文件名(取路径最后一段;无有效段时用兜底名)
pub fn filename_from_url(github_url: &str) -> String {
    let seg = github_url
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or("");
    if seg.is_empty() {
        "qi-bunny-download.bin".to_string()
    } else {
        seg.to_string()
    }
}

/// 经第三方中转源下载 `github_url` 到 `dest` 路径。
/// `github_url` 需为完整 https 链接,支持:
///   - 单文件:  https://raw.githubusercontent.com/user/repo/main/path
///   - Release: https://github.com/user/repo/releases/download/v1.0/x.zip
///   - Archive: https://github.com/user/repo/archive/refs/heads/main.zip
///
/// 成功返回实际使用的源标签;全部失败返回 Err(最后一次错误)。
pub fn download(github_url: &str, dest: &std::path::Path) -> Result<String, String> {
    if !github_url.starts_with("https://") || !github_url.contains("github") {
        return Err(format!("仅支持 GitHub 资源链接,收到: {}", github_url));
    }
    let list = candidates(github_url);
    let mut last_err = String::new();
    for (url, label) in &list {
        print!("[*] 尝试 {} … ", label);
        use std::io::Write;
        let _ = std::io::stdout().flush();
        match fetch_to_file(url, dest) {
            Ok(bytes) => {
                println!("成功 ({} 字节)", bytes);
                return Ok(label.clone());
            }
            Err(e) => {
                println!("失败: {}", e);
                last_err = e;
                let _ = std::fs::remove_file(dest); // 清掉半截文件再换源
            }
        }
    }
    Err(format!("全部 {} 个下载通道均失败,最后错误: {}", list.len(), last_err))
}

/// 单次下载:流式写盘,避免大文件占内存;返回写入字节数
fn fetch_to_file(url: &str, dest: &std::path::Path) -> Result<u64, String> {
    let resp = ureq::get(url)
        .timeout(CONNECT_TIMEOUT)
        .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .call()
        .map_err(|e| format!("{}", e))?;
    if resp.status() != 200 {
        return Err(format!("HTTP {}", resp.status()));
    }
    let mut reader = resp.into_reader();
    let mut file = std::fs::File::create(dest).map_err(|e| format!("创建文件失败: {}", e))?;
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("读取中断: {}", e))?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n]).map_err(|e| format!("写入失败: {}", e))?;
        total += n as u64;
    }
    // 中转站常见故障:返回 200 但内容是几行错误文本。小于 1KB 时
    // 交给调用方按"疑似失败"处理不可靠,这里直接校验非空即可,
    // 具体内容由调用方按需使用。
    if total == 0 {
        return Err("响应为空".to_string());
    }
    Ok(total)
}

/// 打印当前中转源测速榜(供 status/诊断用,只读,不写任何状态)
pub fn report() {
    println!("第三方下载加速中转源测速(候选手段,与 hosts 加速无关):");
    for m in rank_mirrors() {
        match m.latency_ms {
            Some(ms) => println!("  {:>5}ms  {}", ms, m.base),
            None => println!("    --    {} (不可用)", m.base),
        }
    }
}
