//! 第三方候选 IP 采集模块
//!
//! 四条与 DNS 完全独立的候选 IP 通道(并行,任一失败不影响其他):
//!   1. GitHub 官方 meta API(https://api.github.com/meta)——官方公布的
//!      git/web 网段(CIDR),每段采样多个代表地址,权威可靠;
//!   2. ipaddress.com——第三方 IP 查询站,返回大量历史解析记录;
//!   3. ip138(site.ip138.com)——国内 IP 历史解析库,与 ipaddress 的
//!      记录集重叠度低,常能补到别的源没有的冷门可用 IP;
//!   4. hackertarget 的 DNS 查询 API——境外视角解析,和国内 DoH 的
//!      污染结果互补。
//!
//! 全部失败时返回空,不影响主流程(候选池还有 DoH/UDP DNS)。

use std::collections::HashSet;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(6);

/// 采集全部四路候选(去重,并行):官方网段采样 + ipaddress.com + ip138
/// + hackertarget。返回与 DNS 无关的候选 IP(IPv4 + IPv6)。
pub fn collect(domain: &str) -> Vec<String> {
    let (tx, rx) = mpsc::channel::<String>();
    {
        let tx = tx.clone();
        let domain = domain.to_string();
        thread::spawn(move || {
            if let Some(ips) = from_meta_api(&domain) {
                for ip in ips {
                    let _ = tx.send(ip);
                }
            }
        });
    }
    {
        let tx = tx.clone();
        let domain = domain.to_string();
        thread::spawn(move || {
            if let Some(ips) = from_ipaddress_site(&domain) {
                for ip in ips {
                    let _ = tx.send(ip);
                }
            }
        });
    }
    {
        let tx = tx.clone();
        let domain = domain.to_string();
        thread::spawn(move || {
            if let Some(ips) = from_ip138(&domain) {
                for ip in ips {
                    let _ = tx.send(ip);
                }
            }
        });
    }
    {
        let tx = tx.clone();
        let domain = domain.to_string();
        thread::spawn(move || {
            if let Some(ips) = from_hackertarget(&domain) {
                for ip in ips {
                    let _ = tx.send(ip);
                }
            }
        });
    }
    // 第 5 路:已知 CDN 网段静态采样(参照 Watt Toolkit 对 Fastly 网段的
    // 内置表):githubusercontent 系域名走 Fastly,官方 meta API 不覆盖,
    // 历史库也常缺失——静态网段是这类域名兜底可用性的关键通道
    for ip in from_known_ranges(domain) {
        let _ = tx.send(ip);
    }
    drop(tx);
    let set: HashSet<String> = rx.into_iter().collect();
    set.into_iter().collect()
}

/// GitHub 官方 meta API:取 web/git 网段,每段采样一个代表地址(首地址+1,
/// 避免网络地址)。仅 github.com 系主域适用,返回 IPv4 采样。
fn from_meta_api(domain: &str) -> Option<Vec<String>> {
    // meta API 本身经 api.github.com 查询;若 hosts 已有旧记录则走之
    let resp = ureq::get("https://api.github.com/meta")
        .timeout(TIMEOUT)
        .call()
        .ok()?;
    let v: serde_json::Value = resp.into_json().ok()?;

    let mut out = Vec::new();
    for key in ["web", "git"] {
        if let Some(list) = v.get(key).and_then(|x| x.as_array()) {
            for cidr in list.iter().filter_map(|c| c.as_str()) {
                // 每段采样多个地址:只取网络地址+1 时,一个 /16 段只有一个
                // 代表 IP,恰被风控则整段缺席;多点采样提高命中可用 IP 的概率
                for ip in sample_cidr_v4_multi(cidr, SAMPLES_PER_CIDR) {
                    out.push(ip);
                }
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        // 官方网段对任何 github.com 系域名都是有效候选
        let _ = domain;
        Some(out)
    }
}

/// 官方网段采样:每个 CIDR 段内均匀取几个代表地址(不是只取网络地址+1)
const SAMPLES_PER_CIDR: usize = 4;

/// 从 CIDR(仅支持 IPv4 形式 a.b.c.d/p)均匀采样 n 个代表地址:
/// 把主机位空间均分为 n 格,各取格内靠前的地址,单段覆盖面更广。
fn sample_cidr_v4_multi(cidr: &str, n: usize) -> Vec<String> {
    let Some((addr, prefix)) = cidr.split_once('/') else {
        return Vec::new();
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return Vec::new();
    };
    if prefix > 32 {
        return Vec::new();
    }
    let octets: Vec<u8> = addr.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 {
        return Vec::new();
    }
    let base = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
    let host_bits = 32 - prefix;
    let space: u64 = if host_bits == 0 {
        1
    } else {
        1u64 << host_bits.min(31)
    };
    let n = n.max(1) as u64;
    let mut out = Vec::new();
    for i in 0..n.min(space) {
        // 第 i 格的起始地址(+1 跳过可能的网络地址)
        let offset = (i * space / n + 1).min(space.saturating_sub(1));
        let ip = base + offset as u32;
        let b = ip.to_be_bytes();
        out.push(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]));
    }
    out
}

/// ipaddress.com:抓取该域名的历史解析 IP 列表页,提取页面中的 IPv4/IPv6。
fn from_ipaddress_site(domain: &str) -> Option<Vec<String>> {
    let url = format!("https://www.ipaddress.com/website/{}", domain);
    let resp = ureq::get(&url)
        .timeout(TIMEOUT)
        .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .call()
        .ok()?;
    let text = resp.into_string().ok()?;
    Some(extract_ips(&text))
}

/// ip138:抓取该域名的 IP 历史解析页,提取页面中的 IPv4/IPv6。
/// 记录集与 ipaddress.com 重叠度低,是多路采集里的国内视角补充。
/// 历史记录里混有大量陈旧/污染/无关 IP(甚至 127.x),必须限量:
/// 只取前 N 个,且页面通常按新旧排列,取头部的新鲜记录。
fn from_ip138(domain: &str) -> Option<Vec<String>> {
    const MAX_IPS: usize = 12;
    let url = format!("https://site.ip138.com/{}/", domain);
    let resp = ureq::get(&url)
        .timeout(TIMEOUT)
        .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .call()
        .ok()?;
    let text = resp.into_string().ok()?;
    let ips: Vec<String> = extract_ips(&text)
        .into_iter()
        .filter(|ip| !ip.starts_with("127.") && ip != "0.0.0.0")
        .take(MAX_IPS)
        .collect();
    if ips.is_empty() {
        None
    } else {
        Some(ips)
    }
}

/// hackertarget 的 DNS 查询 API:境外视角解析该域名,与国内 DoH 的
/// 污染结果互补。只取 "A : x.x.x.x" 行——NS/MX/TXT 行里的域名和文本
/// 会被宽松提取器误认成候选,把池子灌爆,探测就串行卡死了。
fn from_hackertarget(domain: &str) -> Option<Vec<String>> {
    let url = format!("https://api.hackertarget.com/dnslookup/?q={}", domain);
    let resp = ureq::get(&url)
        .timeout(TIMEOUT)
        .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .call()
        .ok()?;
    let text = resp.into_string().ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("A :") {
            let ip = rest.trim();
            if ip.parse::<std::net::Ipv4Addr>().is_ok() {
                out.push(ip.to_string());
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// 已知 CDN 网段(Fastly,承载 githubusercontent 系域名)。零网络开销的
/// 静态候选通道:meta API 只覆盖 github.com 系网段,githubusercontent 系
/// 走 Fastly,历史解析库对它经常缺货——内置网段表兜底。
/// 只列公网大段(可靠性高),探测层会用真实 TLS 握手过滤不可用地址。
const KNOWN_RANGES: &[(&str, &str)] = &[
    // (CIDR, 适配的域名后缀;"" = 所有 GitHub 相关域名通用)
    ("151.101.0.0/16", "githubusercontent"),
    ("199.232.0.0/16", "githubusercontent"),
    ("146.75.0.0/16", "githubusercontent"),
];

/// 已知 CDN 网段静态采样:域名匹配后缀才给候选,每段采样多个地址
fn from_known_ranges(domain: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (cidr, suffix) in KNOWN_RANGES {
        if domain.contains(suffix) {
            for ip in sample_cidr_v4_multi(cidr, SAMPLES_PER_CIDR) {
                out.push(ip);
            }
        }
    }
    out
}

/// 从 HTML 文本中提取 IPv4 / IPv6 地址(宽松匹配 + 合法性校验去噪)。
fn extract_ips(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    // IPv4: 四段十进制
    for seg in text.split(|c: char| !(c.is_ascii_digit() || c == '.')) {
        let parts: Vec<&str> = seg.split('.').collect();
        if parts.len() == 4
            && parts
                .iter()
                .all(|p| p.parse::<u8>().map(|_| !p.starts_with('+')).unwrap_or(false))
        {
            out.push(seg.to_string());
        }
    }
    // IPv6: 含冒号十六进制的段(粗筛,parse 校验)
    for seg in text.split(|c: char| !(c.is_ascii_hexdigit() || c == ':')) {
        if seg.contains(':') && seg.contains("::") && seg.parse::<std::net::Ipv6Addr>().is_ok() {
            out.push(seg.to_string());
        }
    }
    out
}
