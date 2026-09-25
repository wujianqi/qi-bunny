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
    // 采集通道清单由 address.rs 的 IP_SOURCES 常量提供(地址集中
    // 管理),按 kind 分派:meta_api 走官方网段接口,url_template 把
    // {domain} 替换为目标域名后请求页面文本提取 IP。enabled=false
    // 或类型未知的通道跳过。
    for src in crate::address::IP_SOURCES.iter().filter(|s| s.enabled).cloned() {
        let tx = tx.clone();
        let domain = domain.to_string();
        thread::spawn(move || {
            let url = src.url.replace("{domain}", &domain);
            let ips = match src.kind {
                "meta_api" => from_meta_api(&url, &domain),
                "url_template" => from_url_template(&url, src.name),
                "hackertarget" => from_hackertarget(&url),
                "hosts_list" => from_hosts_list(&url, &domain),
                _ => None,
            };
            if let Some(ips) = ips {
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
fn from_meta_api(url: &str, _domain: &str) -> Option<Vec<String>> {
    let resp = ureq::get(url)
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
        Some(out)
    }
}

/// url_template 类通道(ipaddress/ip138 等):请求模板 URL(已填域名),
/// 从响应文本提取 IPv4/IPv6,并按源头特性做基础过滤。
fn from_url_template(url: &str, name: &str) -> Option<Vec<String>> {
    let resp = ureq::get(url)
        .timeout(TIMEOUT)
        .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .call()
        .ok()?;
    let text = resp.into_string().ok()?;
    // 历史解析库混有陈旧/污染/无关记录,按源头限量:
    // ip138 类历史页按新旧排列只取头部;其余源头不设限由探测层过滤
    let max = if name == "ip138" { 12 } else { usize::MAX };
    let ips: Vec<String> = extract_ips(&text)
        .into_iter()
        .filter(|ip| !ip.starts_with("127.") && ip != "0.0.0.0")
        .take(max)
        .collect();
    if ips.is_empty() { None } else { Some(ips) }
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

/// hosts_list 类通道(GitHub520 / ittuann 等公共 hosts 库):拉取
/// 「IP 域名」映射列表,筛出目标域名的记录。
/// 支持两种格式:
///   - JSON 数组(GitHub520 hosts.json):[["1.2.3.4","github.com"], …]
///   - hosts 文本(ittuann hosts):"1.2.3.4    github.com" 每行一条
///
/// 公共库更新及时且带测速择优,是历史解析库之外的高质量补充。
fn from_hosts_list(url: &str, domain: &str) -> Option<Vec<String>> {
    let resp = ureq::get(url)
        .timeout(TIMEOUT)
        .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        .call()
        .ok()?;
    // hosts 库是 github.com 系专用,主域与库中记录按后缀匹配
    // (github.com 同时命中 codeload.github.com 等子域记录)
    let d = domain.to_ascii_lowercase();
    let mut out = Vec::new();
    let ctype = resp.content_type().to_string();
    if ctype.contains("json") {
        let v: serde_json::Value = resp.into_json().ok()?;
        if let Some(arr) = v.as_array() {
            for item in arr {
                if let Some(pair) = item.as_array() {
                    let ip = pair.first().and_then(|x| x.as_str()).unwrap_or("");
                    let host = pair.get(1).and_then(|x| x.as_str()).unwrap_or("");
                    if host == d || host.ends_with(&format!(".{}", d)) {
                        out.push(ip.to_string());
                    }
                }
            }
        }
    } else {
        let text = resp.into_string().ok()?;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let mut it = line.split_whitespace();
            if let (Some(ip), Some(host)) = (it.next(), it.next()) {
                let host = host.to_ascii_lowercase();
                if host == d || host.ends_with(&format!(".{}", d)) {
                    out.push(ip.to_string());
                }
            }
        }
    }
    out.retain(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok());
    if out.is_empty() { None } else { Some(out) }
}

/// hackertarget 的 DNS 查询 API:境外视角解析该域名,与国内 DoH 的
/// 污染结果互补。只取 "A : x.x.x.x" 行——NS/MX/TXT 行里的域名和文本
/// 会被宽松提取器误认成候选,把池子灌爆,探测就串行卡死了。
fn from_hackertarget(url: &str) -> Option<Vec<String>> {
    let resp = ureq::get(url)
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

// ---- 链接辅助函数(原 source.rs,与地址常量 address.rs 分离)----

/// 从一段自由文本(剪贴板内容等)提取可下载的 GitHub 链接。
/// 兼容常见粘贴形态:
///   - 纯链接:            https://github.com/u/r/releases/download/v1/x.zip
///   - git clone 前缀:     git clone https://github.com/u/r.git
///   - 中文冒号/引号包裹:  链接:「https://github.com/u/r」
///   - wget/curl 命令:     wget https://github.com/u/r/archive/main.zip
///
/// 返回第一个匹配的 https GitHub 链接;找不到返回 None。
pub fn extract_github_url(text: &str) -> Option<String> {
    // github.com / raw.githubusercontent.com / gist / codeload 等官方域
    const GITHUB_HOSTS: &[&str] = &[
        "https://github.com/",
        "https://raw.githubusercontent.com/",
        "https://gist.github.com/",
        "https://codeload.github.com/",
        "https://objects.githubusercontent.com/",
    ];
    let text = text.trim();
    for host in GITHUB_HOSTS {
        let mut from = 0;
        while let Some(pos) = text[from..].find(host) {
            let start = from + pos;
            // 链接终止于空白或中文/英文引号等包裹符
            let rest = &text[start..];
            let end = rest
                .find(|c: char| {
                    c.is_whitespace() || matches!(c, '"' | '\'' | '」' | '》' | ')')
                })
                .unwrap_or(rest.len());
            let url = rest[..end].trim_end_matches(['.', ',', '、']);
            if url.len() > host.len() {
                return Some(url.to_string());
            }
            from = start + host.len();
        }
    }
    None
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
