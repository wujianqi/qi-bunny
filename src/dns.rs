//! DNS 解析模块
//!
//! 面向"IP 被针对性阻断"的网络环境,单一 DNS 源返回的 IP 可能不可用,因此:
//!   - 全部 DoH 端点 + UDP 53 明文 DNS 并行查询(DoH 全挂时兜底)
//!   - 同时采集 A(IPv4)与 AAAA(IPv6)记录,扩充候选池
//!
//! 所有候选交由 probe.rs 做真实连通性测速后择优。

use serde_json::Value;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// DoH 端点(DNSPod/Ali/360/Google,加密 DNS):多源并行,单一源返回的
/// 污染/陈旧 IP 会被其他源的可信记录稀释,探测层再兜底过滤
const DOH_ENDPOINTS: &[&str] = &[
    "https://1.12.12.12/resolve",      // DNSPod DoH
    "https://doh.pub/resolve",         // DNSPod DoH
    "https://120.53.53.53/resolve",    // DNSPod DoH 3
    "https://223.5.5.5/resolve",       // Ali DoH
    "https://223.6.6.6/resolve",       // Ali DoH 2
    "https://dns.alidns.com/resolve",  // Ali DoH 域名形式
    "https://doh.360.cn/resolve",      // 360 DoH
];

/// UDP 53 公共 DNS(DNSPod/Ali/114,DoH 全挂时仍可解析)
const UDP_DNS: &[&str] = &["119.29.29.29", "223.5.5.5", "114.114.114.114"];

const TIMEOUT: Duration = Duration::from_secs(4);

/// DNS 记录类型: 1=A(IPv4) 28=AAAA(IPv6)
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

/// 向全部 DoH 端点 + UDP DNS 并行查询,收集该域名所有 A/AAAA 候选 IP(去重)。
pub fn candidates(domain: &str) -> Vec<String> {
    let (tx, rx) = mpsc::channel::<String>();
    for ep in DOH_ENDPOINTS {
        for qtype in [TYPE_A, TYPE_AAAA] {
            let tx = tx.clone();
            let domain = domain.to_string();
            let ep = ep.to_string();
            thread::spawn(move || {
                let url = format!("{}?name={}&type={}", ep, domain, qtype_name(qtype));
                if let Ok(resp) = ureq::get(&url).timeout(TIMEOUT).call() {
                    if let Ok(text) = resp.into_string() {
                        if let Some(ips) = parse_doh_records(&text, qtype) {
                            for ip in ips {
                                let _ = tx.send(ip);
                            }
                        }
                    }
                }
            });
        }
    }
    for server in UDP_DNS {
        for qtype in [TYPE_A, TYPE_AAAA] {
            let tx = tx.clone();
            let domain = domain.to_string();
            let server = server.to_string();
            thread::spawn(move || {
                if let Some(ips) = udp_dns_query(&server, &domain, qtype) {
                    for ip in ips {
                        let _ = tx.send(ip);
                    }
                }
            });
        }
    }
    drop(tx); // 全部发送端结束后 for 循环自然结束(即所有查询完成)
    let set: HashSet<String> = rx.into_iter().collect();
    set.into_iter().collect()
}

/// DoH URL 中的类型名
fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        TYPE_AAAA => "AAAA",
        _ => "A",
    }
}

/// 从 DoH JSON 应答(RFC8484 JSON)中提取指定类型的记录。
/// A 记录 data 为点分 IPv4;AAAA 记录 data 为 IPv6 文本,统一归一为规范字符串。
fn parse_doh_records(json: &str, qtype: u16) -> Option<Vec<String>> {
    let v: Value = serde_json::from_str(json).ok()?;
    let answers = v.get("Answer")?.as_array()?;
    Some(
        answers
            .iter()
            .filter(|a| a.get("type").and_then(|t| t.as_u64()) == Some(qtype as u64))
            .filter_map(|a| a.get("data").and_then(|d| d.as_str()))
            .filter_map(|s| normalize(s.trim(), qtype))
            .collect(),
    )
}

/// 归一化 rdata 文本为规范 IP 字符串(校验合法性;IPv6 展开为规范形式)
fn normalize(data: &str, qtype: u16) -> Option<String> {
    match qtype {
        TYPE_AAAA => data.parse::<Ipv6Addr>().ok().map(|v| v.to_string()),
        _ => {
            // A 记录:校验为合法 IPv4
            let parts: Vec<&str> = data.split('.').collect();
            if parts.len() == 4
                && parts.iter().all(|p| {
                    p.parse::<u8>().map(|_| !p.starts_with('+')).unwrap_or(false)
                })
            {
                Some(data.to_string())
            } else {
                None
            }
        }
    }
}

/// 向指定 UDP DNS 服务器发起查询,返回全部指定类型记录。
/// 手写极简 DNS 报文(单查询、无 EDNS),失败返回 None。
fn udp_dns_query(server: &str, domain: &str, qtype: u16) -> Option<Vec<String>> {
    use std::net::UdpSocket;

    // 编码问题域名为 DNS 标签序列
    let mut qname = Vec::with_capacity(domain.len() + 2);
    for label in domain.split('.') {
        qname.push(label.len() as u8);
        qname.extend_from_slice(label.as_bytes());
    }
    qname.push(0);

    // 报文: 头部(随机 ID, RD=1, QD=1) + 问题
    let id: u16 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .subsec_nanos()) as u16;
    let mut pkt = Vec::with_capacity(12 + qname.len() + 4);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    pkt.extend_from_slice(&qname);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(TIMEOUT)).ok()?;
    sock.set_write_timeout(Some(TIMEOUT)).ok()?;
    sock.send_to(&pkt, (server, 53)).ok()?;

    let mut buf = [0u8; 2048];
    let n = sock.recv_from(&mut buf).ok()?.0;
    parse_dns_response(&buf[..n], qtype)
}

/// 解析 DNS 应答报文中指定类型的记录(支持响应内压缩名跳过)。
fn parse_dns_response(pkt: &[u8], qtype: u16) -> Option<Vec<String>> {
    if pkt.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    // 跳过问题区(qdcount 个 Question)
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(pkt, pos)?;
        pos += 4; // QTYPE + QCLASS
    }

    // 逐条读 Answer,记录目标类型的 rdata
    let mut ips = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(pkt, pos)?;
        if pos + 10 > pkt.len() {
            break;
        }
        let rtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let rdlen = u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > pkt.len() {
            break;
        }
        let rdata = &pkt[pos..pos + rdlen];
        match (rtype, rdlen) {
            (TYPE_A, 4) if qtype == TYPE_A => {
                ips.push(format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]));
            }
            (TYPE_AAAA, 16) if qtype == TYPE_AAAA => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                ips.push(Ipv6Addr::from(octets).to_string());
            }
            _ => {}
        }
        pos += rdlen;
    }
    if ips.is_empty() {
        None
    } else {
        Some(ips)
    }
}

/// 跳过(可能压缩指向的)域名字段,返回其后位置。
fn skip_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= pkt.len() {
            return None;
        }
        let len = pkt[pos];
        if len & 0xC0 == 0xC0 {
            // 压缩指针,2 字节即结束
            return Some(pos + 2);
        }
        pos += 1;
        if len == 0 {
            return Some(pos);
        }
        pos += len as usize;
    }
}
