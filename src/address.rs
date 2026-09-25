//! 源头地址常量(单一文件,内嵌常量,无需外部配置文件)
//!
//! 两类源头地址集中在此,增删直接改下面的常量表即可:
//!   - IP_SOURCES:     IP 源头(候选 IP 采集通道,DNS 解析之外的独立通道)
//!   - MIRROR_SOURCES: 加速源头(第三方 gh-proxy 类下载中转站)
//!
//! URL 中 {domain} 为待解析域名占位符,由采集层(sources.rs)替换。

/// 一条 IP 源头(候选 IP 采集通道)
#[derive(Clone, Debug)]
pub struct IpSource {
    pub name: &'static str,
    /// meta_api = GitHub 官方网段接口(忽略域名参数,全网段采样);
    /// url_template = 把 {domain} 替换为目标域名后请求,从响应文本提取 IP;
    /// hackertarget = DNS lookup API,只取 "A :" 记录行
    pub kind: &'static str,
    pub url: &'static str,
    pub enabled: bool,
}

/// IP 源头:4 条与 DNS 完全独立的候选 IP 采集通道
/// (enabled=false 可临时停用某通道)
pub const IP_SOURCES: &[IpSource] = &[
    IpSource {
        name: "github-meta-api",
        kind: "meta_api",
        url: "https://api.github.com/meta",
        enabled: true,
    },
    IpSource {
        name: "ipaddress",
        kind: "url_template",
        url: "https://www.ipaddress.com/website/{domain}",
        enabled: true,
    },
    IpSource {
        name: "ip138",
        kind: "url_template",
        url: "https://site.ip138.com/{domain}/",
        enabled: true,
    },
    IpSource {
        name: "hackertarget",
        kind: "hackertarget",
        url: "https://api.hackertarget.com/dnslookup/?q={domain}",
        enabled: true,
    },
    IpSource {
        name: "github520",
        kind: "hosts_list",
        url: "https://raw.hellogithub.com/hosts.json",
        enabled: true,
    },
    IpSource {
        name: "ittuann-hosts",
        kind: "hosts_list",
        url: "https://cdn.jsdelivr.net/gh/ittuann/GitHub-IP-hosts@main/hosts",
        enabled: true,
    },
];

pub const MIRROR_SOURCES: &[&str] = &[
    "https://gh-proxy.com",
    "https://ghfast.top",
    "https://ghproxy.net",
    "https://gh.monlor.com",
    "https://github.geekery.cn",
    "https://ghfile.geekertao.top",
    "https://gh.927223.xyz",
    "https://git.tangbai.cc",
    "https://ghp.keleyaa.com",
    "https://gh.nxnow.top",
    "https://gh.chjina.com",
    "https://fastgit.cc",
    "https://gh.ddlc.top",
    "https://g.blfrp.cn",
    "https://ghproxy.monkeyray.net",
    "https://gh.dpik.top",
    "https://githubproxy.cc",
    "https://aifasthub.com",
    "https://github.chenc.dev",
    "https://ghm.078465.xyz",
    "https://ghproxy.imciel.com",
    "https://gitproxy.mrhjx.cn",
    "https://gh.noki.icu",
    "https://github.ednovas.xyz",
    "https://tvv.tw",
    "https://ghpxy.hwinzniej.top",
    "https://gh.catmak.name",
    "https://gh.b52m.cn",
    "https://git.yylx.win",
    "https://github.xxlab.tech",
    "https://ghproxy.cxkpro.top",
    "https://git.669966.xyz",
    "https://github.dpik.top",
    "https://ghproxy.org",
    "https://ghproxy.link",
    "https://gh.idayer.com",
    "https://gh.zwy.one",
    "https://wget.la",
    "https://cdn.crashmc.com",
];
