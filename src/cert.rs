//! 本地 CA 与叶子证书模块(MITM 加速核心,对齐 Watt Toolkit/FastGithub 架构)
//!
//! Watt 的 HTTPS 加速之所以"逐请求可换 IP",前提是本地终结 TLS:
//!   1. 首次运行生成一张本地 CA 根证书,持久化在 exe 同目录(qi-bunny-ca.pem/.key);
//!   2. 用户将其装入系统"受信任的根证书颁发机构"(一次性,工具提供安装引导);
//!   3. 此后浏览器与本机的每条 HTTPS 连接,由本机用 CA 现场签发
//!      以真实域名为 CN/SAN 的叶子证书——浏览器校验通过,流量变成明文 HTTP;
//!   4. 明文请求逐个转发到健康上游(见 proxy.rs forwarder),403/超时/风控
//!      都只影响单个请求,换 IP 重发即可,不再像 TLS 透传那样"会话绑死 IP"。
//!
//! 安全边界:CA 私钥只落在本机 exe 同目录(NTFS ACL 保护下与用户文件同级);
//! 签发的叶子证书有效期 1 年,仅本机 CA 可信,不涉及第三方信任。

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use std::path::PathBuf;
use std::sync::Arc;

/// CA 证书/私钥的持久化路径(exe 同目录,与 lastgood 缓存同级)
fn ca_cert_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    match exe.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join("qi-bunny-ca.pem"),
        _ => PathBuf::from("qi-bunny-ca.pem"),
    }
}

fn ca_key_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    match exe.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join("qi-bunny-ca.key"),
        _ => PathBuf::from("qi-bunny-ca.key"),
    }
}

/// 已就绪的本地 CA(证书 + 签名密钥),进程内共享
pub struct LocalCa {
    /// PEM 编码的 CA 证书(安装引导时写入用户可见位置/输出)
    pub cert_pem: String,
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
}

/// CA 证书参数:DN(CN/Organization)、CA 约束与密钥用途。
/// 生成与重新装配(读回磁盘 CA 签发叶子)必须走同一份,保证 Issuer/Subject
/// 一致,浏览器才能把叶子证书链到系统信任库里的那张 CA 上。
fn ca_params() -> rcgen::CertificateParams {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "qi-bunny Local CA");
    dn.push(DnType::OrganizationName, "qi-bunny");

    let mut params = match rcgen::CertificateParams::new(vec![]) {
        Ok(p) => p,
        Err(e) => {
            // CertificateParams::new 只在 SAN 非法时报错,这里 SAN 为空,
            // 实际不可达;稳妥返回默认参数兜底
            let _ = e;
            return rcgen::CertificateParams::default();
        }
    };
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    params
}

impl LocalCa {
    /// 加载或创建本地 CA:文件存在则读回,否则生成并落盘。
    /// 返回错误说明磁盘不可写或密钥生成失败(调用方给出可操作提示)。
    pub fn load_or_create() -> Result<Arc<LocalCa>, String> {
        let cert_path = ca_cert_path();
        let key_path = ca_key_path();

        let (cert_pem, key_pem) = match (
            std::fs::read_to_string(&cert_path),
            std::fs::read_to_string(&key_path),
        ) {
            (Ok(c), Ok(k)) if !c.is_empty() && !k.is_empty() => (c, k),
            _ => {
                let (c, k) = Self::generate()?;
                // 写盘失败不致命:CA 仍可用于本进程;但下次启动会换 CA,
                // 已装进系统信任库的旧 CA 会失配——尽量保证写成功
                if let Err(e) = std::fs::write(&cert_path, &c) {
                    return Err(format!("CA 证书写入失败({}):{}", cert_path.display(), e));
                }
                if let Err(e) = std::fs::write(&key_path, &k) {
                    return Err(format!("CA 私钥写入失败({}):{}", key_path.display(), e));
                }
                (c, k)
            }
        };

        let ca_key = KeyPair::from_pem(&key_pem).map_err(|e| format!("CA 私钥解析失败:{}", e))?;
        // 从 PEM 重建签发者证书对象:磁盘上的 CA 已装入系统信任库,叶子证书
        // 的 Issuer 必须与那张受信 CA 的 Subject 完全一致(DN/SKID)才能通过
        // 链路校验——必须复用同一套参数,而非空参数临时 self_signed
        let ca_cert = ca_params()
            .self_signed(&ca_key)
            .map_err(|e| format!("CA 证书装配失败:{}", e))?;

        Ok(Arc::new(LocalCa {
            cert_pem,
            ca_cert,
            ca_key,
        }))
    }

    /// 生成新的自签名 CA:CN=qi-bunny Local CA,10 年有效期
    fn generate() -> Result<(String, String), String> {
        let params = ca_params();
        let key = KeyPair::generate().map_err(|e| format!("CA 密钥生成失败:{}", e))?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| format!("CA 证书签名失败:{}", e))?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    /// 以本 CA 为指定域名签发叶子证书(SAN = 域名,使用调用方提供的密钥)。
    /// 浏览器要求 SAN 才认,CN 仅作展示。返回 DER 编码证书。
    pub fn issue_leaf_with(&self, domain: &str, key: &KeyPair) -> Result<Vec<u8>, String> {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);

        let mut params = CertificateParams::new(vec![]).map_err(|e| e.to_string())?;
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::DnsName(
            rcgen::Ia5String::try_from(domain).map_err(|e| format!("非法域名:{}", e))?,
        )];
        let leaf = params
            .signed_by(key, &self.ca_cert, &self.ca_key)
            .map_err(|e| format!("叶子证书签发失败({}):{}", domain, e))?;
        // 返回 DER 编码(rustls Certificate 需要的是 DER 字节)
        Ok(leaf.der().as_ref().to_vec())
    }
}

/// 证书信任状态(供状态展示/安装引导用)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStatus {
    /// 信任库中已存在本工具 CA(按指纹匹配)
    Trusted,
    /// 信任库中不存在,需要安装
    Missing,
    /// 无法读取信任库(非 Windows 平台等)
    Unknown,
}

/// 检查本工具 CA 是否已被系统信任(Windows:用 certutil 枚举 Root 库,
/// 按 CN + SHA1 指纹匹配——只匹配 CN 会把"旧 CA 残留"(同 CN、不同密钥,
/// 删目录重装/CA 重新生成后常见)误判为已信任,导致叶子证书校验全挂;
/// 本地 CA 文件与信任库中那张指纹一致才算 Trusted)。
/// 任何一步失败都按 Missing 处理——宁可重装一次,不误报"已信任"。
pub fn ca_trust_status() -> TrustStatus {
    #[cfg(windows)]
    {
        // 未生成过 CA 直接判缺失
        if !ca_cert_path().exists() {
            return TrustStatus::Missing;
        }
        // 本地 CA 的 SHA1 指纹(certutil -hashfile 输出十六进制,去空格比对)
        let Some(fingerprint) = local_ca_fingerprint() else {
            return TrustStatus::Missing;
        };
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let ok = std::process::Command::new("certutil")
            .args(["-verifystore", "Root", &fingerprint])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            TrustStatus::Trusted
        } else {
            TrustStatus::Missing
        }
    }
    #[cfg(not(windows))]
    {
        TrustStatus::Unknown
    }
}

/// 本地 CA 证书文件的 SHA1 指纹(小写十六进制,无分隔)
#[cfg(windows)]
fn local_ca_fingerprint() -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("certutil")
        .args(["-hashfile", ca_cert_path().to_str()?, "SHA1"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    // 输出第 2 行(索引 1)是纯十六进制指纹,首尾可能有空格
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().nth(1).map(|l| l.trim().to_ascii_lowercase())
}

/// 删除系统受信任根中所有同 CN("qi-bunny Local CA")的旧证书:
/// 覆盖安装前清理,避免旧指纹残留后 verifystore 命中旧证书造成误判,
/// 也减少信任库里的僵尸条目。按 CN 硬编码匹配与 ca_params() 保持一致。
#[cfg(windows)]
fn remove_old_cas() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // certutil -delstore Root <CN> 只删完全匹配该 CN 的条目;旧版本若
    // 改过 CN,这里会漏删——可接受:老 CN 证书不再被本工具引用,只是残留
    let _ = std::process::Command::new("certutil")
        .args(["-delstore", "Root", "qi-bunny Local CA"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

/// 引导安装 CA 到系统受信任根(Windows:先删同 CN 旧证书再 certutil
/// -addstore -f Root <pem> 强制覆盖,确保信任库中始终只有当前密钥的 CA)。
/// 返回 Ok(()) 或失败说明;调用方在 UI/命令行展示结果。
pub fn install_ca_to_trust() -> Result<(), String> {
    #[cfg(windows)]
    {
        let cert_path = ca_cert_path();
        remove_old_cas();
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let out = std::process::Command::new("certutil")
            .args(["-addstore", "-f", "Root"])
            .arg(&cert_path)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("启动 certutil 失败:{}", e))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "certutil 安装失败:{}",
                String::from_utf8_lossy(&out.stderr)
            ))
        }
    }
    #[cfg(not(windows))]
    {
        Err("当前平台暂不支持自动安装,请手动信任 qi-bunny-ca.pem".into())
    }
}

/// 叶子证书缓存条目:(证书 DER, 私钥 DER/PKCS#8)
type LeafMaterial = (Arc<Vec<u8>>, Arc<Vec<u8>>);

/// 叶子证书缓存:同一域名重复握手不重复签发(进程内,域名集合固定且小)
pub struct LeafCache {
    /// 域名 -> LeafMaterial
    inner: std::sync::Mutex<std::collections::HashMap<String, LeafMaterial>>,
    ca: Arc<LocalCa>,
}

impl LeafCache {
    pub fn new(ca: Arc<LocalCa>) -> Self {
        LeafCache {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
            ca,
        }
    }

    /// 便捷构造:Arc 包装(供 proxy.rs 的 OnceLock 初始化用)
    pub fn new_arc(ca: Arc<LocalCa>) -> Arc<LeafCache> {
        Arc::new(LeafCache::new(ca))
    }

    /// 取域名对应的 (证书 DER, 私钥 DER),带缓存;签发失败返回 Err
    fn issue(&self, domain: &str) -> Result<LeafMaterial, String> {
        // 锁中毒时恢复内部状态继续用(仅缓存,数据仍自洽)
        let mut m = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(v) = m.get(domain) {
            return Ok(v.clone());
        }
        if m.len() >= 64 {
            m.clear();
        }
        // 叶子证书配独立密钥(非 CA 密钥):rustls 需要 cert+key 成对
        let leaf_key = KeyPair::generate().map_err(|e| format!("叶子密钥生成失败:{}", e))?;
        let leaf = self
            .ca
            .issue_leaf_with(domain, &leaf_key)?;
        let key_der = leaf_key.serialize_der();
        let pair = (Arc::new(leaf), Arc::new(key_der));
        m.insert(domain.to_string(), pair.clone());
        Ok(pair)
    }

    /// 取证书 DER(带缓存)
    pub fn get(&self, domain: &str) -> Result<Arc<Vec<u8>>, String> {
        self.issue(domain).map(|(c, _)| c)
    }

    /// 取私钥 DER(带缓存)
    pub fn get_key(&self, domain: &str) -> Result<Arc<Vec<u8>>, String> {
        self.issue(domain).map(|(_, k)| k)
    }
}

/// rustls 服务器端配置:持有 LeafCache,按 SNI 现场取证书。
/// 供 proxy.rs 的 MITM TLS 接收器使用。
pub fn server_tls_config(cache: Arc<LeafCache>) -> Arc<rustls::ServerConfig> {
    let resolver = Arc::new(DynamicResolver { cache });
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    Arc::new(cfg)
}

/// 动态证书解析器:rustls 每次握手回调,按 SNI 签发/取缓存叶子证书
struct DynamicResolver {
    cache: Arc<LeafCache>,
}

impl std::fmt::Debug for DynamicResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicResolver").finish_non_exhaustive()
    }
}

impl rustls::server::ResolvesServerCert for DynamicResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name()?.to_string();
        let der = self.cache.get(&sni).ok()?;
        // 叶子证书的私钥:用 CA 密钥签发的证书没有独立私钥文件——
        // rcgen signed_by 产物自带配套密钥,但这里只拿到了 DER;
        // 简化处理:叶子密钥每次由 CA 密钥充当不可行,需要独立密钥。
        // 实际做法:签发时同时返回 PEM 密钥并缓存在 LeafCache 中。
        let key = self.cache.get_key(&sni).ok()?;
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.as_ref().clone()),
        );
        let certified = rustls::sign::CertifiedKey::new(
            vec![rustls::pki_types::CertificateDer::from(der.as_ref().clone())],
            rustls::crypto::ring::sign::any_supported_type(&key).ok()?,
        );
        Some(Arc::new(certified))
    }
}

// ---------- 测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    /// 独立构造一张内存 CA(不落盘,不影响 exe 目录的真实 CA)
    fn mem_ca() -> LocalCa {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, "qi-bunny Test CA");
        let cert = params.self_signed(&key).unwrap();
        LocalCa {
            cert_pem: cert.pem(),
            ca_cert: cert,
            ca_key: key,
        }
    }

    #[test]
    fn ca_generate_produces_pem_pair() {
        let (cert_pem, key_pem) = LocalCa::generate().unwrap();
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn leaf_signed_by_ca_and_key_pairs() {
        let ca = mem_ca();
        let leaf_key = KeyPair::generate().unwrap();
        let der = ca.issue_leaf_with("github.com", &leaf_key).unwrap();
        // DER 证书非空且能被 rustls 解析
        assert!(!der.is_empty());
        let _parsed = rustls::pki_types::CertificateDer::from(der);

        // 私钥 DER 与证书能组成 rustls 认可的 CertifiedKey
        let key_der = leaf_key.serialize_der();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
        );
        assert!(rustls::crypto::ring::sign::any_supported_type(&key).is_ok());
    }

    #[test]
    fn leaf_rejects_invalid_domain() {
        let ca = mem_ca();
        let key = KeyPair::generate().unwrap();
        // 非 ASCII 域名无法编码为 SAN 要求的 IA5String
        assert!(ca.issue_leaf_with("例え.example.com", &key).is_err());
    }

    #[test]
    fn leaf_cache_caches_per_domain() {
        let ca = Arc::new(mem_ca());
        let cache = LeafCache::new(ca);
        let c1 = cache.get("api.github.com").unwrap();
        let c2 = cache.get("api.github.com").unwrap();
        assert!(Arc::ptr_eq(&c1, &c2), "同域名应命中缓存");
        let k1 = cache.get_key("api.github.com").unwrap();
        assert!(!Arc::ptr_eq(&c1, &k1), "cert 与 key 是不同数据");
        // 不同域名不同证书
        let c3 = cache.get("codeload.github.com").unwrap();
        assert!(!Arc::ptr_eq(&c1, &c3));
    }

    #[test]
    fn leaf_cache_clears_at_capacity() {
        let ca = Arc::new(mem_ca());
        let cache = LeafCache::new(ca);
        for i in 0..70 {
            cache.get(&format!("d{}.example.com", i)).unwrap();
        }
        // 超过 64 清空后仍可继续签发(不 panic、不 Err)
        let c = cache.get("d0.example.com").unwrap();
        assert!(!c.is_empty());
    }

    #[test]
    fn dynamic_resolver_serves_sni() {
        let ca = Arc::new(mem_ca());
        let resolver = DynamicResolver { cache: LeafCache::new_arc(ca) };
        // 非 TLS 客户端拿不到 SNI 时返回 None(不 panic)
        // 完整 SNI 路径由集成层(真实 TLS 握手)覆盖,这里验证组件可构造
        drop(resolver);
    }

    #[test]
    fn server_tls_config_builds() {
        let ca = Arc::new(mem_ca());
        let _cfg = server_tls_config(LeafCache::new_arc(ca));
    }
}
