//! hosts 文件操作模块
//!
//! 带注释标记的托管区块读写:标记块(begin/end 注释行)内为本工具写入的
//! 内容,启动时清理残留,退出时恢复原样;块外用户内容不受影响。
//!
//! 标记块读写已泛化为 `read_marked_block` / `write_marked_block`,
//! 供 hosts 与 ssh config 两处复用(ssh 模式见 ssh.rs)。

use std::fs;
use std::io;
use std::path::PathBuf;

/// 当前版本标记块(qi-bunny)
pub const MARKER_BEGIN: &str = "# qi-bunny begin";
pub const MARKER_END: &str = "# qi-bunny end";

/// 旧版(github-proxy)标记块:clean 时兼容清理历史残留
pub const LEGACY_BEGIN: &str = "# github-proxy begin";
pub const LEGACY_END: &str = "# github-proxy end";

pub fn hosts_path() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

fn read_file(path: &PathBuf) -> io::Result<String> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()), // 文件尚不存在(如首次写 ~/.ssh/config)
        Err(e) => Err(e), // 读取失败绝不能当空文件处理,否则会误清用户内容
    }
}

/// 原子写入:先写同目录临时文件再改名覆盖,避免写入中途崩溃/断电截断原文件;
/// 改名失败(个别文件系统/杀软拦截)回退为直接覆盖。
fn write_atomic(path: &PathBuf, content: &str) -> io::Result<()> {
    let tmp = path.with_extension("qibunny-tmp");
    match fs::write(&tmp, content).and_then(|()| fs::rename(&tmp, path)) {
        Ok(()) => Ok(()),
        Err(_) => {
            let _ = fs::remove_file(&tmp);
            fs::write(path, content)
        }
    }
}

/// 去掉内容中指定标记块(begin/end 两行为完整行匹配)。
/// 使用 split_inclusive 保留块外原文字节(含换行风格),不改动用户原有内容。
pub fn strip_block(content: &str, begin: &str, end: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut in_block = false;
    for line in content.split_inclusive('\n') {
        let t = line.trim();
        if t == begin {
            in_block = true;
            continue;
        }
        if t == end {
            in_block = false;
            continue;
        }
        if !in_block {
            out.push_str(line);
        }
    }
    out
}

/// 读取文件中指定标记块内的内容(不含标记行);无块返回 None。
#[allow(dead_code)]
pub fn read_marked_block(path: &PathBuf, begin: &str, end: &str) -> Option<String> {
    let content = read_file(path).ok()?;
    if !content.contains(begin) {
        return None;
    }
    let mut out = String::new();
    let mut in_block = false;
    for line in content.split_inclusive('\n') {
        let t = line.trim();
        if t == begin {
            in_block = true;
            continue;
        }
        if t == end {
            break;
        }
        if in_block {
            out.push_str(line);
        }
    }
    Some(out)
}

/// 用新内容替换文件中的标记块(无块则追加到文件尾部)。
pub fn write_marked_block(path: &PathBuf, begin: &str, end: &str, body: &str) -> io::Result<()> {
    let content = read_file(path)?;
    let mut new = strip_block(&content, begin, end);
    if !new.is_empty() && !new.ends_with('\n') {
        new.push('\n');
    }
    new.push_str(begin);
    new.push('\n');
    new.push_str(body);
    if !body.is_empty() && !body.ends_with('\n') {
        new.push('\n');
    }
    new.push_str(end);
    new.push('\n');
    write_atomic(path, &new)
}

/// 移除文件中的标记块;返回是否发生了改动。
pub fn remove_marked_block(path: &PathBuf, begin: &str, end: &str) -> bool {
    let content = match read_file(path) {
        Ok(c) => c,
        Err(e) => {
            crate::logerr!("[!] 读取文件失败(不改动): {}", e);
            return false;
        }
    };
    if !content.contains(begin) {
        return false;
    }
    match write_atomic(path, &strip_block(&content, begin, end)) {
        Ok(()) => true,
        Err(e) => {
            crate::logerr!("[!] 移除标记块失败: {}", e);
            false
        }
    }
}

/// 文件中是否存在指定标记块
pub fn has_marked_block(path: &PathBuf, begin: &str) -> bool {
    read_file(path).map(|c| c.contains(begin)).unwrap_or(false)
}

// ---------- hosts 专用薄封装 ----------

/// 移除本工具写入的 hosts 块(含旧版 github-proxy 标记残留);返回是否有改动。
/// 有改动时自动刷新系统 DNS 缓存,新解析立即生效,无需手动 ipconfig /flushdns。
pub fn remove_block() -> bool {
    let mut changed = remove_marked_block(&hosts_path(), MARKER_BEGIN, MARKER_END);
    changed |= remove_marked_block(&hosts_path(), LEGACY_BEGIN, LEGACY_END);
    if changed {
        crate::flush_dns_cache();
    }
    changed
}

/// 写入(覆盖旧的)代理 hosts 块。entries: (域名, IP)
pub fn write_block(entries: &[(String, String)]) -> io::Result<()> {
    let mut body = String::new();
    for (domain, ip) in entries {
        body.push_str(ip);
        body.push('\t');
        body.push_str(domain);
        body.push('\n');
    }
    // 写入成功即刷 DNS 缓存:无论指向 127.0.0.1 还是真实 IP,新记录都要
    // 清掉系统缓存才立即生效(否则浏览器可能继续用旧解析,页面挂住)
    match write_marked_block(&hosts_path(), MARKER_BEGIN, MARKER_END, &body) {
        Ok(()) => {
            crate::flush_dns_cache();
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// 是否存在本工具的 hosts 标记块(自检用:被外部工具覆写后返回 false)
pub fn has_block() -> bool {
    has_marked_block(&hosts_path(), MARKER_BEGIN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_block_keeps_user_content() {
        let content = "127.0.0.1 localhost\n# qi-bunny begin\n1.2.3.4 github.com\n# qi-bunny end\n8.8.8.8 dns\n";
        let out = strip_block(content, MARKER_BEGIN, MARKER_END);
        assert!(out.contains("127.0.0.1 localhost"));
        assert!(out.contains("8.8.8.8 dns"));
        assert!(!out.contains("github.com"));
        assert!(!out.contains(MARKER_BEGIN));
    }

    #[test]
    fn strip_block_without_block_is_identity() {
        let content = "1.2.3.4 example.com\n";
        assert_eq!(strip_block(content, MARKER_BEGIN, MARKER_END), content);
    }

    #[test]
    fn strip_block_handles_unterminated_block() {
        // 有 begin 没 end:整块算到文件尾
        let content = "a\n# qi-bunny begin\nb\nc\n";
        let out = strip_block(content, MARKER_BEGIN, MARKER_END);
        assert!(out.contains("a"));
        assert!(!out.contains('b'));
    }

    #[test]
    fn strip_block_crlf_preserved() {
        let content = "x\r\n# qi-bunny begin\r\nb\r\n# qi-bunny end\r\ny\r\n";
        let out = strip_block(content, MARKER_BEGIN, MARKER_END);
        assert_eq!(out, "x\r\ny\r\n");
    }

    #[test]
    fn strip_legacy_block_too() {
        let content = "# github-proxy begin\nold\n# github-proxy end\nnew\n";
        let out = strip_block(content, LEGACY_BEGIN, LEGACY_END);
        assert!(out.contains("new"));
        assert!(!out.contains("old"));
    }

    #[test]
    fn write_then_read_marked_block_roundtrip() {
        let dir = std::env::temp_dir().join("qibunny-test-hosts");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts-test.txt");
        let _ = fs::remove_file(&path);
        write_marked_block(&path, MARKER_BEGIN, MARKER_END, "1.1.1.1\tdomain.com\n").unwrap();
        assert_eq!(
            read_marked_block(&path, MARKER_BEGIN, MARKER_END).unwrap(),
            "1.1.1.1\tdomain.com\n"
        );
        // 重写覆盖,不追加
        write_marked_block(&path, MARKER_BEGIN, MARKER_END, "2.2.2.2\tother.com\n").unwrap();
        assert_eq!(
            read_marked_block(&path, MARKER_BEGIN, MARKER_END).unwrap(),
            "2.2.2.2\tother.com\n"
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn write_block_body_format() {
        // write_block 的 entries 是 (域名, IP),body 组装为 IP \t 域名
        let entries = vec![("github.com".to_string(), "1.2.3.4".to_string())];
        let mut body = String::new();
        for (domain, ip) in &entries {
            body.push_str(ip);
            body.push('\t');
            body.push_str(domain);
            body.push('\n');
        }
        assert_eq!(body, "1.2.3.4\tgithub.com\n");
    }
}
