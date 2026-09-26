//! 系统 Toast 通知(Windows 10+ WinRT,失败自动静默/退回 MessageBox)
//!
//! 用 WinRT ToastNotifier 直接发通知,不依赖运行中的窗口;无 AppUserModelID
//! 注册时通知仍可显示(来源显示为 PowerShell 同类占位),个别精简系统上
//! 可能被策略关闭,此时调用方退回 MessageBox 弹窗,保证结果一定可见。

use windows::core::HSTRING;
use windows::Data::Xml::Dom::XmlDocument;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

/// 发一条系统 Toast 通知(title/正文)。发送失败返回 false,由调用方决定
/// 是否退回 MessageBox(不 panic、不打印——通知只是锦上添花)。
pub fn toast(title: &str, body: &str) -> bool {
    // Toast XML:文字两行,时长短,点击无动作
    let xml = format!(
        r#"<toast duration="short"><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual></toast>"#,
        escape_xml(title),
        escape_xml(body),
    );
    // windows 0.58 中 XmlDocument::new()/LoadXml 均返回 Result
    let Ok(doc) = XmlDocument::new() else {
        return false;
    };
    if doc.LoadXml(&HSTRING::from(xml)).is_err() {
        return false;
    }
    // AUMID 未在开始菜单注册时部分系统仍可显示;失败即返回 false
    let Ok(toast) = ToastNotification::CreateToastNotification(&doc) else {
        return false;
    };
    ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from("qi-bunny"))
        .and_then(|n| n.Show(&toast))
        .is_ok()
}

/// XML 文本转义(标题/正文可能含 & < > 用户粘贴内容)
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
