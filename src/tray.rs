//! 托盘后台模式
//!
//! 启动后分离控制台、驻留后台,无任何窗口:
//!   - 图标即状态:亮色(品牌绿)= 代理开启成功;灰色 = 关闭/失败
//!   - 左键点击图标弹出菜单,所有控制经菜单完成
//!
//! 耗时的解析+测速+写 hosts 在工作线程执行,结果经事件回传刷新图标与菜单;
//! 事件循环(tao)运行在主线程,这是 tray-icon 在 Windows 上的要求。

use crate::{disable_proxy, enable_proxy, logerr, QUIET};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use tao::event::Event;
use tao::event_loop::EventLoopBuilder;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};

/// 原创托盘图标(根目录 logo.svg,单色矢量,编译期内嵌,无第三方商标)
const ICON_SVG_RAW: &str = include_str!("../logo.svg");

/// 图标中的原始单色,运行时按状态替换
const ICON_BASE_COLOR: &str = "#3F4E62";
/// 亮色(代理开启成功):品牌绿,明暗任务栏下均醒目
const ON_COLOR: &str = "#2DA44E";
/// 灰色(关闭/失败):中性灰
const OFF_COLOR: &str = "#9EA7B1";

/// 按状态着色的图标 SVG(true=开启亮色,false=关闭灰色)
fn state_svg(on: bool) -> String {
    ICON_SVG_RAW.replace(ICON_BASE_COLOR, if on { ON_COLOR } else { OFF_COLOR })
}

/// 托盘初始化不可恢复失败:报错后退出进程(GUI 程序无控制台,错误写日志/弹窗无效,
/// 直接退出让用户从退出码感知)
fn fatal_startup(what: &str, detail: String) -> ! {
    logerr!("[!] {}:{}程序退出。", what, detail);
    std::process::exit(1);
}

/// 工作线程命令
enum Cmd {
    /// 开启(自动先清理旧记录,再重新测速写入;同时充当"重新测速并刷新")
    Enable,
    Disable,
    /// 代码库管理模式开关(true=开启 SSH 转发,false=关闭并还原)
    SshSet(bool),
    Quit,
}

/// 工作线程 -> 事件循环的状态回传
enum UserEvent {
    /// HTTPS 代理状态:(是否已开启, 状态描述)
    Status(bool, String),
    /// 代码库管理模式状态:(是否已开启, 状态描述)
    SshStatus(bool, String),
}

pub fn run() {
    // GUI 子系统(#!windows_subsystem)下进程从启动起就没有控制台,无需
    // FreeConsole;日志静默由 QUIET 统一控制
    QUIET.store(true, std::sync::atomic::Ordering::SeqCst);

    // 单实例互斥锁:防止多开导致 hosts 记录互相覆盖/重复清理
    #[cfg(windows)]
    {
        const ERROR_ALREADY_EXISTS: u32 = 183;
        let name: Vec<u16> = "Global\\qi-bunny-tray-mutex\0"
            .encode_utf16()
            .collect();
        let handle = unsafe {
            windows_sys::Win32::System::Threading::CreateMutexW(
                std::ptr::null(),
                0, // 不立即持有,仅判断是否已存在实例
                name.as_ptr(),
            )
        };
        if !handle.is_null()
            && unsafe { windows_sys::Win32::Foundation::GetLastError() } == ERROR_ALREADY_EXISTS
        {
            logerr!("[!] qi-bunny(奇小兔)已在运行(托盘图标见任务栏),本次启动退出。");
            std::process::exit(0);
        }
        // handle 有意不关闭:互斥锁需随进程生命周期保持
    }

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    // 菜单:状态行(只读)+ 开启/关闭/刷新 + 代码库管理模式(勾选) + 关于 + 退出
    let status = MenuItem::new("状态: 初始化…", false, None);
    let enable = MenuItem::new("开启代理", true, None);
    let disable = MenuItem::new("关闭代理", false, None);
    let refresh = MenuItem::new("重新测速并刷新", true, None);
    let ssh_mode = tray_icon::menu::CheckMenuItem::new("代码库管理模式(git)", false, true, None);
    let about = MenuItem::new("关于 qi-bunny…", true, None);
    let quit = MenuItem::new("退出(自动取消代理)", true, None);
    let enable_id = enable.id().clone();
    let disable_id = disable.id().clone();
    let refresh_id = refresh.id().clone();
    let ssh_id = ssh_mode.id().clone();
    let about_id = about.id().clone();
    let quit_id = quit.id().clone();

    let menu = Menu::new();
    menu.append_items(&[
        &status,
        &PredefinedMenuItem::separator(),
        &enable,
        &disable,
        &refresh,
        &PredefinedMenuItem::separator(),
        &ssh_mode,
        &PredefinedMenuItem::separator(),
        &about,
        &quit,
    ])
    .unwrap_or_else(|e| fatal_startup("菜单构建失败", e.to_string()));

    // 启动时灰色图标(代理未开启),渲染失败则退回纯色方块
    let initial = render_icon(32, &state_svg(false))
        .or_else(|e| {
            logerr!("[!] logo 渲染失败({}),使用兜底图标", e);
            tray_icon::Icon::from_rgba([158, 167, 177, 255].repeat(32 * 32), 32, 32)
        })
        .unwrap_or_else(|e| fatal_startup("托盘图标创建失败", e.to_string()));

    let tray = tray_icon::TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("qi-bunny 奇小兔(代理未开启)")
        .with_icon(initial)
        .build()
        .unwrap_or_else(|e| fatal_startup("托盘图标创建失败", e.to_string()));

    // 工作线程:执行耗时的解析+测速+写 hosts,完成后回传状态;
    // 空闲时定期自检,加速链路失效时自动重新测速恢复
    let (tx, rx) = mpsc::channel::<Cmd>();
    // 代码库管理模式当前状态(菜单事件线程翻转勾选项用)
    let ssh_on = Arc::new(AtomicBool::new(false));
    {
        let proxy = proxy.clone();
        let ssh_on = ssh_on.clone();
        std::thread::spawn(move || {
            // 自检周期:5 分钟;recv_timeout 空闲等待期间做自检
            let check_interval = std::time::Duration::from_secs(300);
            let mut proxy_on = false;
            // enable 失败后的冷却期(按 tick 计):失败通常意味着当前网络下
            // 探不出可用 IP,连续每 5 分钟重测既无意义也拖慢自检循环;
            // 冷却期内不再自动重试,期间 hosts 无记录,系统走原始解析
            const RETRY_COOLDOWN_TICKS: usize = 6;
            let mut retry_wait = 0usize;

            // 启动:直接测速写入 hosts 并启动反代(不再检测直连状态)
            match enable_proxy() {
                Ok(entries) => {
                    proxy_on = true;
                    let _ = proxy.send_event(UserEvent::Status(
                        true,
                        format!("已开启({} 条记录)", entries.len()),
                    ));
                }
                Err(e) => {
                    retry_wait = RETRY_COOLDOWN_TICKS;
                    let _ = proxy.send_event(UserEvent::Status(
                        false,
                        format!("开启失败:{}({}分钟后自动重试)", e, RETRY_COOLDOWN_TICKS * 5),
                    ));
                }
            }

            loop {
                match rx.recv_timeout(check_interval) {
                    Ok(cmd) => match cmd {
                        Cmd::Enable => {
                            // 手动开启/刷新:先清理旧记录再重新测速写入
                            crate::hosts::remove_block();
                            match enable_proxy() {
                                Ok(entries) => {
                                    proxy_on = true;
                                    let _ = proxy.send_event(UserEvent::Status(
                                        true,
                                        format!("已开启({} 条记录)", entries.len()),
                                    ));
                                }
                                Err(e) => {
                                    proxy_on = false;
                                    let _ = proxy.send_event(UserEvent::Status(
                                        false,
                                        format!("开启失败:{}", e),
                                    ));
                                }
                            }
                        }
                        Cmd::Disable => {
                            disable_proxy();
                            proxy_on = false;
                            let _ = proxy.send_event(UserEvent::Status(false, "已关闭".into()));
                        }
                        Cmd::SshSet(on) => {
                            if on {
                                // 复用 HTTPS 代理的 github.com 候选池
                                let pool = crate::candidate_pool("github.com");
                                match crate::ssh::enable_ssh(&pool) {
                                    Ok(mode) => {
                                        ssh_on.store(true, Ordering::SeqCst);
                                        let _ = proxy.send_event(UserEvent::SshStatus(
                                            true,
                                            format!("已开启({})", mode),
                                        ));
                                    }
                                    Err(e) => {
                                        ssh_on.store(false, Ordering::SeqCst);
                                        let _ = proxy.send_event(UserEvent::SshStatus(
                                            false,
                                            format!("开启失败:{}", e),
                                        ));
                                    }
                                }
                            } else {
                                crate::ssh::disable_ssh();
                                ssh_on.store(false, Ordering::SeqCst);
                                let _ = proxy.send_event(UserEvent::SshStatus(
                                    false,
                                    "已关闭".into(),
                                ));
                            }
                        }
                        Cmd::Quit => {
                            // 退出前确保取消代理与代码库管理模式
                            disable_proxy();
                            crate::ssh::disable_ssh();
                            std::process::exit(0);
                        }
                    },
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // 空闲期:刷新状态行为实时详情(反代 + 链路实测),
                        // 让菜单第一行始终反映当下链路,而非最后一次事件文案
                        {
                            let (up, link) = crate::status_detail();
                            let text = if up {
                                if link.is_empty() {
                                    "状态: 反代运行中,链路无响应".to_string()
                                } else {
                                    format!("状态: 反代运行中,链路 HTTP {}", link)
                                }
                            } else if retry_wait > 0 {
                                format!("状态: 未开启({} 分钟后重试)", retry_wait * 5)
                            } else {
                                "状态: 未开启".to_string()
                            };
                            let _ = proxy.send_event(UserEvent::Status(proxy_on && up, text));
                        }
                        // 开启失败后的冷却期内不自动重试(每 5 分钟重测一轮
                        // 无意义且拖慢自检),只倒计时;期间 hosts 无记录,走原始解析
                        if retry_wait > 0 {
                            retry_wait -= 1;
                            continue;
                        }
                        if proxy_on && self_check_failed() {
                            // 加速链路失效(hosts 块丢失或 GitHub 不可达):
                            // 先写直连 IP 保住可达性(代理可以慢,不能断网),
                            // 再尝试重新测速升回反代模式;升回失败则留在
                            // 直连模式,下个周期继续重试。
                            logerr!("[*] 自检失败,先切直连兜底再尝试恢复加速…");
                            let fallback = crate::write_direct_fallback();
                            if fallback == 0 {
                                // 连直连 IP 都拿不到:清掉劫持记录,走系统原始解析
                                crate::hosts::remove_block();
                            }
                            if enable_proxy().is_ok() {
                                let _ = proxy.send_event(UserEvent::Status(
                                    true,
                                    "自检恢复(已重新测速)".into(),
                                ));
                            } else if fallback > 0 {
                                let _ = proxy.send_event(UserEvent::Status(
                                    true,
                                    format!("直连兜底({} 条记录),稍后重试加速", fallback),
                                ));
                            } else {
                                proxy_on = false;
                                retry_wait = RETRY_COOLDOWN_TICKS;
                                let _ = proxy.send_event(UserEvent::Status(
                                    false,
                                    format!("自检恢复失败({}分钟后重试)", RETRY_COOLDOWN_TICKS * 5),
                                ));
                            }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
    }

    // 启动时代理由工作线程直接测速写入 hosts

    // 托盘菜单事件 -> 工作线程(独立线程收全局菜单事件通道)
    // CheckMenuItem 点击即翻转勾选,按当前 ssh_on 状态取反下发
    {
        let menu_tx = tx.clone();
        let ssh_on = ssh_on.clone();
        std::thread::spawn(move || {
            let menu_rx = MenuEvent::receiver();
            while let Ok(ev) = menu_rx.recv() {
                if ev.id == enable_id {
                    let _ = menu_tx.send(Cmd::Enable);
                } else if ev.id == disable_id {
                    let _ = menu_tx.send(Cmd::Disable);
                } else if ev.id == refresh_id {
                    let _ = menu_tx.send(Cmd::Enable);
                } else if ev.id == ssh_id {
                    let on = !ssh_on.load(Ordering::SeqCst);
                    let _ = menu_tx.send(Cmd::SshSet(on));
                } else if ev.id == about_id {
                    show_about();
                } else if ev.id == quit_id {
                    let _ = menu_tx.send(Cmd::Quit);
                }
            }
        });
    }

    // 主线程事件循环:状态回传 -> 切换图标(亮/灰)+ tooltip + 菜单文字
    event_loop.run(move |event, _, control_flow| {
        *control_flow = tao::event_loop::ControlFlow::Wait;
        match event {
            Event::UserEvent(UserEvent::Status(on, msg)) => {
                status.set_text(format!("状态: {}", msg));
                enable.set_enabled(!on);
                disable.set_enabled(on);
                refresh.set_enabled(true);

                let svg = state_svg(on);
                if let Ok(icon) = render_icon(32, &svg) {
                    let _ = tray.set_icon(Some(icon));
                } // 渲染失败保持当前图标,不影响功能
                let tip = if on {
                    "qi-bunny 奇小兔(代理已开启)"
                } else {
                    "qi-bunny 奇小兔(代理未开启)"
                };
                let _ = tray.set_tooltip(Some(tip.to_string()));
            }
            Event::UserEvent(UserEvent::SshStatus(on, msg)) => {
                // 代码库管理模式:同步勾选状态与状态行
                ssh_mode.set_checked(on);
                status.set_text(format!("提交: {}", msg));
            }
            _ => {}
        }
    });
}

/// 「关于」对话框:版本、用途说明与合法使用警告(Windows 原生 MessageBox,
/// 不引入额外 GUI 依赖)
fn show_about() {
    #[cfg(windows)]
    {
        const MB_OK: u32 = 0x0000_0000;
        const MB_ICONINFORMATION: u32 = 0x0000_0040;
        let text = format!(
            "qi-bunny(奇小兔)v{}\n\
             AI 智能体开发辅助工具:开源库的搜索与更新加速\n\n\
             本工具仅供个人学习、技术研究与辅助 AI 智能体开发使用\n\
             (如拉取 GitHub 上的开源代码库、文档、依赖与开发资源)。\n\n\
             ⚠ 警告:使用者必须遵守所在国家/地区的法律法规,\n\
             严禁将本工具用于任何非法用途。\n\
             下载、安装或运行即表示已同意《免责声明与使用限制》\n\
             (详见项目 README.md)。",
            env!("CARGO_PKG_VERSION")
        );
        let title = format!("关于 qi-bunny(奇小兔)v{}", env!("CARGO_PKG_VERSION"));
        use std::os::windows::ffi::OsStrExt;
        let wide = |s: &str| -> Vec<u16> {
            std::ffi::OsStr::new(s)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        };
        // MessageBoxW(无窗口句柄、文本、标题、标志);直接调用,失败也无碍
        extern "system" {
            fn MessageBoxW(hwnd: isize, text: *const u16, caption: *const u16, utype: u32) -> i32;
        }
        let t = wide(&text);
        let c = wide(&title);
        unsafe {
            MessageBoxW(0, t.as_ptr(), c.as_ptr(), MB_OK | MB_ICONINFORMATION);
        }
        let _ = (MB_OK, MB_ICONINFORMATION);
    }
    #[cfg(not(windows))]
    {
        log!(
            "qi-bunny(奇小兔)v{} —— 仅供个人学习、技术研究与辅助 AI 智能体开发使用,严禁用于非法用途",
            env!("CARGO_PKG_VERSION")
        );
    }
}

/// 自检:代理应开启状态下,hosts 块丢失或 github.com 不可达即视为失效。
/// 用真实 HTTPS 请求验证(走系统 hosts),5 秒超时,失败重试一次防抖。
fn self_check_failed() -> bool {
    if !crate::hosts::has_block() {
        return true; // hosts 记录被外部清掉(如其他工具覆写)
    }

    let attempt = || -> bool {
        ureq::get("https://github.com/")
            .timeout(std::time::Duration::from_secs(5))
            .call()
            .is_ok()
    };
    // 失败重试一次防抖:两次都失败才判定失效
    !attempt() && !attempt()
}

/// GitHub logo SVG -> RGBA 托盘图标
fn render_icon(size: u32, svg: &str) -> Result<tray_icon::Icon, String> {
    let opt = resvg::usvg::Options::default();
    let tree = resvg::usvg::Tree::from_str(svg, &opt).map_err(|e| e.to_string())?;
    let mut pixmap = resvg::tiny_skia::Pixmap::new(size, size).ok_or("pixmap 创建失败")?;
    let ts = resvg::tiny_skia::Transform::from_scale(
        size as f32 / tree.size().width(),
        size as f32 / tree.size().height(),
    );
    resvg::render(&tree, ts, &mut pixmap.as_mut());
    let rgba = pixmap.data().to_vec();
    tray_icon::Icon::from_rgba(rgba, size, size).map_err(|e| e.to_string())
}
