//! 托盘后台模式
//!
//! 启动后分离控制台、驻留后台,无任何窗口:
//!   - 图标即状态:亮色(品牌绿)= 代理开启成功;灰色 = 关闭/失败
//!   - 左键点击图标弹出菜单,所有控制经菜单完成
//!
//! 耗时的解析+测速+写 hosts 在工作线程执行,结果经事件回传刷新图标与菜单;
//! 事件循环(tao)运行在主线程,这是 tray-icon 在 Windows 上的要求。

use crate::{disable_proxy, enable_proxy, logerr, QUIET};
use std::sync::mpsc;
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
    Quit,
}

/// 工作线程 -> 事件循环的状态回传
enum UserEvent {
    /// HTTPS 代理状态:(是否已开启, 状态描述)
    Status(bool, String),
    /// 加速下载进度/结果:None = 下载结束(恢复菜单),Some = 进行中的文案
    Download(Option<String>),
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

    // 菜单:状态行(只读)+ 开启/关闭/刷新 + 加速下载 + 关于 + 退出
    let status = MenuItem::new("状态: 初始化…", false, None);
    let enable = MenuItem::new("开启代理", true, None);
    let disable = MenuItem::new("关闭代理", false, None);
    let refresh = MenuItem::new("重新测速并刷新", true, None);
    // 第三方下载加速(候选手段):链接取自剪贴板,与 hosts 加速完全隔离;
    // 下方只读行展示下载进度,下载中禁用「加速下载」防止并发下载互相覆盖
    let fetch = MenuItem::new("加速下载(链接取自剪贴板)", true, None);
    let dl_status = MenuItem::new("加速下载: 空闲", false, None);
    let about = MenuItem::new("关于 qi-bunny…", true, None);
    let quit = MenuItem::new("退出(自动取消代理)", true, None);
    let enable_id = enable.id().clone();
    let disable_id = disable.id().clone();
    let refresh_id = refresh.id().clone();
    let fetch_id = fetch.id().clone();
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
        &fetch,
        &dl_status,
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
    {
        let proxy = proxy.clone();
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
                        Cmd::Quit => {
                            // 退出前取消代理
                            disable_proxy();
                            std::process::exit(0);
                        }
                    },
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                    // 空闲期:刷新状态行为实时详情(反代 + 链路实测),
                    // 让菜单第一行始终反映当下链路,而非最后一次事件文案。
                    // 行为与 CLI 一致:开启后驻留不动,只展示状态,
                    // 不做自检降级(直连兜底 IP 未经测速,反而更不稳)。
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
                            retry_wait = retry_wait.saturating_sub(1);
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
    }

    // 启动时代理由工作线程直接测速写入 hosts

    // 托盘菜单事件 -> 工作线程(独立线程收全局菜单事件通道)
    {
        let menu_tx = tx.clone();
        std::thread::spawn(move || {
            let menu_rx = MenuEvent::receiver();
            while let Ok(ev) = menu_rx.recv() {
                if ev.id == enable_id {
                    let _ = menu_tx.send(Cmd::Enable);
                } else if ev.id == disable_id {
                    let _ = menu_tx.send(Cmd::Disable);
                } else if ev.id == refresh_id {
                    let _ = menu_tx.send(Cmd::Enable);
                } else if ev.id == fetch_id {
                    fetch_from_clipboard(proxy.clone());
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
            Event::UserEvent(UserEvent::Download(msg)) => match msg {
                // 进行中:显示进度并禁用「加速下载」,防止并发下载互相覆盖文件
                Some(text) => {
                    dl_status.set_text(text);
                    fetch.set_enabled(false);
                }
                // 结束(无论成败):状态行保留结果文案,恢复「加速下载」可点击
                None => fetch.set_enabled(true),
            },
            _ => {}
        }
    });
}

/// 「关于」对话框:版本、用途说明与合法使用警告(Windows 原生 MessageBox,
/// 不引入额外 GUI 依赖)
fn show_about() {
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
    message_box(
        &format!("关于 qi-bunny(奇小兔)v{}", env!("CARGO_PKG_VERSION")),
        &text,
        false,
    );
}

/// Windows 原生 MessageBox 弹窗(托盘无窗口,提示用;失败也无碍)
fn message_box(title: &str, text: &str, is_error: bool) {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let wide = |s: &str| -> Vec<u16> {
            std::ffi::OsStr::new(s)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        };
        const MB_OK: u32 = 0x0000_0000;
        const MB_ICONINFORMATION: u32 = 0x0000_0040;
        const MB_ICONERROR: u32 = 0x0000_0010;
        // MessageBoxW(无窗口句柄、文本、标题、标志);直接调用,失败也无碍
        extern "system" {
            fn MessageBoxW(hwnd: isize, text: *const u16, caption: *const u16, utype: u32) -> i32;
        }
        let t = wide(text);
        let c = wide(title);
        unsafe {
            MessageBoxW(
                0,
                t.as_ptr(),
                c.as_ptr(),
                MB_OK | if is_error { MB_ICONERROR } else { MB_ICONINFORMATION },
            );
        }
        let _ = (MB_OK, MB_ICONINFORMATION, MB_ICONERROR);
    }
    #[cfg(not(windows))]
    {
        let _ = (title, is_error);
        log!("{}", text);
    }
}

/// 托盘「加速下载」:链接取自剪贴板,存入系统下载目录,完成后弹窗通知。
/// 第三方中转下载是候选手段,与 hosts/反代主链路完全隔离,失败不影响加速。
/// 下载期间通过 Download 事件实时刷新菜单状态行(百分比/阶段),
/// 并禁用「加速下载」项,直到本次下载结束(无论成败)才恢复可点击。
fn fetch_from_clipboard(proxy: tao::event_loop::EventLoopProxy<UserEvent>) {
    // 独立线程执行:下载含测速可能耗时数十秒,不能卡住菜单事件线程
    std::thread::spawn(move || {
        // 进度快照 -> 菜单文案:有总大小显示百分比,否则显示已下载字节数
        let mut send = |p: &crate::mirror::Progress| {
            let text = if p.total > 0 {
                format!(
                    "加速下载: {} {:.1}%",
                    p.stage,
                    (p.done as f64 / p.total as f64 * 100.0).min(100.0)
                )
            } else if p.done > 0 {
                format!("加速下载: {} {:.1} MB", p.stage, p.done as f64 / 1048576.0)
            } else {
                format!("加速下载: {}", p.stage)
            };
            let _ = proxy.send_event(UserEvent::Download(Some(text)));
        };

        let finish = |text: &str, proxy: &tao::event_loop::EventLoopProxy<UserEvent>| {
            let _ = proxy.send_event(UserEvent::Download(Some(text.to_string())));
            let _ = proxy.send_event(UserEvent::Download(None));
        };

        let text = match arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
            Ok(t) => t,
            Err(e) => {
                finish(&format!("加速下载: 读剪贴板失败"), &proxy);
                message_box("加速下载", &format!("读取剪贴板失败:{}", e), true);
                return;
            }
        };
        // 剪贴板常是整段命令或段落(git clone …、wget …、纯链接),
        // 先从中提取出 GitHub 链接再校验
        let url = match crate::sources::extract_github_url(&text) {
            Some(u) => u,
            None => {
                finish("加速下载: 未找到链接", &proxy);
                message_box(
                    "加速下载",
                    "未在剪贴板中找到 GitHub 链接。请复制 GitHub 文件/Release/Archive 链接(支持整段 git clone 命令)再点击。",
                    true,
                );
                return;
            }
        };
        if let Err(e) = crate::sources::validate_url(&url) {
            finish("加速下载: 链接无效", &proxy);
            message_box("加速下载", &format!("链接无效:{}", e), true);
            return;
        }
        // 保存到系统下载目录(取不到则退回当前目录)
        let dir = crate::sources::default_download_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        let dest = dir.join(crate::sources::filename_from_url(&url));
        match crate::mirror::download(&url, &dest, &mut send) {
            Ok(label) => {
                finish("加速下载: ✅ 完成", &proxy);
                let body = format!("已保存:{}\n使用通道:{}", dest.display(), label);
                // Toast 优先(不挡操作);失败退回 MessageBox 保证结果可见
                if !crate::notify::toast("加速下载完成", &body) {
                    message_box("加速下载完成", &body, false);
                }
            }
            Err(e) => {
                finish("加速下载: ❌ 失败", &proxy);
                if !crate::notify::toast("加速下载失败", &e) {
                    message_box("加速下载失败", &e, true);
                }
            }
        }
    });
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
