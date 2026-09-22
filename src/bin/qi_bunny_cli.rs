//! qi-bunny(奇小兔)—— 命令行模式入口
//!
//! 控制台子系统程序,专为命令窗口下手动启动执行设计,与托盘模式完全独立:
//!   qi-bunny-cli start    HTTPS 加速:测速后本机反代接管;关窗口/Ctrl+C 即取消
//!   qi-bunny-cli stop     手动取消加速(移除 hosts/ssh config 标记块)
//!   qi-bunny-cli git      代码库管理模式:SSH 转发,关窗口即还原
//!   qi-bunny-cli status   查看加速是否开启(hosts / ssh config)
//!   qi-bunny-cli clean    清理全部记录(hosts + ssh config)
//!   qi-bunny-cli help     帮助(亦支持 -h/--help/-V/--version)
//!
//! 不带参数默认执行 start。
//! 托盘后台模式请直接运行 qi-bunny.exe(GUI 程序,无控制台窗口)。

use std::sync::atomic::Ordering;

/// 打印帮助信息
fn print_help() {
    println!(
        "qi-bunny(奇小兔)v{} —— AI 智能体开发辅助工具:开源库的搜索与更新加速

用法: qi-bunny-cli [子命令]

子命令:
  start    HTTPS 加速:测速写入 hosts,本机反代接管(默认);
           前台驻留,关闭窗口/Ctrl+C 即取消
  stop     手动取消加速:移除 hosts 标记块与 ssh config 标记块
  git      代码库管理模式:SSH 本地转发承载 git push/pull,关闭窗口即还原
  status   查看加速状态(hosts 是否写入 / ssh config 是否托管 / CA 信任状态)
  cert     生成并安装本地 CA 根证书(MITM 加速模式需要,一次性;需管理员权限)
  clean    清理全部记录(hosts 标记块 + ssh config 标记块)
  help     显示本帮助

全局选项:
  -h, --help     显示本帮助
  -V, --version  显示版本号

说明:
  * 写入 hosts 需要管理员权限(请以管理员身份运行命令窗口)
  * 托盘后台模式(常驻系统托盘、无控制台窗口)请直接运行 qi-bunny.exe

⚠ 用途警告:
  本工具仅供个人学习、技术研究与辅助 AI 智能体开发使用(如拉取
  GitHub 上的开源代码库、文档、依赖与开发资源)。使用者必须遵守
  所在国家/地区的法律法规,严禁将本工具用于任何非法用途。
  详见项目 README.md《免责声明与使用限制》。",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str);

    match cmd {
        // ---- 全局选项 ----
        Some("-h") | Some("--help") | Some("help") => {
            print_help();
        }
        Some("-V") | Some("--version") => {
            println!("qi-bunny(奇小兔)v{}", env!("CARGO_PKG_VERSION"));
        }
        // ---- 子命令 ----
        Some("start") | None => start_run(),
        Some("stop") => stop_run(),
        Some("git") => git_run(),
        Some("status") => status_run(),
        Some("cert") => cert_run(),
        Some("clean") => clean_run(),
        // ---- 未知参数:报错 + 帮助,退出码 2 ----
        Some(other) => {
            eprintln!("[!] 未知子命令: {}\n", other);
            print_help();
            std::process::exit(2);
        }
    }
}

/// 子命令 cert:生成本地 CA 并安装到系统受信任根(MITM 加速前提,一次性)
fn cert_run() {
    println!("qi-bunny(奇小兔)v{} —— 本地 CA 证书管理", env!("CARGO_PKG_VERSION"));
    match qi_bunny::cert::LocalCa::load_or_create() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("[!] 本地 CA 生成失败:{}", e);
            std::process::exit(1);
        }
    }
    match qi_bunny::cert::ca_trust_status() {
        qi_bunny::cert::TrustStatus::Trusted => {
            println!("[+] 本地 CA 已在系统受信任根中,无需重复安装。");
        }
        _ => match qi_bunny::cert::install_ca_to_trust() {
            Ok(()) => println!("[+] 本地 CA 已安装到系统受信任根(受信任的根证书颁发机构)。"),
            Err(e) => {
                eprintln!("[!] 自动安装失败:{}\n    请以管理员身份运行: qi-bunny-cli cert", e);
                std::process::exit(1);
            }
        },
    }
}

/// 子命令 stop:手动取消加速(hosts + ssh config 一次清理)
fn stop_run() {
    let mut n = 0;
    if qi_bunny::hosts::remove_block() {
        println!("[+] 已移除 hosts 记录,HTTPS 加速已取消。");
        n += 1;
    }
    if qi_bunny::ssh::disable_and_report() {
        println!("[+] 已还原 ssh config,代码库管理模式已取消。");
        n += 1;
    }
    if n == 0 {
        println!("[*] 当前未开启加速,无需操作。");
    }
}

/// 子命令 status:查看当前加速状态(只读)
/// hosts/ssh 标记块反映"配置是否写入";反代候选池是**运行期内存态**,
/// 只有本进程(或托盘进程)自己知道——status 作为独立进程读不到运行中
/// 托盘的池子,因此池况仅在本进程托管反代时展示(如 start 驻留中另开
/// 窗口查询);跨进程场景以 hosts 配置 + 实际连通性测试为准。
fn status_run() {
    let hosts_on = qi_bunny::hosts::has_block();
    let ssh_on = qi_bunny::ssh::has_config_block();
    println!("qi-bunny(奇小兔)v{}", env!("CARGO_PKG_VERSION"));
    println!("  HTTPS 加速(hosts):  {}", if hosts_on { "已开启" } else { "未开启" });
    println!("  代码库管理(ssh config): {}", if ssh_on { "已开启" } else { "未开启" });

    // 反代与链路:与托盘状态行共用 status_detail(443 端口探测 + HTTP 链路实测)
    let (proxy_up, link) = qi_bunny::status_detail();
    println!(
        "  本机反代(127.0.0.1:443): {}",
        if proxy_up { "运行中" } else { "未运行" }
    );
    if hosts_on && !proxy_up {
        println!("  [!] hosts 指向 127.0.0.1 但反代未运行,GitHub 将无法访问——请重新 start 或运行 clean。");
    }
    if hosts_on {
        if link.is_empty() {
            println!("  链路实测(github.com): 无响应(反代未运行或上游异常)");
        } else {
            println!("  链路实测(github.com): HTTP {}(流量已正常到达上游)", link);
        }
    }

    // CA 信任状态(MITM 加速前提:不信任则浏览器报证书错误)
    let trust = qi_bunny::cert::ca_trust_status();
    let trust_text = match trust {
        qi_bunny::cert::TrustStatus::Trusted => "已信任",
        qi_bunny::cert::TrustStatus::Missing => "未信任(运行 qi-bunny-cli cert 安装)",
        qi_bunny::cert::TrustStatus::Unknown => "未知",
    };
    println!("  本地 CA(MITM): {}", trust_text);
}

/// 子命令 clean:清理 hosts 与 ssh config 的全部标记块(含旧版残留)
fn clean_run() {
    let mut n = 0;
    if qi_bunny::hosts::remove_block() {
        println!("[+] 已移除 hosts 记录。");
        n += 1;
    }
    if qi_bunny::ssh::disable_and_report() {
        println!("[+] 已还原 ssh config(代码库管理模式配置)。");
        n += 1;
    }
    if n == 0 {
        println!("[*] 未发现本工具的记录,无需清理。");
    }
}

/// 代码库管理模式(CLI 前台):开启 SSH 转发,验证后驻留,退出时还原
fn git_run() {
    println!(
        "qi-bunny(奇小兔)v{} —— 代码库管理模式(SSH 本地转发)
仅供个人学习、技术研究与辅助 AI 智能体开发使用,严禁用于非法用途。
",
        env!("CARGO_PKG_VERSION")
    );
    println!("开启后 git push/pull(git@github.com) 走加速链路;关闭本程序自动还原。\n");

    println!("[*] 收集 github.com 候选 IP…");
    let pool = qi_bunny::candidate_pool("github.com");
    match qi_bunny::ssh::enable_ssh(&pool) {
        Ok(mode) => {
            println!("[+] 代码库管理模式{}", mode);
            let (ok, msg) = qi_bunny::ssh::verify();
            if ok {
                println!("[+] SSH 链路验证通过:{}", msg);
                println!("[+] 现在可以 git push / git pull 了。");
            } else {
                println!("[!] SSH 链路验证未通过:{},可重试或检查 ssh key。", msg);
            }
            println!("[+] 保持本窗口开启;关闭即自动还原配置取消提交加速。");

            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            {
                let running = running.clone();
                ctrlc::set_handler(move || {
                    running.store(false, Ordering::SeqCst);
                })
                .ok();
            }
            while running.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            qi_bunny::ssh::disable_ssh();
            println!("[+] 已还原 ssh config,代码库管理模式已取消。");
        }
        Err(e) => {
            eprintln!("[!] 开启失败:{}", e);
            std::process::exit(1);
        }
    }
}

/// 子命令 start(默认):开启 HTTPS 加速,前台驻留,退出时自动取消
fn start_run() {
    println!(
        "qi-bunny(奇小兔)v{} —— GitHub 网络加速(Hosts 模式)
仅供个人学习、技术研究与辅助 AI 智能体开发使用,严禁用于非法用途。
",
        env!("CARGO_PKG_VERSION")
    );

    println!("[*] 采集候选 IP,测速并写入 hosts…");
    if let Err(e) = qi_bunny::enable_proxy() {
        eprintln!("\n[!] {}", e);
        std::process::exit(1);
    }
    println!("[*] 提示:浏览器如仍打不开,请清空 DNS 缓存或重启浏览器(可用 ipconfig /flushdns)。");
    println!("[+] 保持本窗口开启即可;关闭即取消代理。");

    // 退出时清理(覆盖 Ctrl+C 与正常终止)
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
        })
        .ok();
    }

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    qi_bunny::disable_proxy();
}
