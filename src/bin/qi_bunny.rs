//! qi-bunny(奇小兔)—— 托盘后台模式入口
//!
//! `#![windows_subsystem = "windows"]`:进程以 GUI 子系统启动,Windows 从
//! 创建进程起就不会分配控制台窗口——从根源上消除托盘模式启动时的黑窗闪烁。
//! (旧的 FreeConsole 方案只是事后分离,启动瞬间窗口仍会闪现。)
//!
//! 命令行调试:若需查看托盘模式的日志输出,请用 qi-bunny-cli(控制台子系统)
//! 或在 IDE/调试器中启动本程序。

#![windows_subsystem = "windows"]

fn main() {
    qi_bunny::tray::run();
}
