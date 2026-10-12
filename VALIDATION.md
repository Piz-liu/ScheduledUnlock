# 验证记录

本次交付日期：2026-10-11。开发环境为 macOS，未连接 Windows 11 测试机。

## 已执行

- 使用 LLVM-MinGW 20261006 / Clang 23.1.3，成功构建 Release x64 的设置程序和 Credential Provider DLL。
- 使用原生 C++ 执行请求有效性测试：17 项检查通过，覆盖锁屏条件、会话匹配、设置版本匹配、缺少请求标识、精确过期时间、时间倒退和时间戳溢出。
- 使用 Clang 静态分析检查四个 Windows C++ 实现文件，无诊断；最后增加的 SYSTEM 会话查询权限处理也单独完成静态分析。
- 检查最终 PE 文件：两个文件均为 AMD64；登录组件导出 `DllGetClassObject`、`DllCanUnloadNow`。
- 检查设置程序包含管理员权限清单，清单 XML 可解析；DLL 和 EXE 的导入依赖均为 Windows 系统组件，没有需要另外分发的 C++ 运行库 DLL。
- 检查安装脚本不会注册凭据过滤器或更改 Windows 自带提供程序；卸载范围限定于本软件的 GUID、注册表项、任务和安装目录。
- PowerShell 脚本使用 UTF-8 BOM，入口 CMD 使用 CRLF，以兼容 Windows PowerShell 5.1。

## 未执行

- Windows 上的安装、卸载和管理员权限确认。
- 实际 DPAPI 加解密、Windows 密码验证和 Task Scheduler 任务注册。
- LogonUI 的 COM 事件通知、Credential Provider 枚举与 Windows 验证结果回调。
- Windows 11 完整锁屏画面和登录画面下的无人操作自动解锁。
- 睡眠唤醒、不同显示缩放、不同 Windows 11 版本及登录策略下的兼容性。
- PowerShell 脚本的运行时验证；尝试获取脚本解析工具时遇到下载超时，未把该项记为通过。
- 数字签名与安装器签名。

**以上编译、边界测试和静态检查不能证明真实 Windows 登录流程已经可用。本版本应作为可编译、可安装验证的原型，先完成 README 中的 Windows 虚拟机测试。**
