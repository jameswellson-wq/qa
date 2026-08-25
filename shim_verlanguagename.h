#pragma once
//
// shim_verlanguagename.h
// VerLanguageNameA / W 运行时兼容 SHIM — 头文件
//
// ─────────────────────────────────────────────────────────────────────────────
// 问题背景
// ─────────────────────────────────────────────────────────────────────────────
//   原 version.cpp 用静态 PE 转发条目把这两个函数硬绑到 KERNEL32：
//
//     #pragma comment(linker, "/EXPORT:VerLanguageNameA=KERNEL32.VerLanguageNameA,@14")
//     #pragma comment(linker, "/EXPORT:VerLanguageNameW=KERNEL32.VerLanguageNameW,@15")
//
//   KERNEL32 中的 VerLanguageName* 是 XP 时代留下的兼容存根。
//   风险：
//     · 微软未来某个大版本可能直接删除这两个导出（存根本就是遗留品）
//     · Wine / ReactOS / 精简版 Windows（LTSC/IoT）有时缺少此导出
//     · 删除后代理 DLL 在加载时直接报"找不到过程入口"，整个进程崩溃
//
// ─────────────────────────────────────────────────────────────────────────────
// SHIM 策略（运行时按优先级逐级探测）
// ─────────────────────────────────────────────────────────────────────────────
//   1. VERSION_SRC.dll  — 重命名后的真实 version.dll
//                          Vista+ 起函数的真实实现就在这里；
//                          若已加载（应用首次调用其他 version 函数后），优先使用。
//   2. KERNEL32.dll     — XP 兼容存根，Win7~Win11 均保留，最可靠的后备
//   3. KERNELBASE.dll   — Wine / 精简镜像中有时只有 KERNELBASE 实现
//   4. 安全降级          — 写空串 + SetLastError(ERROR_PROC_NOT_FOUND) + 返回 0
//                          调用方拿到 0 和错误码，行为明确，不会崩溃
//
// ─────────────────────────────────────────────────────────────────────────────
// 线程安全
// ─────────────────────────────────────────────────────────────────────────────
//   内部使用 Windows INIT_ONCE 机制，保证探测逻辑全进程只执行一次，
//   任意线程并发调用均安全，无锁开销。
//
// ─────────────────────────────────────────────────────────────────────────────
// 使用方式
// ─────────────────────────────────────────────────────────────────────────────
//   1. 在 version.cpp DllMain → DLL_PROCESS_ATTACH 中调用 ShimVerLanguageName_Init()
//      （可选，但推荐：提前探测，避免首次调用的微小延迟）
//   2. 删除 version.cpp 中的两条 KERNEL32 forwarder pragma（@14 / @15）
//   3. 把 shim_verlanguagename.cpp 加入 vcxproj 源文件列表
//
// ─────────────────────────────────────────────────────────────────────────────
// WIN32_LEAN_AND_MEAN（必须在 #include <windows.h> 之前生效）
// ─────────────────────────────────────────────────────────────────────────────
// 根本原因：若缺少此宏，<windows.h> 会拉入 <winver.h>，
// <winver.h> 会把 VerLanguageNameA/W 声明为 __declspec(dllimport)，
// 而 shim_verlanguagename.cpp 里这两个函数是 __declspec(dllexport) 定义，
// 链接器遇到同一符号的两种 linkage → C2375: redefinition; different linkage。
//
// 防御策略（双重保险）：
//   · 在本头文件的 #include <windows.h> 之前用 #ifndef 守护宏
//   · 每个 .cpp（version.cpp / shim_verlanguagename.cpp）顶部也显式定义
//   · vcxproj PreprocessorDefinitions 同样加入 WIN32_LEAN_AND_MEAN
//     （保证任何 TU 都不会意外漏掉）
//
// 注意：#ifndef 守护只在 <windows.h> 尚未被当前 TU 包含时有效。
// 若上游 TU 已经用无 LEAN_AND_MEAN 的方式 #include <windows.h>，
// 则 <winver.h> 已在 TU 内存在。因此 .cpp 文件顶部的显式定义是关键。
// ─────────────────────────────────────────────────────────────────────────────
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// ShimVerLanguageName_Init
//   主动触发探测；建议在 DllMain DLL_PROCESS_ATTACH 中调用。
//   内部由 INIT_ONCE 保护，多次调用无副作用。
//   在 Loader Lock 内调用安全（见 shim_verlanguagename.cpp 注释）。
// ---------------------------------------------------------------------------
void ShimVerLanguageName_Init(void);

// ---------------------------------------------------------------------------
// VerLanguageNameA / VerLanguageNameW
//   替代原来的 KERNEL32 静态转发，在运行时动态路由到正确实现。
//   序号由 shim_verlanguagename.cpp 中的 linker pragma 固定为 @14 / @15。
// ---------------------------------------------------------------------------
DWORD WINAPI VerLanguageNameA(DWORD wLang, LPSTR  szLang, DWORD nSize);
DWORD WINAPI VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD nSize);

#ifdef __cplusplus
}
#endif
