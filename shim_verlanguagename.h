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
// WIN32_LEAN_AND_MEAN 保护（关键！）
// ─────────────────────────────────────────────────────────────────────────────
//   若不定义 WIN32_LEAN_AND_MEAN，<windows.h> 会自动拉入 <winver.h>。
//   <winver.h> 将 VerLanguageNameA/W 声明为 WINBASEAPI（即 __declspec(dllimport)）：
//
//     WINBASEAPI DWORD WINAPI VerLanguageNameA(DWORD, LPSTR, UINT);
//     WINBASEAPI DWORD WINAPI VerLanguageNameW(DWORD, LPWSTR, UINT);
//
//   而 shim_verlanguagename.cpp 中的函数定义没有 dllimport 属性，
//   两者在同一翻译单元内共存 → C2375 redefinition; different linkage
//                                 / C4273 inconsistent dll linkage
//
//   修复：本头文件在包含 <windows.h> 前强制定义 WIN32_LEAN_AND_MEAN，
//   阻断对 <winver.h> 的拉入，从根本上消除冲突。
//
// ─────────────────────────────────────────────────────────────────────────────
// SHIM 策略（运行时按优先级逐级探测）
// ─────────────────────────────────────────────────────────────────────────────
//   1. VERSION_SRC.dll  — 重命名后的真实 version.dll
//                          Vista+ 起函数的真实实现就在这里；
//                          若已加载（应用首次调用其他 version 函数后），优先使用。
//   2. KERNEL32.dll     — XP 兼容存根，Win7～Win11 均保留，最可靠的后备
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
// 导出机制
// ─────────────────────────────────────────────────────────────────────────────
//   序号 @14/@15 统一在 version.def 中声明，本文件和 .cpp 均不再使用
//   /EXPORT pragma 或 __declspec(dllexport)。
//   · 消除双重导出（pragma + dllexport 同时存在的 LNK4197 风险）
//   · 所有导出的单一真实来源在 version.def
//
// ─────────────────────────────────────────────────────────────────────────────
// 使用方式
// ─────────────────────────────────────────────────────────────────────────────
//   1. 在 version.cpp DllMain → DLL_PROCESS_ATTACH 中调用 ShimVerLanguageName_Init()
//      （可选，但推荐：提前探测，避免首次调用的微小延迟）
//   2. 确保 version.def 中包含 VerLanguageNameA @14 / VerLanguageNameW @15
//   3. 把 shim_verlanguagename.cpp 加入 vcxproj 源文件列表
//   4. vcxproj Link 节点设置 ModuleDefinitionFile = version.def
//

// ── WIN32_LEAN_AND_MEAN 保护 ─────────────────────────────────────────────────
// 条件定义：若调用者已定义则不覆盖，若未定义则在此处补充定义。
// 必须在第一个 #include <windows.h> 之前生效。
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// ShimVerLanguageName_Init
//   主动触发探测；建议在 DllMain DLL_PROCESS_ATTACH 中调用。
//   内部由 INIT_ONCE 保护，多次调用无副作用。
// ---------------------------------------------------------------------------
void ShimVerLanguageName_Init(void);

// ---------------------------------------------------------------------------
// VerLanguageNameA / VerLanguageNameW
//   替代原来的 KERNEL32 静态转发，在运行时动态路由到正确实现。
//   序号 @14 / @15 由 version.def 统一指定，此处声明无 dllimport/dllexport。
// ---------------------------------------------------------------------------
DWORD WINAPI VerLanguageNameA(DWORD wLang, LPSTR  szLang, DWORD nSize);
DWORD WINAPI VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD nSize);

#ifdef __cplusplus
}
#endif
