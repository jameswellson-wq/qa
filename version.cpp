// version.dll HiJack Project
// Caution: 
//   This project code is for testing purposes only! Please do not use it in any other way.
// Code By : Baymax Patch toOls 
//

// ── WIN32_LEAN_AND_MEAN（必须在所有 #include 之前）────────────────────────────
// 作用：阻止 <windows.h> 拉入 <winver.h>。
// 若缺少此宏，<winver.h> 会把 VerLanguageNameA/W 声明为 __declspec(dllimport)，
// 与 shim_verlanguagename.cpp 中的 __declspec(dllexport) 定义产生 C2375 冲突。
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shim_verlanguagename.h"   // VerLanguageNameA/W 运行时 SHIM（@14 / @15）


// ── 全局状态 ─────────────────────────────────────────────────────────────────
HMODULE g_hCurrentModule = NULL;
static  HANDLE  g_hNsLoadThread = NULL;  // DLL_PROCESS_DETACH 时关闭句柄用


// ── 静态 PE 转发条目（15 个函数直连 VERSION_SRC） ───────────────────────────
#pragma comment(linker, "/EXPORT:GetFileVersionInfoA=VERSION_SRC.GetFileVersionInfoA,@1")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoByHandle=VERSION_SRC.GetFileVersionInfoByHandle,@2")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExA=VERSION_SRC.GetFileVersionInfoExA,@3")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExW=VERSION_SRC.GetFileVersionInfoExW,@4")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeA=VERSION_SRC.GetFileVersionInfoSizeA,@5")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExA=VERSION_SRC.GetFileVersionInfoSizeExA,@6")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExW=VERSION_SRC.GetFileVersionInfoSizeExW,@7")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeW=VERSION_SRC.GetFileVersionInfoSizeW,@8")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoW=VERSION_SRC.GetFileVersionInfoW,@9")
#pragma comment(linker, "/EXPORT:VerFindFileA=VERSION_SRC.VerFindFileA,@10")
#pragma comment(linker, "/EXPORT:VerFindFileW=VERSION_SRC.VerFindFileW,@11")
#pragma comment(linker, "/EXPORT:VerInstallFileA=VERSION_SRC.VerInstallFileA,@12")
#pragma comment(linker, "/EXPORT:VerInstallFileW=VERSION_SRC.VerInstallFileW,@13")
// @14  VerLanguageNameA — shim_verlanguagename.cpp（运行时 4 级探测）
// @15  VerLanguageNameW — 同上
//      原静态转发 KERNEL32.VerLanguageNameA/W 已删除：
//      KERNEL32 存根是 XP 遗留，将来版本/Wine/精简 Windows 可能缺失，
//      缺失时 DLL 加载失败并报「找不到过程入口」。
#pragma comment(linker, "/EXPORT:VerQueryValueA=VERSION_SRC.VerQueryValueA,@16")
#pragma comment(linker, "/EXPORT:VerQueryValueW=VERSION_SRC.VerQueryValueW,@17")


// ─────────────────────────────────────────────────────────────────────────────
// NsLoad — 用户自定义初始化 / payload
//
// ★ 此函数在独立线程中调用（DllMain 已返回、Loader Lock 已释放）。
//   可以安全地执行任意复杂操作，包括但不限于：
//     · LoadLibrary / LoadLibraryEx（任意 DLL）
//     · WinHTTP / WinSock 网络请求
//     · CreateThread / WaitForSingleObject / 互斥体
//     · CoCreateInstance（COM 初始化）
//     · 任意同步或异步 I/O
//
// ★ 此函数的返回值不再影响 DllMain 的返回值。
//   代理 DLL 的透传职能（17 个导出函数的转发 + SHIM）不依赖 NsLoad 成功。
//   若需要在 NsLoad 失败时记录日志，在函数内部处理即可。
// ─────────────────────────────────────────────────────────────────────────────
static BOOL NsLoad()
{
    // ── 在此填写真正的 payload ────────────────────────────────────────────

    return TRUE;
}


// ─────────────────────────────────────────────────────────────────────────────
// 异步载荷线程入口
//
// 设计要点：
//   · CreateThread 在 DLL_PROCESS_ATTACH 中是 Windows 明确允许的操作
//   · 线程开始执行用户代码之前，DllMain 必须已返回（Windows 内部保证）
//   · 因此线程内任何操作都不受 Loader Lock 约束
// ─────────────────────────────────────────────────────────────────────────────
static DWORD WINAPI NsLoadThread(LPVOID /*lpParam*/)
{
    NsLoad();
    return 0;
}


// ─────────────────────────────────────────────────────────────────────────────
// DllMain
// ─────────────────────────────────────────────────────────────────────────────
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    // ── DLL 加载 ──────────────────────────────────────────────────────────
    case DLL_PROCESS_ATTACH:
    {
        g_hCurrentModule = hModule;
        DisableThreadLibraryCalls(hModule);     // 不需要线程通知

        // ── SHIM 提前初始化（在 Loader Lock 内安全）────────────────────
        // 安全理由：
        //   1. GetModuleHandleW 是只读查询，不需要 Loader Lock
        //   2. KERNEL32 / KERNELBASE 在 DllMain 执行时必定已加载；
        //      SafeLoadSystem 内 GetModuleHandleW 成功 →
        //      LoadLibraryExW 永远不会被调用
        //   3. VERSION_SRC.dll 若未加载，mustAlreadyBeLoaded=true 直接跳过
        //   4. INIT_ONCE 使用原子 CAS，不持有 Loader Lock
        ShimVerLanguageName_Init();

        // ── NsLoad 异步化，彻底规避 Loader Lock ────────────────────────
        //
        // 【旧代码的问题】
        //   if (!NsLoad()) return FALSE;
        //   NsLoad 在 Loader Lock 保护下同步执行：
        //     · 内部调用 LoadLibrary  → 尝试获取 Loader Lock → 已被当前
        //       线程持有 → 死锁（WaitForSingleObjectEx 无限等待）
        //     · 内部等待其他线程      → 若对方线程也在等 DLL 加载 → 死锁
        //     · 内部发起网络请求      → WinHTTP 内部加载辅助 DLL → 同上
        //
        // 【解法】CreateThread（DllMain 内合法）→ 线程里跑 NsLoad
        //   线程真正执行用户代码时，DllMain 已返回，Loader Lock 已释放。
        //   保存句柄用于 DLL_PROCESS_DETACH 路径的正常关闭。
        g_hNsLoadThread = CreateThread(
            NULL,           // 默认安全属性
            0,              // 默认栈大小
            NsLoadThread,   // 线程函数
            NULL,           // 参数（如需传 hModule 可改为 hModule）
            0,              // 立即运行
            NULL            // 不需要线程 ID
        );
        // CreateThread 失败时 g_hNsLoadThread = NULL；
        // DLL_PROCESS_DETACH 中的 NULL 检查保证安全。

        // ★ 始终返回 TRUE：代理透传能力不依赖 NsLoad 成功。
        break;
    }

    // ── DLL 卸载 ──────────────────────────────────────────────────────────
    case DLL_PROCESS_DETACH:
    {
        // lpReserved != NULL：进程退出（ExitProcess / main 返回）
        //   → 什么都不做。此时 Loader Lock 状态不确定，内核会回收所有资源；
        //      在此调用 WaitForSingleObject 极易死锁。
        //
        // lpReserved == NULL：FreeLibrary 正常卸载
        //   → 仅关闭线程句柄。
        //   → 注意：此路径下 Loader Lock 仍被持有，
        //      禁止调用 WaitForSingleObject（若 NsLoad 线程内有 LoadLibrary
        //      则两者死锁）。
        //   → NsLoad 定位为短生命周期初始化线程，预期早已退出；
        //      直接 CloseHandle 安全。
        //      若 NsLoad 被改造为长期运行的服务线程，需在此额外设置
        //      停止事件（CreateEvent + SetEvent）并在 NsLoad 内轮询。
        if (lpReserved == NULL && g_hNsLoadThread != NULL)
        {
            CloseHandle(g_hNsLoadThread);
            g_hNsLoadThread = NULL;
        }
        break;
    }

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
