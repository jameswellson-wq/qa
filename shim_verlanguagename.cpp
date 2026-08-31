// =============================================================================
// shim_verlanguagename.cpp  ── v2 重构
//
// 修复缺陷：
//   Defect 1 ─ DllMain / Loader Lock 下的 SafeLoadSystem 死锁风险
//   Defect 2 ─ INIT_ONCE 将"降级结果"永久固化，VERSION_SRC 加载后无法升级
//   Defect 3 ─ SHIM_ENSURE_INIT 无质量感知，错过升级到最优路径的机会
//
// 新架构（两阶段初始化）：
//   阶段 1 ─ BaseInit（INIT_ONCE 保护，首次导出调用时触发）
//             仅探测 KERNEL32 / KERNELBASE，必然成功；
//             不在 DllMain 中调用，彻底脱离 Loader Lock。
//   阶段 2 ─ TryUpgradeToSrc（无锁原子，每次导出调用均执行，O(1) 开销）
//             轻量探测 VERSION_SRC（仅 GetModuleHandle + GetProcAddress）；
//             一旦找到，原子写入最优指针并设置标志，后续调用直走快速路径。
// =============================================================================
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include "shim_verlanguagename.h"

typedef DWORD (WINAPI *pfnVerLanguageNameA_t)(DWORD wLang, LPSTR  szLang, DWORD nSize);
typedef DWORD (WINAPI *pfnVerLanguageNameW_t)(DWORD wLang, LPWSTR szLang, DWORD nSize);

// ─────────────────────────────────────────────────────────────────────────────
// 阶段 1：基础 fallback（KERNEL32 / KERNELBASE）
// ─────────────────────────────────────────────────────────────────────────────
// INIT_ONCE 保护，全进程执行一次。
// DllMain 不再调用 Init，此回调仅在首次导出函数调用时触发，
// 确保完全脱离 Loader Lock 上下文。
static INIT_ONCE             s_BaseOnce  = INIT_ONCE_STATIC_INIT;
static pfnVerLanguageNameA_t s_pfnA_base = nullptr;  // KERNEL32 / KERNELBASE fallback
static pfnVerLanguageNameW_t s_pfnW_base = nullptr;
static HMODULE               s_hOwned    = nullptr;  // LoadLibraryExW 时需 FreeLibrary

// ─────────────────────────────────────────────────────────────────────────────
// 阶段 2：最优路径（VERSION_SRC）
// ─────────────────────────────────────────────────────────────────────────────
// 【修复 Defect 2 + 3】
// 不再受 INIT_ONCE 约束。每次导出调用轻量检查一次 s_optimal；
// 找到 VERSION_SRC 后原子升级，后续调用仅读一个原子变量（O(1)，无任何锁）。
static volatile LONG         s_optimal   = 0;        // 0=fallback, 1=VERSION_SRC 就绪
static pfnVerLanguageNameA_t s_pfnA_opt  = nullptr;  // VERSION_SRC 最优指针
static pfnVerLanguageNameW_t s_pfnW_opt  = nullptr;

// ─────────────────────────────────────────────────────────────────────────────
// SafeLoadSystem（语义与旧版相同）
// ─────────────────────────────────────────────────────────────────────────────
static HMODULE SafeLoadSystem(const wchar_t* dllName, bool* pbOwned)
{
    *pbOwned = false;
    HMODULE h = GetModuleHandleW(dllName);
    if (!h)
    {
        h = LoadLibraryExW(dllName, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (h) *pbOwned = true;
    }
    return h;
}

// ─────────────────────────────────────────────────────────────────────────────
// BaseInitCallback ── 阶段 1 回调
// ─────────────────────────────────────────────────────────────────────────────
// 只探测 KERNEL32 / KERNELBASE，不再处理 VERSION_SRC。
// VERSION_SRC 交由 TryUpgradeToSrc() 在每次导出调用时处理。
//
// 【修复 Defect 1 原理】
//   即使 SafeLoadSystem 的 LoadLibraryExW 分支在 Wine/精简系统上触发，
//   此回调已脱离 DllMain（Loader Lock 已释放），不存在死锁风险。
//   而在完整 Windows 上，KERNEL32 必然已加载，GetModuleHandle 直接命中，
//   LoadLibraryExW 分支根本不会执行。
// ─────────────────────────────────────────────────────────────────────────────
static BOOL WINAPI BaseInitCallback(PINIT_ONCE, PVOID, PVOID*)
{
    const wchar_t* kCandidates[] = { L"KERNEL32.dll", L"KERNELBASE.dll" };

    for (auto dll : kCandidates)
    {
        bool bOwned = false;
        HMODULE h = SafeLoadSystem(dll, &bOwned);
        if (!h) continue;

        auto pA = reinterpret_cast<pfnVerLanguageNameA_t>(
            GetProcAddress(h, "VerLanguageNameA"));
        auto pW = reinterpret_cast<pfnVerLanguageNameW_t>(
            GetProcAddress(h, "VerLanguageNameW"));

        if (pA && pW)
        {
            s_pfnA_base = pA;
            s_pfnW_base = pW;
            if (bOwned) s_hOwned = h;
            return TRUE;
        }
        if (bOwned) FreeLibrary(h);
    }
    // 两个候选都失败 → 安全降级路径
    // 必须返回 TRUE；返回 FALSE 使 INIT_ONCE 进入失败重试模式（性能问题）
    return TRUE;
}

// ─────────────────────────────────────────────────────────────────────────────
// TryUpgradeToSrc ── 阶段 2 无锁升级探测
// ─────────────────────────────────────────────────────────────────────────────
// 【修复 Defect 2 + 3 原理】
//   旧 INIT_ONCE 方案问题：
//     t=0  DllMain → ShimInit → VERSION_SRC 未加载 → 固化为 KERNEL32 fallback
//     t=1  VERSION_SRC 加载完毕（PE Forwarder 机制）
//     t=2  应用调用 VerLanguageNameA → INIT_ONCE 已完成 → 永远用 KERNEL32 ← ⚠
//
//   新方案：
//     s_optimal 初始为 0；每次导出调用读 s_optimal：
//       · 为 1 → InterlockedCompareExchange 快速退出，直接使用 s_pfnA/W_opt
//       · 为 0 → GetModuleHandle("VERSION_SRC.dll")（纯用户态，无 Loader Lock 风险）
//               找到 → 原子写入指针 → InterlockedExchange(&s_optimal, 1)
//               未找到 → 返回，继续用 fallback，下次调用再试
//
// 内存序保证（x86/x64）：
//   InterlockedExchangePointer 使用 LOCK XCHG（完整内存屏障）。
//   先写两个函数指针（各带屏障），再写 s_optimal=1（带屏障）。
//   读方若看到 s_optimal=1，一定能看到已写入的 s_pfnA/W_opt。
// ─────────────────────────────────────────────────────────────────────────────
static void TryUpgradeToSrc()
{
    // 快速路径：已升级，原子读后直接返回
    if (InterlockedCompareExchange(&s_optimal, 0, 0) == 1) return;

    // GetModuleHandle 只查已加载模块，不触发加载，完全 Loader Lock 安全
    HMODULE h = GetModuleHandleW(L"VERSION_SRC.dll");
    if (!h) h = GetModuleHandleW(L"VERSION_SRC");  // 部分环境省略 .dll 后缀
    if (!h) return;                                 // 尚未加载，本次跳过，下次再探

    auto pA = reinterpret_cast<pfnVerLanguageNameA_t>(
        GetProcAddress(h, "VerLanguageNameA"));
    auto pW = reinterpret_cast<pfnVerLanguageNameW_t>(
        GetProcAddress(h, "VerLanguageNameW"));
    if (!pA || !pW) return;  // 模块存在但函数缺失（不完整 VERSION_SRC），跳过

    // 发布顺序：先写函数指针（带屏障），再置标志（带屏障）
    // 多线程并发时可能多次写入，但写入值相同，幂等安全
    InterlockedExchangePointer(
        reinterpret_cast<PVOID*>(&s_pfnA_opt), reinterpret_cast<PVOID>(pA));
    InterlockedExchangePointer(
        reinterpret_cast<PVOID*>(&s_pfnW_opt), reinterpret_cast<PVOID>(pW));
    InterlockedExchange(&s_optimal, 1);  // 发布屏障：读方看到 1 即可安全使用 opt 指针
}

// ─────────────────────────────────────────────────────────────────────────────
// SHIM_ENSURE_INIT ── 两阶段初始化入口（更新后）
// ─────────────────────────────────────────────────────────────────────────────
// 稳态性能：
//   · InitOnceExecuteOnce → 已完成时内部仅读一个标志，O(1)
//   · TryUpgradeToSrc     → s_optimal=1 后仅一次 InterlockedCompareExchange，O(1)
//   两者在 VERSION_SRC 找到后共同构成接近零开销的热路径
// ─────────────────────────────────────────────────────────────────────────────
#define SHIM_ENSURE_INIT()                                                      \
    do {                                                                        \
        PVOID _ctx = nullptr;                                                   \
        InitOnceExecuteOnce(&s_BaseOnce, BaseInitCallback, nullptr, &_ctx);     \
        TryUpgradeToSrc();                                                      \
    } while (0)

// ─────────────────────────────────────────────────────────────────────────────
// 公开 API
// ─────────────────────────────────────────────────────────────────────────────

// 【行为变更】
//   旧：DllMain DLL_PROCESS_ATTACH 中同步调用（Loader Lock 持有期间）
//   新：DllMain 中不再调用。接口保留供以下场景：
//       · 显式要求在首次导出调用之前完成基础探测（非 DllMain 上下文）
//       · 单元测试主动触发初始化
//   INIT_ONCE 保护，多次调用无副作用。
void ShimVerLanguageName_Init(void)
{
    PVOID _ctx = nullptr;
    InitOnceExecuteOnce(&s_BaseOnce, BaseInitCallback, nullptr, &_ctx);
    TryUpgradeToSrc();
}

// 释放 LoadLibraryExW 引入的额外引用计数（Load/Free 配对）
// InterlockedExchangePointer 保证多次调用幂等
void ShimVerLanguageName_Cleanup(void)
{
    HMODULE h = static_cast<HMODULE>(
        InterlockedExchangePointer(
            reinterpret_cast<PVOID*>(&s_hOwned), nullptr));
    if (h) FreeLibrary(h);
}

// ─────────────────────────────────────────────────────────────────────────────
// 导出函数实现（序号由 version.def 统一管理：@14 / @15）
// ─────────────────────────────────────────────────────────────────────────────
// 调用优先级：
//   1. VERSION_SRC（最优，直接调用真实实现）
//   2. KERNEL32 / KERNELBASE（fallback，可靠兼容）
//   3. 安全降级（全部失败时，写空串 + 错误码 + 返回 0）
// ─────────────────────────────────────────────────────────────────────────────

extern "C"
DWORD WINAPI VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD nSize)
{
    SHIM_ENSURE_INIT();

    if (s_pfnA_opt)  return s_pfnA_opt (wLang, szLang, nSize);  // 最优路径
    if (s_pfnA_base) return s_pfnA_base(wLang, szLang, nSize);  // fallback

    if (szLang && nSize > 0) szLang[0] = '\0';
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

extern "C"
DWORD WINAPI VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD nSize)
{
    SHIM_ENSURE_INIT();

    if (s_pfnW_opt)  return s_pfnW_opt (wLang, szLang, nSize);
    if (s_pfnW_base) return s_pfnW_base(wLang, szLang, nSize);

    if (szLang && nSize > 0) szLang[0] = L'\0';
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}
