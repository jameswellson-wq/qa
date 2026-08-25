// ─────────────────────────────────────────────────────────────────────────────
// WIN32_LEAN_AND_MEAN — 必须是翻译单元的第一条有效语句
// ─────────────────────────────────────────────────────────────────────────────
// 即使 shim_verlanguagename.h 已条件定义此宏，在 .cpp 中重复保证不会有副作用。
// 防御性写法：无论 include 顺序如何，都能保证 <windows.h> 以 lean 模式编译。
//
// 根因说明：
//   若缺少此宏，#include <windows.h> → #include <winver.h>（自动拉入）
//   winver.h 声明 WINBASEAPI DWORD WINAPI VerLanguageNameA(...) （dllimport）
//   本文件下方再定义同名函数（无 dllimport）→ C2375 redefinition; different linkage
//
#define WIN32_LEAN_AND_MEAN

//
// shim_verlanguagename.cpp
// VerLanguageNameA / W 运行时兼容 SHIM — 实现
//
// 替换 version.cpp 中已删除的两条静态 KERNEL32 转发：
//   删除: #pragma comment(linker, "/EXPORT:VerLanguageNameA=KERNEL32.VerLanguageNameA,@14")
//   删除: #pragma comment(linker, "/EXPORT:VerLanguageNameW=KERNEL32.VerLanguageNameW,@15")
//
// 导出机制重新设计：
//   ✗ 旧方案: /EXPORT pragma + __declspec(dllexport) 双写 → 潜在 LNK4197
//   ✓ 新方案: 由 version.def 统一声明 VerLanguageNameA @14 / VerLanguageNameW @15
//             本文件仅提供函数实现，不再涉及导出属性
//

#include <windows.h>
#include "shim_verlanguagename.h"

// ─────────────────────────────────────────────────────────────────────────────
// 序号导出：已迁移至 version.def
// ─────────────────────────────────────────────────────────────────────────────
// 原来的两条 pragma：
//   #pragma comment(linker, "/EXPORT:VerLanguageNameA,@14")   ← 已删除
//   #pragma comment(linker, "/EXPORT:VerLanguageNameW,@15")   ← 已删除
//
// version.def 中对应条目：
//   VerLanguageNameA  @14
//   VerLanguageNameW  @15
//
// 删除原因：
//   pragma + __declspec(dllexport) 同时存在是双重导出。
//   链接器若检测到同一符号被两种机制导出且 ordinal 一致，
//   会产生 LNK4197 警告。改用 .def 是 DLL proxy 项目的标准做法，
//   ordinal 管理集中在一处，易于维护和审查。

// ─────────────────────────────────────────────────────────────────────────────
// 函数指针类型
// ─────────────────────────────────────────────────────────────────────────────
typedef DWORD (WINAPI *pfnVerLanguageNameA_t)(DWORD wLang, LPSTR  szLang, DWORD nSize);
typedef DWORD (WINAPI *pfnVerLanguageNameW_t)(DWORD wLang, LPWSTR szLang, DWORD nSize);

// 解析后固定的目标函数指针（nullptr = 进入安全降级路径）
static pfnVerLanguageNameA_t s_pfnA = nullptr;
static pfnVerLanguageNameW_t s_pfnW = nullptr;

// INIT_ONCE 控制：全进程只做一次探测
static INIT_ONCE s_InitOnce = INIT_ONCE_STATIC_INIT;

// ─────────────────────────────────────────────────────────────────────────────
// 内部工具：安全加载系统 DLL
//   · 先 GetModuleHandle（零开销：已加载就不重复 Load）
//   · 再 LoadLibraryEx + LOAD_LIBRARY_SEARCH_SYSTEM32
//     （只搜系统目录，防止 DLL 劫持攻击我们自己）
// ─────────────────────────────────────────────────────────────────────────────
static HMODULE SafeLoadSystem(const wchar_t* dllName)
{
    HMODULE hMod = GetModuleHandleW(dllName);
    if (!hMod)
        hMod = LoadLibraryExW(dllName, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    return hMod;
}

// ─────────────────────────────────────────────────────────────────────────────
// INIT_ONCE 回调：按优先级逐级探测，找到即停
// ─────────────────────────────────────────────────────────────────────────────
static BOOL WINAPI ShimInitCallback(
    PINIT_ONCE  /*pInitOnce*/,
    PVOID       /*pParam*/,
    PVOID*      /*ppContext*/)
{
    // ── 探测配置表 ────────────────────────────────────────────────────────
    //   mustAlreadyBeLoaded = true  → 只用 GetModuleHandle，不主动加载
    //                                 (VERSION_SRC.dll 是代理 DLL 的依赖，
    //                                  若已加载则用它，否则跳过，不强制 Load)
    //   mustAlreadyBeLoaded = false → SafeLoadSystem（允许主动加载）
    // ─────────────────────────────────────────────────────────────────────
    struct Probe {
        const wchar_t* name;
        bool mustAlreadyBeLoaded;
    };

    static const Probe kProbes[] = {
        // 1. 真实 version.dll（Vista+ 起函数实现就在这里，最短路径）
        //    仅在已加载时使用；DLL_PROCESS_ATTACH 阶段可能尚未加载，安全跳过
        { L"VERSION_SRC.dll",  true  },
        { L"VERSION_SRC",      true  },   // 部分环境省略 .dll 后缀

        // 2. KERNEL32.dll — XP 兼容存根，所有真实 Windows 均已加载
        { L"KERNEL32.dll",     false },

        // 3. KERNELBASE.dll — Wine / 精简镜像 / 未来可能的实现位置
        { L"KERNELBASE.dll",   false },
    };

    for (const auto& p : kProbes)
    {
        HMODULE hMod = p.mustAlreadyBeLoaded
            ? GetModuleHandleW(p.name)
            : SafeLoadSystem(p.name);

        if (!hMod)
            continue;

        auto pfnA = reinterpret_cast<pfnVerLanguageNameA_t>(
            GetProcAddress(hMod, "VerLanguageNameA"));
        auto pfnW = reinterpret_cast<pfnVerLanguageNameW_t>(
            GetProcAddress(hMod, "VerLanguageNameW"));

        if (pfnA && pfnW)
        {
            // 两个都找到才算成功，避免出现 A 有 W 无的半残状态
            s_pfnA = pfnA;
            s_pfnW = pfnW;
            return TRUE;
        }
    }

    // 4. 完全找不到 → s_pfnA / s_pfnW 保持 nullptr → 安全降级路径
    //    注意：必须返回 TRUE；返回 FALSE 会导致 INIT_ONCE 进入失败状态，
    //    后续 InitOnceExecuteOnce 会反复重试，造成性能问题。
    return TRUE;
}

// ─────────────────────────────────────────────────────────────────────────────
// 公开 API：主动初始化（version.cpp DllMain 中调用）
// ─────────────────────────────────────────────────────────────────────────────
void ShimVerLanguageName_Init(void)
{
    PVOID pCtx = nullptr;
    InitOnceExecuteOnce(&s_InitOnce, ShimInitCallback, nullptr, &pCtx);
}

// 内部懒初始化宏：在导出函数入口处保证 INIT_ONCE 已执行
#define SHIM_ENSURE_INIT() \
    do { \
        PVOID _ctx = nullptr; \
        InitOnceExecuteOnce(&s_InitOnce, ShimInitCallback, nullptr, &_ctx); \
    } while (0)

// ─────────────────────────────────────────────────────────────────────────────
// 导出函数实现
// ─────────────────────────────────────────────────────────────────────────────
// 注意：此处不再使用 __declspec(dllexport)。
//       导出由 version.def 控制（VerLanguageNameA @14 / VerLanguageNameW @15）。
//       extern "C" 保留：确保链接器符号名为 C 风格（无 C++ 名称修饰），
//       与 .def 文件中的导出名称 "VerLanguageNameA" / "VerLanguageNameW" 精确匹配。

extern "C"
DWORD WINAPI VerLanguageNameA(DWORD wLang, LPSTR szLang, DWORD nSize)
{
    // 懒初始化：若 DllMain 中未提前调用 ShimVerLanguageName_Init()，
    // 此处仍可正确初始化（INIT_ONCE 保证幂等 + 线程安全）
    SHIM_ENSURE_INIT();

    if (s_pfnA)
        return s_pfnA(wLang, szLang, nSize);

    // ── 安全降级 ─────────────────────────────────────────────────────────
    // 所有探测路径均失败（Wine 极精简环境 / 未知未来系统）
    // 写空串：调用方不会读到垃圾内存
    // SetLastError：调用方可检测到失败
    // 返回 0：符合 MSDN 文档对失败情况的约定
    if (szLang && nSize > 0)
        szLang[0] = '\0';
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

extern "C"
DWORD WINAPI VerLanguageNameW(DWORD wLang, LPWSTR szLang, DWORD nSize)
{
    SHIM_ENSURE_INIT();

    if (s_pfnW)
        return s_pfnW(wLang, szLang, nSize);

    // 安全降级（宽字符版）
    if (szLang && nSize > 0)
        szLang[0] = L'\0';
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}
