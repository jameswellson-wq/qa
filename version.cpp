// version.dll HiJack Project
// Caution:
//   This project code is for testing purposes only! Please do not use it in any other way.
// Code By : Baymax Patch toOls
//

// ── WIN32_LEAN_AND_MEAN 必须在第一个 #include 之前 ─────────────────────────
// 作用：阻断 <windows.h> 对 <winver.h> 的自动拉入。
// <winver.h> 会把 VerLanguageNameA/W 声明为 __declspec(dllimport)，
// 与 shim_verlanguagename.h 中的声明冲突，触发 C4273。
// 此宏必须先于任何 SDK 头文件定义，否则 windows.h 内部 include 卫士已处理，
// 宏定义晚了就不起作用。
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shim_verlanguagename.h"   // VerLanguageNameA/W 运行时 SHIM

// ── 导出表已全部移入 version.def ──────────────────────────────────────────
// 原来在此处的 15 条 /EXPORT pragma（@1~@13, @16~@17）统一由 version.def 管理。
// 链接器通过 /DEF:version.def 读取所有导出定义，包含 Forwarder 条目和 SHIM 序号。
// 好处：
//   · 单一真实来源，ordinal 修改只在 .def 进行
//   · 彻底消除与 __declspec(dllexport) 混用时的 LNK4197 双重导出警告
//   · .def 文件格式更易审查和 diff

HMODULE g_hCurrentModule = NULL;


BOOL NsLoad()
{
    return TRUE;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD   ul_reason_for_call,
                       LPVOID  lpReserved
                       )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        {
            g_hCurrentModule = hModule;
            DisableThreadLibraryCalls(hModule);

            // 提前初始化 VerLanguageNameA/W SHIM
            // · 在此时机探测 KERNEL32 / KERNELBASE（肯定已加载）
            // · VERSION_SRC.dll 若已加载也会被优先使用
            // · INIT_ONCE 保证线程安全，重复调用无副作用
            ShimVerLanguageName_Init();

            if (!NsLoad())
                return FALSE;
            break;
        }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
