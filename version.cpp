// version.dll HiJack Project
// Caution: 
//   This project code is for testing purposes only! Please do not use it in any other way.
// Code By : Baymax Patch toOls 
//

#include <windows.h>
#include "shim_verlanguagename.h"   // VerLanguageNameA/W 运行时 SHIM（替代 KERNEL32 静态转发）

HMODULE g_hCurrentModule = NULL;


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
// @14  VerLanguageNameA — 已移入 shim_verlanguagename.cpp（运行时 4 级探测）
// @15  VerLanguageNameW — 同上
//      原来的写法："/EXPORT:VerLanguageNameA=KERNEL32.VerLanguageNameA,@14"
//      问题：KERNEL32 存根是 XP 兼容遗留，未来版本 / Wine 可能缺失，
//             DLL 加载时报"找不到过程入口"导致进程崩溃。
#pragma comment(linker, "/EXPORT:VerQueryValueA=VERSION_SRC.VerQueryValueA,@16")
#pragma comment(linker, "/EXPORT:VerQueryValueW=VERSION_SRC.VerQueryValueW,@17")


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
