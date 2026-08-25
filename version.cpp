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

// ── PE Forwarder 条目（@1~@13, @16~@17）→ VERSION_SRC.dll ────────────────
// MSVC 链接器不支持 .def 文件的 Forwarder 语法（Symbol = DLL.Symbol @N），
// 会把右侧当本地符号名解析 → LNK2001。
// 必须用 /EXPORT:Symbol=DLL.Symbol,@N 链接器选项，此处以 #pragma 注入。
// @14/@15（VerLanguageNameA/W）由 shim_verlanguagename.cpp 实现，序号在 version.def 声明。
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
#pragma comment(linker, "/EXPORT:VerQueryValueA=VERSION_SRC.VerQueryValueA,@16")
#pragma comment(linker, "/EXPORT:VerQueryValueW=VERSION_SRC.VerQueryValueW,@17")

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

            // SHIM 初始化保持同步：仅 GetModuleHandle + GetProcAddress，
            // 在 Loader Lock 下完全合法（KERNEL32/KERNELBASE 此时必然已加载）。
            ShimVerLanguageName_Init();

            // [FIX LOADER LOCK]
            // NsLoad() 可能执行 LoadLibrary / 网络请求 / 复杂线程同步。
            // DllMain 持有 Loader Lock 期间同步调用这些操作会死锁或崩溃。
            // 修复：CreateThread 把 NsLoad() 派发到 Loader Lock 之外执行。
            // MSDN 明确允许在 DllMain 里调用 CreateThread。
            // DllMain 立即返回 TRUE，不阻塞加载器；
            // NsLoad() 失败时在其内部实现重试 / 错误日志。
            {
                HANDLE hThread = CreateThread(
                    NULL, 0,
                    [](LPVOID) -> DWORD { NsLoad(); return 0; },
                    NULL, 0, NULL
                );
                if (hThread)
                    CloseHandle(hThread); // detached：线程自行退出
            }
            break;
        }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
