// version.dll HiJack Project
// Caution: 
//   This project code is for testing purposes only! Please do not use it in any other way.
// Code By : Baymax Patch toOls 
//

#include <windows.h>
HMODULE g_hCurrentModule = NULL;


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
#pragma comment(linker, "/EXPORT:VerLanguageNameA=KERNEL32.VerLanguageNameA,@14")
#pragma comment(linker, "/EXPORT:VerLanguageNameW=KERNEL32.VerLanguageNameW,@15")
#pragma comment(linker, "/EXPORT:VerQueryValueA=VERSION_SRC.VerQueryValueA,@16")
#pragma comment(linker, "/EXPORT:VerQueryValueW=VERSION_SRC.VerQueryValueW,@17")


BOOL NsLoad()
{
    return TRUE;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved
                      )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        {
            g_hCurrentModule = hModule;
            DisableThreadLibraryCalls(hModule);
            if ( !NsLoad() )
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

