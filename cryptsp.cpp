
//
// created by AheadLibEx
// Author:i1tao
// Blog:https://www.cnblogs.com/0xc5
// Github:https://github.com/i1tao/AheadLibEx
// 

#include <windows.h>
#include <Shlwapi.h>

#pragma comment( lib, "Shlwapi.lib")

#pragma comment(linker, "/EXPORT:CheckSignatureInFile=AheadLibEx_CheckSignatureInFile,@1")
#pragma comment(linker, "/EXPORT:CryptAcquireContextA=AheadLibEx_CryptAcquireContextA,@2")
#pragma comment(linker, "/EXPORT:CryptAcquireContextW=AheadLibEx_CryptAcquireContextW,@3")
#pragma comment(linker, "/EXPORT:CryptContextAddRef=AheadLibEx_CryptContextAddRef,@4")
#pragma comment(linker, "/EXPORT:CryptCreateHash=AheadLibEx_CryptCreateHash,@5")
#pragma comment(linker, "/EXPORT:CryptDecrypt=AheadLibEx_CryptDecrypt,@6")
#pragma comment(linker, "/EXPORT:CryptDeriveKey=AheadLibEx_CryptDeriveKey,@7")
#pragma comment(linker, "/EXPORT:CryptDestroyHash=AheadLibEx_CryptDestroyHash,@8")
#pragma comment(linker, "/EXPORT:CryptDestroyKey=AheadLibEx_CryptDestroyKey,@9")
#pragma comment(linker, "/EXPORT:CryptDuplicateHash=AheadLibEx_CryptDuplicateHash,@10")
#pragma comment(linker, "/EXPORT:CryptDuplicateKey=AheadLibEx_CryptDuplicateKey,@11")
#pragma comment(linker, "/EXPORT:CryptEncrypt=AheadLibEx_CryptEncrypt,@12")
#pragma comment(linker, "/EXPORT:CryptEnumProviderTypesA=AheadLibEx_CryptEnumProviderTypesA,@13")
#pragma comment(linker, "/EXPORT:CryptEnumProviderTypesW=AheadLibEx_CryptEnumProviderTypesW,@14")
#pragma comment(linker, "/EXPORT:CryptEnumProvidersA=AheadLibEx_CryptEnumProvidersA,@15")
#pragma comment(linker, "/EXPORT:CryptEnumProvidersW=AheadLibEx_CryptEnumProvidersW,@16")
#pragma comment(linker, "/EXPORT:CryptExportKey=AheadLibEx_CryptExportKey,@17")
#pragma comment(linker, "/EXPORT:CryptGenKey=AheadLibEx_CryptGenKey,@18")
#pragma comment(linker, "/EXPORT:CryptGenRandom=AheadLibEx_CryptGenRandom,@19")
#pragma comment(linker, "/EXPORT:CryptGetDefaultProviderA=AheadLibEx_CryptGetDefaultProviderA,@20")
#pragma comment(linker, "/EXPORT:CryptGetDefaultProviderW=AheadLibEx_CryptGetDefaultProviderW,@21")
#pragma comment(linker, "/EXPORT:CryptGetHashParam=AheadLibEx_CryptGetHashParam,@22")
#pragma comment(linker, "/EXPORT:CryptGetKeyParam=AheadLibEx_CryptGetKeyParam,@23")
#pragma comment(linker, "/EXPORT:CryptGetProvParam=AheadLibEx_CryptGetProvParam,@24")
#pragma comment(linker, "/EXPORT:CryptGetUserKey=AheadLibEx_CryptGetUserKey,@25")
#pragma comment(linker, "/EXPORT:CryptHashData=AheadLibEx_CryptHashData,@26")
#pragma comment(linker, "/EXPORT:CryptHashSessionKey=AheadLibEx_CryptHashSessionKey,@27")
#pragma comment(linker, "/EXPORT:CryptImportKey=AheadLibEx_CryptImportKey,@28")
#pragma comment(linker, "/EXPORT:CryptReleaseContext=AheadLibEx_CryptReleaseContext,@29")
#pragma comment(linker, "/EXPORT:CryptSetHashParam=AheadLibEx_CryptSetHashParam,@30")
#pragma comment(linker, "/EXPORT:CryptSetKeyParam=AheadLibEx_CryptSetKeyParam,@31")
#pragma comment(linker, "/EXPORT:CryptSetProvParam=AheadLibEx_CryptSetProvParam,@32")
#pragma comment(linker, "/EXPORT:CryptSetProviderA=AheadLibEx_CryptSetProviderA,@33")
#pragma comment(linker, "/EXPORT:CryptSetProviderExA=AheadLibEx_CryptSetProviderExA,@34")
#pragma comment(linker, "/EXPORT:CryptSetProviderExW=AheadLibEx_CryptSetProviderExW,@35")
#pragma comment(linker, "/EXPORT:CryptSetProviderW=AheadLibEx_CryptSetProviderW,@36")
#pragma comment(linker, "/EXPORT:CryptSignHashA=AheadLibEx_CryptSignHashA,@37")
#pragma comment(linker, "/EXPORT:CryptSignHashW=AheadLibEx_CryptSignHashW,@38")
#pragma comment(linker, "/EXPORT:CryptVerifySignatureA=AheadLibEx_CryptVerifySignatureA,@39")
#pragma comment(linker, "/EXPORT:CryptVerifySignatureW=AheadLibEx_CryptVerifySignatureW,@40")
#pragma comment(linker, "/EXPORT:SystemFunction006=AheadLibEx_SystemFunction006,@41")
#pragma comment(linker, "/EXPORT:SystemFunction007=AheadLibEx_SystemFunction007,@42")
#pragma comment(linker, "/EXPORT:SystemFunction008=AheadLibEx_SystemFunction008,@43")
#pragma comment(linker, "/EXPORT:SystemFunction009=AheadLibEx_SystemFunction009,@44")
#pragma comment(linker, "/EXPORT:SystemFunction010=AheadLibEx_SystemFunction010,@45")
#pragma comment(linker, "/EXPORT:SystemFunction011=AheadLibEx_SystemFunction011,@46")
#pragma comment(linker, "/EXPORT:SystemFunction012=AheadLibEx_SystemFunction012,@47")
#pragma comment(linker, "/EXPORT:SystemFunction013=AheadLibEx_SystemFunction013,@48")
#pragma comment(linker, "/EXPORT:SystemFunction014=AheadLibEx_SystemFunction014,@49")
#pragma comment(linker, "/EXPORT:SystemFunction015=AheadLibEx_SystemFunction015,@50")
#pragma comment(linker, "/EXPORT:SystemFunction016=AheadLibEx_SystemFunction016,@51")
#pragma comment(linker, "/EXPORT:SystemFunction018=AheadLibEx_SystemFunction018,@52")
#pragma comment(linker, "/EXPORT:SystemFunction020=AheadLibEx_SystemFunction020,@53")
#pragma comment(linker, "/EXPORT:SystemFunction021=AheadLibEx_SystemFunction021,@54")
#pragma comment(linker, "/EXPORT:SystemFunction022=AheadLibEx_SystemFunction022,@55")
#pragma comment(linker, "/EXPORT:SystemFunction023=AheadLibEx_SystemFunction023,@56")
#pragma comment(linker, "/EXPORT:SystemFunction024=AheadLibEx_SystemFunction024,@57")
#pragma comment(linker, "/EXPORT:SystemFunction025=AheadLibEx_SystemFunction025,@58")
#pragma comment(linker, "/EXPORT:SystemFunction026=AheadLibEx_SystemFunction026,@59")
#pragma comment(linker, "/EXPORT:SystemFunction027=AheadLibEx_SystemFunction027,@60")
#pragma comment(linker, "/EXPORT:SystemFunction030=AheadLibEx_SystemFunction030,@61")
#pragma comment(linker, "/EXPORT:SystemFunction031=AheadLibEx_SystemFunction031,@62")
#pragma comment(linker, "/EXPORT:SystemFunction032=AheadLibEx_SystemFunction032,@63")
#pragma comment(linker, "/EXPORT:SystemFunction033=AheadLibEx_SystemFunction033,@64")
#pragma comment(linker, "/EXPORT:SystemFunction035=AheadLibEx_SystemFunction035,@65")


extern "C"
{
	PVOID pfnAheadLibEx_CheckSignatureInFile;
	PVOID pfnAheadLibEx_CryptAcquireContextA;
	PVOID pfnAheadLibEx_CryptAcquireContextW;
	PVOID pfnAheadLibEx_CryptContextAddRef;
	PVOID pfnAheadLibEx_CryptCreateHash;
	PVOID pfnAheadLibEx_CryptDecrypt;
	PVOID pfnAheadLibEx_CryptDeriveKey;
	PVOID pfnAheadLibEx_CryptDestroyHash;
	PVOID pfnAheadLibEx_CryptDestroyKey;
	PVOID pfnAheadLibEx_CryptDuplicateHash;
	PVOID pfnAheadLibEx_CryptDuplicateKey;
	PVOID pfnAheadLibEx_CryptEncrypt;
	PVOID pfnAheadLibEx_CryptEnumProviderTypesA;
	PVOID pfnAheadLibEx_CryptEnumProviderTypesW;
	PVOID pfnAheadLibEx_CryptEnumProvidersA;
	PVOID pfnAheadLibEx_CryptEnumProvidersW;
	PVOID pfnAheadLibEx_CryptExportKey;
	PVOID pfnAheadLibEx_CryptGenKey;
	PVOID pfnAheadLibEx_CryptGenRandom;
	PVOID pfnAheadLibEx_CryptGetDefaultProviderA;
	PVOID pfnAheadLibEx_CryptGetDefaultProviderW;
	PVOID pfnAheadLibEx_CryptGetHashParam;
	PVOID pfnAheadLibEx_CryptGetKeyParam;
	PVOID pfnAheadLibEx_CryptGetProvParam;
	PVOID pfnAheadLibEx_CryptGetUserKey;
	PVOID pfnAheadLibEx_CryptHashData;
	PVOID pfnAheadLibEx_CryptHashSessionKey;
	PVOID pfnAheadLibEx_CryptImportKey;
	PVOID pfnAheadLibEx_CryptReleaseContext;
	PVOID pfnAheadLibEx_CryptSetHashParam;
	PVOID pfnAheadLibEx_CryptSetKeyParam;
	PVOID pfnAheadLibEx_CryptSetProvParam;
	PVOID pfnAheadLibEx_CryptSetProviderA;
	PVOID pfnAheadLibEx_CryptSetProviderExA;
	PVOID pfnAheadLibEx_CryptSetProviderExW;
	PVOID pfnAheadLibEx_CryptSetProviderW;
	PVOID pfnAheadLibEx_CryptSignHashA;
	PVOID pfnAheadLibEx_CryptSignHashW;
	PVOID pfnAheadLibEx_CryptVerifySignatureA;
	PVOID pfnAheadLibEx_CryptVerifySignatureW;
	PVOID pfnAheadLibEx_SystemFunction006;
	PVOID pfnAheadLibEx_SystemFunction007;
	PVOID pfnAheadLibEx_SystemFunction008;
	PVOID pfnAheadLibEx_SystemFunction009;
	PVOID pfnAheadLibEx_SystemFunction010;
	PVOID pfnAheadLibEx_SystemFunction011;
	PVOID pfnAheadLibEx_SystemFunction012;
	PVOID pfnAheadLibEx_SystemFunction013;
	PVOID pfnAheadLibEx_SystemFunction014;
	PVOID pfnAheadLibEx_SystemFunction015;
	PVOID pfnAheadLibEx_SystemFunction016;
	PVOID pfnAheadLibEx_SystemFunction018;
	PVOID pfnAheadLibEx_SystemFunction020;
	PVOID pfnAheadLibEx_SystemFunction021;
	PVOID pfnAheadLibEx_SystemFunction022;
	PVOID pfnAheadLibEx_SystemFunction023;
	PVOID pfnAheadLibEx_SystemFunction024;
	PVOID pfnAheadLibEx_SystemFunction025;
	PVOID pfnAheadLibEx_SystemFunction026;
	PVOID pfnAheadLibEx_SystemFunction027;
	PVOID pfnAheadLibEx_SystemFunction030;
	PVOID pfnAheadLibEx_SystemFunction031;
	PVOID pfnAheadLibEx_SystemFunction032;
	PVOID pfnAheadLibEx_SystemFunction033;
	PVOID pfnAheadLibEx_SystemFunction035;
}


static HMODULE g_OldModule = NULL;

VOID WINAPI Free()
{
	if (g_OldModule)
	{
		FreeLibrary(g_OldModule);
	}
}


BOOL WINAPI Load()
{
	TCHAR tzPath[MAX_PATH];
	TCHAR tzTemp[MAX_PATH * 2];

	//
	// 这里是否从系统目录或当前目录加载原始DLL
	//
	//GetModuleFileName(NULL,tzPath,MAX_PATH); //获取本目录下的
	//PathRemoveFileSpec(tzPath);

	GetSystemDirectory(tzPath, MAX_PATH); //默认获取系统目录的

	lstrcat(tzPath, TEXT("\\cryptsp.dll"));

	g_OldModule = LoadLibrary(tzPath);
	if (g_OldModule == NULL)
	{
		wsprintf(tzTemp, TEXT("无法找到模块 %s,程序无法正常运行"), tzPath);
		MessageBox(NULL, tzTemp, TEXT("AheadLibEx"), MB_ICONSTOP);
	}

	return (g_OldModule != NULL);

}


FARPROC WINAPI GetAddress(PCSTR pszProcName)
{
	FARPROC fpAddress;
	CHAR szProcName[64];
	TCHAR tzTemp[MAX_PATH];

	fpAddress = GetProcAddress(g_OldModule, pszProcName);
	if (fpAddress == NULL)
	{
		if (HIWORD(pszProcName) == 0)
		{
			wsprintfA(szProcName, "#%d", pszProcName);
			pszProcName = szProcName;
		}

		wsprintf(tzTemp, TEXT("无法找到函数 %hs,程序无法正常运行"), pszProcName);
		MessageBox(NULL, tzTemp, TEXT("AheadLibEx"), MB_ICONSTOP);
		ExitProcess(-2);
	}
	return fpAddress;
}

BOOL WINAPI Init()
{
	pfnAheadLibEx_CheckSignatureInFile = GetAddress("CheckSignatureInFile");
	pfnAheadLibEx_CryptAcquireContextA = GetAddress("CryptAcquireContextA");
	pfnAheadLibEx_CryptAcquireContextW = GetAddress("CryptAcquireContextW");
	pfnAheadLibEx_CryptContextAddRef = GetAddress("CryptContextAddRef");
	pfnAheadLibEx_CryptCreateHash = GetAddress("CryptCreateHash");
	pfnAheadLibEx_CryptDecrypt = GetAddress("CryptDecrypt");
	pfnAheadLibEx_CryptDeriveKey = GetAddress("CryptDeriveKey");
	pfnAheadLibEx_CryptDestroyHash = GetAddress("CryptDestroyHash");
	pfnAheadLibEx_CryptDestroyKey = GetAddress("CryptDestroyKey");
	pfnAheadLibEx_CryptDuplicateHash = GetAddress("CryptDuplicateHash");
	pfnAheadLibEx_CryptDuplicateKey = GetAddress("CryptDuplicateKey");
	pfnAheadLibEx_CryptEncrypt = GetAddress("CryptEncrypt");
	pfnAheadLibEx_CryptEnumProviderTypesA = GetAddress("CryptEnumProviderTypesA");
	pfnAheadLibEx_CryptEnumProviderTypesW = GetAddress("CryptEnumProviderTypesW");
	pfnAheadLibEx_CryptEnumProvidersA = GetAddress("CryptEnumProvidersA");
	pfnAheadLibEx_CryptEnumProvidersW = GetAddress("CryptEnumProvidersW");
	pfnAheadLibEx_CryptExportKey = GetAddress("CryptExportKey");
	pfnAheadLibEx_CryptGenKey = GetAddress("CryptGenKey");
	pfnAheadLibEx_CryptGenRandom = GetAddress("CryptGenRandom");
	pfnAheadLibEx_CryptGetDefaultProviderA = GetAddress("CryptGetDefaultProviderA");
	pfnAheadLibEx_CryptGetDefaultProviderW = GetAddress("CryptGetDefaultProviderW");
	pfnAheadLibEx_CryptGetHashParam = GetAddress("CryptGetHashParam");
	pfnAheadLibEx_CryptGetKeyParam = GetAddress("CryptGetKeyParam");
	pfnAheadLibEx_CryptGetProvParam = GetAddress("CryptGetProvParam");
	pfnAheadLibEx_CryptGetUserKey = GetAddress("CryptGetUserKey");
	pfnAheadLibEx_CryptHashData = GetAddress("CryptHashData");
	pfnAheadLibEx_CryptHashSessionKey = GetAddress("CryptHashSessionKey");
	pfnAheadLibEx_CryptImportKey = GetAddress("CryptImportKey");
	pfnAheadLibEx_CryptReleaseContext = GetAddress("CryptReleaseContext");
	pfnAheadLibEx_CryptSetHashParam = GetAddress("CryptSetHashParam");
	pfnAheadLibEx_CryptSetKeyParam = GetAddress("CryptSetKeyParam");
	pfnAheadLibEx_CryptSetProvParam = GetAddress("CryptSetProvParam");
	pfnAheadLibEx_CryptSetProviderA = GetAddress("CryptSetProviderA");
	pfnAheadLibEx_CryptSetProviderExA = GetAddress("CryptSetProviderExA");
	pfnAheadLibEx_CryptSetProviderExW = GetAddress("CryptSetProviderExW");
	pfnAheadLibEx_CryptSetProviderW = GetAddress("CryptSetProviderW");
	pfnAheadLibEx_CryptSignHashA = GetAddress("CryptSignHashA");
	pfnAheadLibEx_CryptSignHashW = GetAddress("CryptSignHashW");
	pfnAheadLibEx_CryptVerifySignatureA = GetAddress("CryptVerifySignatureA");
	pfnAheadLibEx_CryptVerifySignatureW = GetAddress("CryptVerifySignatureW");
	pfnAheadLibEx_SystemFunction006 = GetAddress("SystemFunction006");
	pfnAheadLibEx_SystemFunction007 = GetAddress("SystemFunction007");
	pfnAheadLibEx_SystemFunction008 = GetAddress("SystemFunction008");
	pfnAheadLibEx_SystemFunction009 = GetAddress("SystemFunction009");
	pfnAheadLibEx_SystemFunction010 = GetAddress("SystemFunction010");
	pfnAheadLibEx_SystemFunction011 = GetAddress("SystemFunction011");
	pfnAheadLibEx_SystemFunction012 = GetAddress("SystemFunction012");
	pfnAheadLibEx_SystemFunction013 = GetAddress("SystemFunction013");
	pfnAheadLibEx_SystemFunction014 = GetAddress("SystemFunction014");
	pfnAheadLibEx_SystemFunction015 = GetAddress("SystemFunction015");
	pfnAheadLibEx_SystemFunction016 = GetAddress("SystemFunction016");
	pfnAheadLibEx_SystemFunction018 = GetAddress("SystemFunction018");
	pfnAheadLibEx_SystemFunction020 = GetAddress("SystemFunction020");
	pfnAheadLibEx_SystemFunction021 = GetAddress("SystemFunction021");
	pfnAheadLibEx_SystemFunction022 = GetAddress("SystemFunction022");
	pfnAheadLibEx_SystemFunction023 = GetAddress("SystemFunction023");
	pfnAheadLibEx_SystemFunction024 = GetAddress("SystemFunction024");
	pfnAheadLibEx_SystemFunction025 = GetAddress("SystemFunction025");
	pfnAheadLibEx_SystemFunction026 = GetAddress("SystemFunction026");
	pfnAheadLibEx_SystemFunction027 = GetAddress("SystemFunction027");
	pfnAheadLibEx_SystemFunction030 = GetAddress("SystemFunction030");
	pfnAheadLibEx_SystemFunction031 = GetAddress("SystemFunction031");
	pfnAheadLibEx_SystemFunction032 = GetAddress("SystemFunction032");
	pfnAheadLibEx_SystemFunction033 = GetAddress("SystemFunction033");
	pfnAheadLibEx_SystemFunction035 = GetAddress("SystemFunction035");
	return TRUE;
}

DWORD WINAPI ThreadProc(LPVOID lpThreadParameter)
{
	HANDLE hProcess;

	PVOID addr1 = reinterpret_cast<PVOID>(0x00401000);
	BYTE data1[] = { 0x90, 0x90, 0x90, 0x90 };

	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, GetCurrentProcessId());
	if (hProcess)
	{
		WriteProcessMemory(hProcess, addr1, data1, sizeof(data1), NULL);

		CloseHandle(hProcess);
	}

	return 0;
}


#ifndef NDEBUG
#define DEBUGLOG(x) OutputDebugString(TEXT("[wezterm-gui MessageBeep hook] ") x TEXT("\n"))
#else 
#define DEBUGLOG(x)
#endif

// 原始函数指针类型声明
typedef BOOL(WINAPI* MessageBeepType)(UINT);
static MessageBeepType OriginalMessageBeep = nullptr;

typedef struct _GET_PROCESS_MAIN_WINDOW_CONTEXT {
	DWORD ProcessId;          // 目标进程 ID
	HWND Window;              // 找到的主窗口句柄
	BOOL SkipInvisible;       // 是否跳过不可见窗口
	BOOL IsImmersive;         // 是否为沉浸式窗口
	HWND ImmersiveWindow;     // 沉浸式窗口句柄
} GET_PROCESS_MAIN_WINDOW_CONTEXT, * PGET_PROCESS_MAIN_WINDOW_CONTEXT;


// 回调函数，用于枚举窗口
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
	PGET_PROCESS_MAIN_WINDOW_CONTEXT context = (PGET_PROCESS_MAIN_WINDOW_CONTEXT)lParam;
	DWORD processId;
	WINDOWINFO windowInfo;

	// 跳过不可见窗口
	if (context->SkipInvisible && !IsWindowVisible(hWnd)) {
		return TRUE;
	}

	// 获取窗口所属进程 ID
	GetWindowThreadProcessId(hWnd, &processId);

	// 检查窗口是否属于目标进程
	if (processId == context->ProcessId) {
		// 检查是否为沉浸式窗口
		if (!context->ImmersiveWindow && context->IsImmersive &&
			GetPropA(hWnd, "Windows.ImmersiveShell.IdentifyAsMainCoreWindow")) {
			context->ImmersiveWindow = hWnd;
		}

		// 获取窗口信息
		windowInfo.cbSize = sizeof(WINDOWINFO);
		if (!context->Window && GetWindowInfo(hWnd, &windowInfo) && (windowInfo.dwStyle & WS_DLGFRAME)) {
			context->Window = hWnd;

			// 如果不是沉浸式窗口，直接返回
			if (!context->IsImmersive) {
				return FALSE;
			}
		}
	}

	return TRUE;
}

HWND GetProcessMainWindow(DWORD dwProcessId, BOOL bSkipInvisible, BOOL bIsImmersive) {
	GET_PROCESS_MAIN_WINDOW_CONTEXT context = { 0 };
	context.ProcessId = dwProcessId;
	context.SkipInvisible = bSkipInvisible;
	context.IsImmersive = bIsImmersive;

	// 枚举所有顶层窗口
	EnumWindows(EnumWindowsProc, (LPARAM)&context);

	// 返回找到的主窗口
	return context.Window ? context.Window : context.ImmersiveWindow;
}


// 自定义的MessageBeep函数
BOOL WINAPI MyMessageBeep(UINT uType) {
	DEBUGLOG(TEXT("hooked!"));

	FLASHWINFO fwi = { sizeof(fwi) };
	fwi.hwnd = GetProcessMainWindow(GetCurrentProcessId(), TRUE, FALSE);
	fwi.dwFlags = FLASHW_ALL| FLASHW_TIMERNOFG;
	fwi.uCount = 0;         // 无限次闪烁
	fwi.dwTimeout = 0;       // 使用系统默认闪烁间隔

	FlashWindowEx(&fwi);

	return OriginalMessageBeep(uType);
}

BOOL HookMessageBeepInIAT() {
	// 获取当前模块基址（假设DLL注入到目标进程）
	HMODULE hModule = GetModuleHandleA(nullptr);
	if (!hModule) {
		DEBUGLOG(TEXT("Failed to get module handle"));
		return FALSE;
	}

	// 解析PE头
	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		DEBUGLOG(TEXT("Invalid DOS header"));
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
		reinterpret_cast<BYTE*>(hModule) + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		DEBUGLOG(TEXT("Invalid NT header"));
		return FALSE;
	}

	// 获取导入表目录
	IMAGE_DATA_DIRECTORY importDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDir.VirtualAddress == 0 || importDir.Size == 0) {
		DEBUGLOG(TEXT("No import table found"));
		return FALSE;
	}

	// 遍历导入描述符
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
		reinterpret_cast<BYTE*>(hModule) + importDir.VirtualAddress);

	while (pImportDesc->Name != 0) {
		LPCSTR moduleName = reinterpret_cast<LPCSTR>(reinterpret_cast<BYTE*>(hModule) + pImportDesc->Name);
		if (_stricmp(moduleName, "user32.dll") == 0) {
			break;
		}
		pImportDesc++;
	}

	if (pImportDesc->Name == 0) {
		DEBUGLOG(TEXT("user32.dll not found in import table"));
		return FALSE;
	}

	// 准备获取原始函数地址
	HMODULE hUser32 = GetModuleHandle(TEXT("user32.dll"));
	if (!hUser32) {
		DEBUGLOG(TEXT("Failed to get user32 module"));
		return FALSE;
	}

	OriginalMessageBeep = reinterpret_cast<MessageBeepType>(
		GetProcAddress(hUser32, "MessageBeep"));
	if (!OriginalMessageBeep) {
		DEBUGLOG(TEXT("Failed to find original MessageBeep"));
		return FALSE;
	}

	// 遍历导入函数
	IMAGE_THUNK_DATA* pThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
		reinterpret_cast<BYTE*>(hModule) + pImportDesc->OriginalFirstThunk);
	IMAGE_THUNK_DATA* pIAT = reinterpret_cast<IMAGE_THUNK_DATA*>(
		reinterpret_cast<BYTE*>(hModule) + pImportDesc->FirstThunk);

	for (; pThunk->u1.AddressOfData != 0; pThunk++, pIAT++) {
		// 跳过序号导入
		if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;

		// 获取导入函数名称
		PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
			reinterpret_cast<BYTE*>(hModule) + pThunk->u1.AddressOfData);

		if (strcmp(pImport->Name, "MessageBeep") == 0) {
			// 修改内存保护
			DWORD oldProtect;
			if (!VirtualProtect(&pIAT->u1.Function, sizeof(ULONG_PTR), PAGE_READWRITE, &oldProtect)) {
				DEBUGLOG(TEXT("Failed to change memory protection"));
				return FALSE;
			}

			// 替换IAT地址
			pIAT->u1.Function = reinterpret_cast<ULONG_PTR>(MyMessageBeep);

			// 恢复内存保护
			DWORD temp;
			VirtualProtect(&pIAT->u1.Function, sizeof(ULONG_PTR), oldProtect, &temp);

			DEBUGLOG(TEXT("Successfully hooked MessageBeep!"));
			return TRUE;
		}
	}

	DEBUGLOG(TEXT("Failed to find MessageBeep in IAT"));
	return FALSE;
}



BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);

		if (Load() && Init())
		{
			TCHAR szAppName[] = TEXT("wezterm-gui.exe");//请修改宿主进程名
			TCHAR szCurName[MAX_PATH];

			GetModuleFileName(NULL, szCurName, MAX_PATH);
			PathStripPath(szCurName);

			//是否判断宿主进程名
			if (StrCmpI(szCurName, szAppName) == 0)
			{
				DEBUGLOG(TEXT("we are in wezterm...."));
				if (!HookMessageBeepInIAT()) {
					DebugBreak();
				}
				//启动补丁线程或者其他操作
				//HANDLE hThread = CreateThread(NULL, NULL, ThreadProc, NULL, NULL, NULL);
				//if (hThread)
				//{
				//	CloseHandle(hThread);
				//}
			}
		}
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		Free();
	}

	return TRUE;
}

