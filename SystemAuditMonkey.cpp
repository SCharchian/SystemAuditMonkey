// SystemAuditMonkey.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h> // Replace <iostream> with <wchar.h> for wprintf
#include <comdef.h>  // Needed for Motherboard name 
#include <Wbemidl.h> // Needed for Motherboard name & CPU Temp
#include <sddl.h>   // For ConvertSidToStringSid
#include <math.h>   // For roundf()

// Tell the linker to include these libs during compilation
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wbemuuid.lib")  // Needed for Motherboard name & CPU Temp
#pragma execution_character_set("utf-8")  // Needed for ANSI ART


// DEFINES / CONSTANTS
#define INFO_BUFFER_SIZE 256

struct _SysInfo {
    WCHAR pszUsername[INFO_BUFFER_SIZE];
    WCHAR pszComputername[INFO_BUFFER_SIZE];
    BOOL  fIsAdmin = false;
    WCHAR pszIPAddress[128];
    WCHAR pszOSName[INFO_BUFFER_SIZE];
    WCHAR pszTerminal[INFO_BUFFER_SIZE];
    WCHAR pszMotherboard[INFO_BUFFER_SIZE];
    WCHAR pszCPU[INFO_BUFFER_SIZE];
    WCHAR pszGPU[INFO_BUFFER_SIZE];
    double nMemoryTotal;
    double nMemoryFree;
    double nDiskTotal;
    double nDiskFree;
    WCHAR pszUptime[INFO_BUFFER_SIZE];
};

// Forward declaration
BOOL GetFirstNonLoopbackIPv4(WCHAR* ipBuffer, LPDWORD bufferSize);
BOOL GetOSVersionInfo(WCHAR* osBuffer, LPDWORD bufferSize);
BOOL GetCPUInfo(WCHAR* cpuBuffer, LPDWORD bufferSize);
BOOL GetGPUInfo(WCHAR* gpuBuffer, LPDWORD bufferSize);
BOOL GetMemoryInfo(double* totalGB, double* freeGB);
BOOL GetDiskInfo(double* totalDiskGB, double* freeDiskGB);
BOOL GetSystemUptime(WCHAR* uptimeBuffer, LPDWORD bufferSize);
BOOL GetMotherboardInfo(WCHAR*, LPDWORD);
void PresentSysInfo(const _SysInfo& info);
BOOL GetTerminalInfo(WCHAR* terminal, LPDWORD size);
BOOL IsRunningAsAdmin();

// Windows headers do not properly expose this function so we have to declare this and access the function from ntdll directly.  LAME
BOOL GetOSVersionInfo(WCHAR* osInfo);
typedef LONG(NTAPI* RtlGetVersionPtr)(POSVERSIONINFOEXW);

//GLOBAL
HANDLE hConsole = 0x0;

int main()
{
 
	// Setup the CONSOLE for UTF-8 and ANSI escape sequences
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    // Make sure console uses UTF-8 for both output and input
    BOOL ok1 = SetConsoleOutputCP(CP_UTF8);
    BOOL ok2 = SetConsoleCP(CP_UTF8);

    // Enable ANSI escape sequences for colored output & position/etc.
    DWORD mode = 0;
    BOOL ok3 = GetConsoleMode(hConsole, &mode);
    BOOL ok4 = SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_LVB_GRID_WORLDWIDE);
    //BOOL ok4 = SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
 
    struct _SysInfo SysInfo;

    const DWORD kBuffSize = INFO_BUFFER_SIZE;  // permanent holder of max size
    DWORD BuffSize = kBuffSize;

    GetUserNameW(SysInfo.pszUsername, &BuffSize);

    BuffSize = kBuffSize;
    GetComputerNameW(SysInfo.pszComputername, &BuffSize);

    BuffSize = 32;
    GetFirstNonLoopbackIPv4(SysInfo.pszIPAddress, &BuffSize);

    // OS INFO
    BuffSize = kBuffSize;
    GetOSVersionInfo(SysInfo.pszOSName, &BuffSize);

    // Get some basic hardware data
    BuffSize = kBuffSize;
    GetMotherboardInfo(SysInfo.pszMotherboard, &BuffSize);

    BuffSize = kBuffSize;
    GetCPUInfo(SysInfo.pszCPU, &BuffSize);

    BuffSize = kBuffSize;
    GetGPUInfo(SysInfo.pszGPU, &BuffSize);

    GetMemoryInfo(&SysInfo.nMemoryTotal, &SysInfo.nMemoryFree);

    GetDiskInfo(&SysInfo.nDiskTotal, &SysInfo.nDiskFree);

    BuffSize = kBuffSize;
    GetSystemUptime(SysInfo.pszUptime, &BuffSize);

    BuffSize = kBuffSize;
    GetTerminalInfo(SysInfo.pszTerminal, &BuffSize);

    SysInfo.fIsAdmin = IsRunningAsAdmin();

    //SysInfo.nCPUTemp = GetCPUTemperature();

/*
    wprintf(L"===== SYSTEM AUDIT MONKEY (S.A.M.) says =====\n");
    wprintf(L"User: %s\n", SysInfo.pszUsername);
    wprintf(L"Computer: %s\n", SysInfo.pszComputername);
    wprintf(L"IP Address: %s\n", SysInfo.pszIPAddress);
    wprintf(L"OS: %s\n", SysInfo.pszOSName);
    wprintf(L"Motherboard: %s\n", SysInfo.pszMotherboard);
    wprintf(L"CPU: %s\n", SysInfo.pszCPU);
    wprintf(L"GPU: %s\n", SysInfo.pszGPU);
    wprintf(L"RAM: %.2fGB Total / %.2fGB Free\n", SysInfo.nMemoryTotal, SysInfo.nMemoryFree);
    wprintf(L"Disk C: %.2fGB Total / %.2fGB Free\n", SysInfo.nDiskTotal, SysInfo.nDiskFree);
    wprintf(L"Uptime: %s\n", SysInfo.pszUptime);
    wprintf(L"Terminal: %s\n", SysInfo.pszTerminal);
    wprintf(L"Admin?: %s", SysInfo.fIsAdmin ? L"true" : L"false");
*/
   // Doesn't work on MOST machines, sadface. wprintf(L"CPU Temp: %.2fc", SysInfo.nCPUTemp);
 

    PresentSysInfo(SysInfo);
}

BOOL IsRunningAsAdmin() 
{
    BOOL isElevated = FALSE;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            isElevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(hToken);
    }
    return isElevated;
}

BOOL GetSystemUptime(WCHAR* uptimeBuffer, LPDWORD bufferSize) 
{
    if (!uptimeBuffer || !bufferSize || *bufferSize < 64) return FALSE;

    ULONGLONG ticks = GetTickCount64(); // Milliseconds since system start
    ULONGLONG seconds = ticks / 1000;
    ULONGLONG minutes = seconds / 60;
    ULONGLONG hours = minutes / 60;
    ULONGLONG days = hours / 24;

    swprintf_s(uptimeBuffer, *bufferSize, L"%llu days %llu hours %llu minutes",
        days, hours % 24, minutes % 60);
    *bufferSize = (DWORD)wcslen(uptimeBuffer) + 1;
    return TRUE;
}

// HARDWARE INFO
BOOL GetMotherboardInfo(WCHAR* mbBuffer, LPDWORD bufferSize) {
    if (!mbBuffer || !bufferSize || *bufferSize < 128) return FALSE;

    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) return FALSE;

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) {
        CoUninitialize();
        return FALSE;
    }

    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return FALSE;
    }

    IWbemServices* pSvc = NULL;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return FALSE;
    }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE);
    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return FALSE;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pSvc->ExecQuery(_bstr_t("WQL"), _bstr_t("SELECT * FROM Win32_BaseBoard"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return FALSE;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    WCHAR manufacturer[64] = L"Unknown";
    WCHAR product[64] = L"Unknown";

    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if (SUCCEEDED(hr) && uReturn) {
        VARIANT vtProp;
        V_VT(&vtProp) = VT_BSTR;
        hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            wcscpy_s(manufacturer, 64, vtProp.bstrVal);
            VariantClear(&vtProp);
        }
        hr = pclsObj->Get(L"Product", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            wcscpy_s(product, 64, vtProp.bstrVal);
            VariantClear(&vtProp);
        }
        pclsObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    swprintf_s(mbBuffer, *bufferSize, L"%s %s", manufacturer, product);
    *bufferSize = (DWORD)wcslen(mbBuffer) + 1;
    return TRUE;
}

BOOL GetCPUInfo(WCHAR* cpuBuffer, LPDWORD bufferSize) {
    if (!cpuBuffer || !bufferSize || *bufferSize < 128) return FALSE;

    wcscpy_s(cpuBuffer, *bufferSize, L"Unknown CPU"); // Fallback/Default
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD byteSize = *bufferSize * sizeof(WCHAR); // Convert to bytes
        if (RegQueryValueExW(hKey, L"ProcessorNameString", NULL, NULL, (LPBYTE)cpuBuffer, &byteSize) == ERROR_SUCCESS) {
            *bufferSize = byteSize / sizeof(WCHAR); // Convert back to WCHAR count
        }
        RegCloseKey(hKey);
    }

    *bufferSize = (DWORD)wcslen(cpuBuffer) + 1;
    return TRUE;
}

BOOL GetGPUInfo(WCHAR* gpuBuffer, LPDWORD bufferSize) {
    if (!gpuBuffer || !bufferSize || *bufferSize < 64) return FALSE;

    wcscpy_s(gpuBuffer, *bufferSize, L"Unknown GPU"); // Fallback/Default
    DISPLAY_DEVICEW display = { sizeof(DISPLAY_DEVICEW) };
    if (EnumDisplayDevicesW(NULL, 0, &display, 0)) {
        wcscpy_s(gpuBuffer, *bufferSize, display.DeviceString);
        *bufferSize = (DWORD)wcslen(gpuBuffer) + 1;
    }

    *bufferSize = (DWORD)wcslen(gpuBuffer) + 1;
    return TRUE;
}

/* CANT reasonably do this without lots of drama!
*  THIS METHOD DOES NOT WORK ON 95+% of Windows machines, so worthless.
double GetCPUTemperature() 
{
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) return FALSE;

    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) {
        CoUninitialize();
        return FALSE;
    }

    IWbemLocator* pLoc = NULL;
    hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        CoUninitialize();
        return FALSE;
    }

    IWbemServices* pSvc = NULL;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\WMI"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hr)) {
        pLoc->Release();
        CoUninitialize();
        return FALSE;
    }

    hr = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE);
    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return FALSE;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hr = pSvc->ExecQuery(_bstr_t("WQL"), _bstr_t("SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hr)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return FALSE;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    double tempCelsius = 0.0;
    BOOL found = FALSE;

    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if (SUCCEEDED(hr) && uReturn) {
        VARIANT vtProp;
        V_VT(&vtProp) = VT_I4;
        hr = pclsObj->Get(L"CurrentTemperature", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr) && vtProp.vt == VT_I4) {
            tempCelsius = (double)vtProp.lVal / 10.0 - 273.15; // Convert from deciKelvin to Celsius
            found = TRUE;
        }
        VariantClear(&vtProp);
        pclsObj->Release();
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    if (!found) {
        tempCelsius = -1;
    }
    return tempCelsius;
}
*/

// Just do 2 floats
BOOL GetMemoryInfo(double* totalGB, double* freeGB) {
    if (!totalGB || !freeGB) return FALSE;

    MEMORYSTATUSEX memInfo = { sizeof(MEMORYSTATUSEX) };
    if (!GlobalMemoryStatusEx(&memInfo)) return FALSE;

    *totalGB = (double)memInfo.ullTotalPhys / (1024 * 1024 * 1024); // Bytes to GB
    *freeGB = (double)memInfo.ullAvailPhys / (1024 * 1024 * 1024);  // Bytes to GB
    return TRUE;
}

BOOL GetDiskInfo(double* totalDiskGB, double* freeDiskGB) {
    if (!totalDiskGB || !freeDiskGB) return FALSE;

    ULARGE_INTEGER freeBytes, totalBytes;
    if (!GetDiskFreeSpaceExW(L"C:\\", NULL, &totalBytes, &freeBytes)) return FALSE;

    *totalDiskGB = (double)totalBytes.QuadPart / (1024 * 1024 * 1024); // Bytes to GB
    *freeDiskGB = (double)freeBytes.QuadPart / (1024 * 1024 * 1024);  // Bytes to GB
    return TRUE;
}

// returns things like cmd.exe, powershell.exe, VsDebugConsole.exe
BOOL GetTerminalInfo(WCHAR* terminalBuffer, LPDWORD bufferSize) {
    if (!terminalBuffer || !bufferSize || *bufferSize < INFO_BUFFER_SIZE) return FALSE;

    DWORD currentPid = GetCurrentProcessId();
    DWORD parentPid = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Find current process entry and capture parent PID (no OpenProcess needed)
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == currentPid) {
                parentPid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    WCHAR parentExe[128] = L"Console";

    // If we found a parent PID, find its process entry and extract the executable name (file portion)
    if (parentPid != 0) {
        HANDLE hParentSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hParentSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W parentPe;
            parentPe.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(hParentSnap, &parentPe)) {
                do {
                    if (parentPe.th32ProcessID == parentPid) {
                        // Call wcsrchr once and check its result BEFORE pointer arithmetic.
                        WCHAR* slash = wcsrchr(parentPe.szExeFile, L'\\');
                        const WCHAR* src = slash ? (slash + 1) : parentPe.szExeFile;
                        wcscpy_s(parentExe, sizeof(parentExe) / sizeof(WCHAR), src);
                        break;
                    }
                } while (Process32NextW(hParentSnap, &parentPe));
            }
            CloseHandle(hParentSnap);
        }
    }

    // Copy the resolved terminal name into the caller buffer safely
    if (wcscpy_s(terminalBuffer, *bufferSize, parentExe) != 0) {
        // copy failed (buffer too small or other error)
        return FALSE;
    }
    *bufferSize = (DWORD)wcslen(terminalBuffer) + 1;
    return TRUE;
}

// Get OS information
BOOL GetOSVersionInfo(WCHAR* osBuffer, LPDWORD bufferSize) {
    if (!osBuffer || !bufferSize || *bufferSize < 128) return FALSE;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;

    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
    if (!RtlGetVersion) return FALSE;

    OSVERSIONINFOEXW osInfo = { sizeof(OSVERSIONINFOEXW) };
    if (RtlGetVersion(&osInfo) != 0) return FALSE;

    DWORD productType;
    if (!GetProductInfo(osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.wServicePackMajor, osInfo.wServicePackMinor, &productType)) {
        productType = 0; // Fallback if GetProductInfo fails
    }

    const WCHAR* osName;
    if (osInfo.dwMajorVersion == 10 && osInfo.dwMinorVersion == 0 && osInfo.dwBuildNumber >= 22000) {
        osName = L"Windows 11";
    }
    else if (osInfo.dwMajorVersion == 10) {
        osName = L"Windows 10";
    }
    else {
        osName = L"Unknown Windows Version";
    }

    const WCHAR* edition;
    switch (productType) {
    case PRODUCT_HOME_BASIC:
    case PRODUCT_HOME_PREMIUM:
        edition = L"Home";
        break;
    case PRODUCT_PROFESSIONAL:
    case PRODUCT_PRO_WORKSTATION:
        edition = L"Pro";
        break;
    case PRODUCT_ENTERPRISE:
        edition = L"Enterprise";
        break;
    case PRODUCT_ULTIMATE:
        edition = L"Ultimate";
        break;
    case PRODUCT_STANDARD_SERVER:
    case PRODUCT_DATACENTER_SERVER:
    case PRODUCT_SMALLBUSINESS_SERVER:
    case PRODUCT_ENTERPRISE_SERVER:
    case PRODUCT_DATACENTER_SERVER_CORE:
    case PRODUCT_STANDARD_SERVER_CORE:
    case PRODUCT_ENTERPRISE_SERVER_CORE:
    case PRODUCT_ENTERPRISE_SERVER_IA64:
    case PRODUCT_WEB_SERVER:
    case PRODUCT_HOME_SERVER:
        edition = L"Server";
        break;
    default:
        edition = L"Unknown Edition";
    }

    swprintf_s(osBuffer, *bufferSize, L"%s %s (Version %u.%u, Build %u)",
        osName, edition, osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber);
    *bufferSize = (DWORD)wcslen(osBuffer) + 1;
    return TRUE;
}

// Getting IP via Winsock
BOOL GetFirstNonLoopbackIPv4(WCHAR* ipBuffer, LPDWORD bufferSize) 
{
    if (!ipBuffer || !bufferSize || *bufferSize < 16) return FALSE;

    ULONG bufLen = 15000;
    PIP_ADAPTER_ADDRESSES adapters = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), 0, bufLen);
    if (!adapters) return FALSE;

    ULONG result = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, adapters, &bufLen);
    if (result == ERROR_BUFFER_OVERFLOW) {
        HeapFree(GetProcessHeap(), 0, adapters);
        adapters = (PIP_ADAPTER_ADDRESSES)HeapAlloc(GetProcessHeap(), 0, bufLen);
        if (!adapters) return FALSE;
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, adapters, &bufLen);
    }

    if (result != NO_ERROR) {
        HeapFree(GetProcessHeap(), 0, adapters);
        return FALSE;
    }

    for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter; adapter = adapter->Next) {
        for (PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                SOCKADDR_IN* ipv4 = (SOCKADDR_IN*)unicast->Address.lpSockaddr;
                if (ipv4->sin_addr.S_un.S_addr != htonl(INADDR_LOOPBACK)) {
                    if (InetNtopW(AF_INET, &ipv4->sin_addr, ipBuffer, *bufferSize) == NULL) {
                        HeapFree(GetProcessHeap(), 0, adapters);
                        return FALSE;
                    }
                    *bufferSize = (DWORD)wcslen(ipBuffer) + 1;
                    HeapFree(GetProcessHeap(), 0, adapters);
                    return TRUE;
                }
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, adapters);
    return FALSE;
}

///////////////// OUTPUT //////////////////////
// Color enums
enum Colors { FG_BLACK = 0, FG_BLUE = 1, FG_GREEN = 2, FG_CYAN = 3, FG_RED = 4, FG_MAGENTA = 5, FG_YELLOW = 6, FG_WHITE = 7, BG_BLACK = 0, INTENSE = 8 };

/*
// Set console color
void SetColor(int color) {
    SetConsoleTextAttribute(hConsole, color);
}
*/

// Simple 40x20 ASCII art (logo-like)
void PrintASCIIArt() 
{
/*

    const char* logoQuadrants[] = {
        "\033[94m,.=:!!t3Z3z.,                  \033[0m\033[92m\033[0m",  // Top-left blue, but wavy - approximate split
        "\033[94m:tt:::tt333EE3                  \033[0m\033[92m\033[0m",
        "\033[94m Et:::ztt33EEEL\\ ''@Ee.,      .., \033[0m\033[92m\033[0m",
        "\033[94m;tt:::tt333EE7\\ ;EEEEEEttttt33#   \033[0m\033[92m\033[0m",
        "\033[94m:Et:::zt333EEQ.\\ $EEEEEttttt33QL   \033[0m\033[92m\033[0m",
        "\033[94m it::::tt333EEF\\ @EEEEEEttttt33F    \033[0m\033[92m\033[0m",
        "\033[94m;3=*^```\"*4EEV\\ :EEEEEEttttt33@.    \033[0m\033[92m\033[0m",
        "\033[94m,.=::::!t=., `\\ @EEEEEEtttz33QF     \033[0m\033[92m\033[0m",
        "\033[92m;t::::::::zt33)\\   \"4EEEtttji3P*      \033[0m\033[33m\033[0m",  // Bottom-left green, bottom-right orange
        "\033[92m:t::::::::tt33.\\:Z3z..  `` ,..g.      \033[0m\033[33m\033[0m",
        "\033[92m i::::::::zt33F\\ AEEEtttt::::ztF       \033[0m\033[33m\033[0m",
        "\033[92m;:::::::::t33V\\ ;EEEttttt::::t3       \033[0m\033[33m\033[0m",
        "\033[92m E::::::::zt33L\\ @EEEtttt::::z3F       \033[0m\033[33m\033[0m",
        "\033[92m {3=*^```\"*4E3)\\ ;EEEtttt:::::tZ`      \033[0m\033[33m\033[0m",
        "\033[92m            `\\ :EEEEtttt::::z7         \033[0m\033[33m\033[0m",
        "\033[92m                \"VEzjt:;;z>*`          \033[0m\033[33m\033[0m"
    };

    for (int i = 0; i < 16; i++) {
        printf("%s\n", logoQuadrants[i]);
    }
 */
 // Prints the Windows FLAG ASCII art with ANSI escape codes for colors
    printf("\x1b[49m      \x1b[49;38;2;1;1;1m▀\x1b[49m  \x1b[38;2;134;134;134;49m▄\x1b[49m                          \x1b[m\n"
        "\x1b[49m    \x1b[38;2;248;187;142;49m▄\x1b[38;2;210;62;17;49m▄\x1b[49m \x1b[49;38;2;102;103;100m▀\x1b[49;38;2;0;0;0m▀\x1b[49m \x1b[38;2;0;0;0;49m▄\x1b[38;2;1;1;1;49m▄\x1b[49m                        \x1b[m\n"
        "\x1b[49m       \x1b[38;2;221;60;2;49m▄\x1b[49m  \x1b[49;38;2;43;43;43m▀\x1b[49;38;2;135;135;135m▀\x1b[38;2;2;5;1;48;2;0;0;0m▄\x1b[38;2;0;0;0;48;2;0;1;0m▄\x1b[38;2;0;0;1;48;2;0;0;0m▄\x1b[38;2;1;1;1;49m▄\x1b[38;2;0;1;0;49m▄\x1b[38;2;0;0;0;49m▄\x1b[38;2;137;137;137;49m▄\x1b[38;2;5;4;5;49m▄\x1b[38;2;3;3;3;49m▄\x1b[38;2;2;2;2;49m▄\x1b[38;2;0;0;0;48;2;129;129;129m▄\x1b[38;2;0;0;1;48;2;100;100;100m▄\x1b[38;2;0;0;0;48;2;38;38;38m▄▄\x1b[38;2;0;0;0;48;2;132;132;132m▄\x1b[38;2;1;2;0;49m▄\x1b[38;2;1;3;0;49m▄\x1b[38;2;0;0;0;49m▄\x1b[38;2;3;4;1;49m▄\x1b[49m     \x1b[m\n"
        "\x1b[49m    \x1b[49;38;2;192;75;49m▀\x1b[49m    \x1b[38;2;218;65;14;48;2;193;72;31m▄\x1b[38;2;191;88;48;48;2;224;67;29m▄\x1b[38;2;244;187;143;49m▄\x1b[38;2;211;73;40;49m▄\x1b[38;2;199;68;35;49m▄\x1b[49m \x1b[49;38;2;0;0;0m▀▀\x1b[49;38;2;6;7;2m▀\x1b[48;2;0;0;0m \x1b[38;2;7;0;0;48;2;2;2;2m▄\x1b[48;2;0;0;0m \x1b[38;2;179;115;116;49m▄\x1b[38;2;169;69;39;48;2;0;0;0m▄\x1b[38;2;165;68;37;48;2;0;0;0m▄▄\x1b[38;2;168;64;45;48;2;0;0;0m▄\x1b[38;2;151;109;86;48;2;1;1;1m▄\x1b[38;2;6;0;0;48;2;1;2;0m▄\x1b[38;2;0;2;1;48;2;1;2;0m▄\x1b[38;2;0;4;8;48;2;1;2;0m▄\x1b[38;2;0;0;8;48;2;0;0;0m▄\x1b[38;2;0;2;2;48;2;0;0;0m▄\x1b[38;2;0;1;0;48;2;0;1;1m▄\x1b[38;2;0;2;1;48;2;32;35;34m▄\x1b[38;2;0;0;0;49m▄\x1b[49m \x1b[m\n"
        "\x1b[49m   \x1b[38;2;42;42;40;49m▄\x1b[49m  \x1b[49;38;2;233;63;4m▀\x1b[49m \x1b[38;2;184;85;36;49m▄\x1b[38;2;199;68;37;49m▄\x1b[49m \x1b[49;38;2;191;58;21m▀\x1b[49;38;2;229;53;0m▀\x1b[49;38;2;203;68;29m▀\x1b[38;2;245;65;11;48;2;251;177;143m▄\x1b[38;2;244;54;0;48;2;233;50;0m▄\x1b[38;2;196;60;26;48;2;241;58;18m▄\x1b[38;2;0;0;0;49m▄\x1b[38;2;0;0;0;48;2;0;8;11m▄\x1b[38;2;1;1;5;48;2;0;2;0m▄\x1b[38;2;202;74;37;48;2;6;0;0m▄\x1b[38;2;255;47;0;48;2;253;46;0m▄\x1b[38;2;255;49;0;48;2;255;48;0m▄\x1b[38;2;252;50;1;48;2;255;49;0m▄\x1b[38;2;253;52;1;48;2;255;50;1m▄\x1b[38;2;248;47;0;48;2;255;52;0m▄\x1b[38;2;22;0;1;48;2;41;0;0m▄\x1b[38;2;0;0;3;48;2;7;5;6m▄\x1b[38;2;6;129;1;48;2;28;117;34m▄\x1b[38;2;0;135;3;48;2;14;135;24m▄\x1b[38;2;0;135;0;48;2;42;117;35m▄\x1b[38;2;1;134;1;48;2;0;1;0m▄\x1b[38;2;34;114;41;48;2;0;2;0m▄\x1b[38;2;1;12;0;48;2;1;0;0m▄\x1b[38;2;2;1;0;48;2;0;0;0m▄\x1b[38;2;0;0;7;48;2;2;0;0m▄\x1b[m\n"
        "\x1b[49m     \x1b[38;2;0;0;1;49m▄\x1b[38;2;98;98;98;49m▄\x1b[49m \x1b[49;38;2;220;88;32m▀\x1b[49;38;2;255;175;129m▀\x1b[38;2;200;77;45;49m▄\x1b[38;2;254;49;9;48;2;218;65;14m▄\x1b[38;2;206;89;51;48;2;233;70;11m▄\x1b[49m \x1b[38;2;231;59;12;49m▄\x1b[38;2;229;63;18;49m▄\x1b[49m \x1b[38;2;0;1;0;48;2;6;4;4m▄\x1b[38;2;0;1;0;48;2;0;0;0m▄\x1b[38;2;0;4;0;48;2;45;45;57m▄\x1b[38;2;253;51;0;48;2;225;62;10m▄\x1b[48;2;255;48;0m \x1b[48;2;255;49;0m \x1b[38;2;250;52;0;48;2;252;50;0m▄\x1b[38;2;255;50;0;48;2;253;52;1m▄\x1b[38;2;191;90;58;48;2;236;54;18m▄\x1b[38;2;0;0;2;48;2;5;0;1m▄\x1b[38;2;0;74;0;48;2;0;9;0m▄\x1b[38;2;4;135;2;48;2;4;132;3m▄\x1b[38;2;0;138;2;48;2;1;136;2m▄\x1b[38;2;4;135;2;48;2;2;135;2m▄\x1b[38;2;4;135;2;48;2;1;134;1m▄\x1b[38;2;11;128;9;48;2;0;135;0m▄\x1b[38;2;0;8;0;48;2;20;52;14m▄\x1b[38;2;2;0;0;48;2;0;1;0m▄\x1b[38;2;0;0;3;48;2;0;0;6m▄\x1b[m\n"
        "\x1b[49m       \x1b[38;2;0;0;0;49m▄\x1b[38;2;1;1;1;48;2;128;128;128m▄\x1b[49m \x1b[38;2;0;0;0;49m▄▄\x1b[49m \x1b[49;38;2;197;74;31m▀\x1b[49;38;2;251;52;5m▀\x1b[49;38;2;231;55;23m▀\x1b[38;2;8;9;2;48;2;6;5;3m▄\x1b[38;2;0;2;1;48;2;0;3;1m▄\x1b[38;2;0;0;0;48;2;0;3;1m▄\x1b[38;2;210;61;23;48;2;196;117;89m▄\x1b[38;2;255;39;4;48;2;255;46;0m▄\x1b[38;2;255;43;0;48;2;254;48;0m▄\x1b[38;2;255;44;0;48;2;255;49;0m▄\x1b[38;2;240;48;13;48;2;255;47;2m▄\x1b[38;2;223;58;34;48;2;244;45;5m▄\x1b[38;2;0;4;0;48;2;22;0;0m▄\x1b[38;2;1;0;0;48;2;2;0;2m▄\x1b[38;2;1;132;11;48;2;20;124;16m▄\x1b[38;2;0;137;2;48;2;5;134;2m▄\x1b[38;2;2;136;0;48;2;5;134;2m▄\x1b[38;2;2;135;2;48;2;5;134;2m▄\x1b[38;2;2;136;0;48;2;4;134;4m▄\x1b[38;2;0;15;1;48;2;19;112;17m▄\x1b[38;2;0;0;4;48;2;0;8;0m▄\x1b[38;2;0;0;0;48;2;2;0;0m▄\x1b[49;38;2;0;5;7m▀\x1b[m\n"
        "\x1b[49m    \x1b[49;38;2;18;141;227m▀\x1b[49;38;2;51;138;175m▀\x1b[49m   \x1b[49;38;2;6;6;6m▀\x1b[49;38;2;12;15;14m▀\x1b[49;38;2;0;1;0m▀\x1b[38;2;0;0;2;48;2;4;7;6m▄\x1b[38;2;0;2;3;48;2;0;2;1m▄\x1b[38;2;0;2;2;48;2;0;2;1m▄\x1b[38;2;99;101;100;49m▄\x1b[38;2;0;0;0;48;2;5;8;7m▄\x1b[48;2;0;0;0m \x1b[38;2;1;0;0;48;2;0;0;0m▄\x1b[38;2;7;1;16;48;2;8;0;0m▄\x1b[38;2;0;0;3;48;2;5;0;1m▄\x1b[38;2;1;0;0;48;2;10;0;0m▄\x1b[38;2;0;0;0;48;2;13;0;0m▄\x1b[38;2;0;0;1;48;2;8;0;0m▄\x1b[38;2;0;4;0;48;2;11;0;0m▄\x1b[48;2;0;0;12m \x1b[38;2;15;0;14;48;2;0;3;1m▄\x1b[38;2;0;3;0;48;2;2;133;5m▄\x1b[38;2;87;157;90;48;2;2;136;0m▄\x1b[38;2;15;127;14;48;2;10;139;4m▄\x1b[48;2;1;137;0m \x1b[38;2;12;128;12;48;2;5;133;6m▄\x1b[38;2;0;0;3;48;2;4;1;0m▄\x1b[38;2;0;0;1;48;2;0;2;3m▄\x1b[38;2;0;0;0;48;2;0;1;0m▄\x1b[49m \x1b[m\n"
        "\x1b[49m \x1b[49;38;2;32;147;211m▀\x1b[49m \x1b[38;2;34;144;223;49m▄\x1b[49m  \x1b[49;38;2;0;150;244m▀\x1b[49;38;2;22;134;208m▀\x1b[38;2;55;140;175;49m▄\x1b[38;2;1;157;248;49m▄\x1b[38;2;33;153;238;49m▄\x1b[49m \x1b[38;2;40;145;212;49m▄\x1b[38;2;43;138;202;49m▄\x1b[49m \x1b[38;2;0;2;1;48;2;0;0;0m▄\x1b[38;2;0;0;0;48;2;0;1;0m▄▄\x1b[38;2;30;150;240;49m▄\x1b[38;2;0;155;251;48;2;48;135;190m▄\x1b[38;2;1;156;255;48;2;52;143;199m▄\x1b[38;2;3;155;254;48;2;49;144;201m▄\x1b[38;2;3;154;255;48;2;44;146;203m▄\x1b[38;2;49;151;206;48;2;55;130;185m▄\x1b[38;2;0;3;0;48;2;0;1;0m▄\x1b[38;2;0;4;0;48;2;1;3;0m▄\x1b[38;2;255;209;3;48;2;9;0;1m▄\x1b[38;2;234;205;35;48;2;0;3;0m▄\x1b[38;2;50;40;0;48;2;0;2;0m▄\x1b[38;2;0;5;0;48;2;4;9;7m▄\x1b[38;2;2;0;5;48;2;6;55;7m▄\x1b[38;2;6;0;6;48;2;80;155;86m▄\x1b[38;2;0;0;2;48;2;1;0;4m▄\x1b[38;2;0;0;3;48;2;1;0;3m▄\x1b[49;38;2;137;133;128m▀\x1b[49m \x1b[m\n"
        "\x1b[38;2;0;0;0;49m▄\x1b[49m    \x1b[38;2;23;146;220;49m▄\x1b[38;2;4;154;238;49m▄\x1b[49m    \x1b[49;38;2;32;141;213m▀\x1b[49;38;2;0;156;255m▀\x1b[49;38;2;10;152;243m▀\x1b[38;2;1;3;4;48;2;113;136;134m▄\x1b[38;2;0;1;0;48;2;1;3;2m▄\x1b[38;2;0;0;2;48;2;0;0;3m▄\x1b[38;2;105;153;183;48;2;0;8;14m▄\x1b[38;2;5;155;252;48;2;7;149;243m▄\x1b[38;2;0;155;255;48;2;0;152;254m▄\x1b[48;2;0;155;255m \x1b[38;2;0;154;255;48;2;0;155;255m▄\x1b[38;2;1;156;255;48;2;0;153;254m▄\x1b[38;2;0;4;4;48;2;0;13;35m▄\x1b[38;2;11;0;17;48;2;0;0;7m▄\x1b[38;2;245;201;52;48;2;135;113;25m▄\x1b[38;2;254;206;0;48;2;255;205;0m▄\x1b[38;2;255;205;0;48;2;249;207;5m▄\x1b[38;2;255;204;0;48;2;246;209;3m▄\x1b[38;2;255;203;9;48;2;238;206;12m▄\x1b[38;2;243;201;42;48;2;10;0;0m▄\x1b[38;2;0;7;1;48;2;0;3;0m▄\x1b[48;2;2;0;4m \x1b[38;2;6;5;8;48;2;0;0;4m▄\x1b[49m  \x1b[m\n"
        "\x1b[49m  \x1b[49;38;2;2;3;0m▀\x1b[49;38;2;6;6;4m▀\x1b[49m    \x1b[49;38;2;0;157;244m▀\x1b[49;38;2;9;156;255m▀\x1b[49m \x1b[38;2;5;155;243;48;2;28;146;220m▄\x1b[38;2;5;149;239;48;2;33;138;223m▄\x1b[49m \x1b[38;2;0;0;0;48;2;0;6;0m▄\x1b[38;2;1;4;0;48;2;1;0;0m▄\x1b[38;2;0;17;29;48;2;0;0;0m▄\x1b[38;2;11;154;231;48;2;33;138;203m▄\x1b[38;2;10;149;255;48;2;0;155;255m▄\x1b[48;2;0;154;255m \x1b[38;2;0;155;254;48;2;0;155;255m▄\x1b[38;2;3;153;255;48;2;4;152;255m▄\x1b[38;2;31;120;184;48;2;26;149;237m▄\x1b[38;2;3;0;4;48;2;2;0;3m▄\x1b[38;2;229;212;117;48;2;9;12;0m▄\x1b[38;2;255;206;0;48;2;248;207;15m▄\x1b[38;2;255;207;1;48;2;253;207;1m▄\x1b[38;2;255;207;0;48;2;254;206;0m▄\x1b[38;2;254;208;0;48;2;254;206;0m▄\x1b[38;2;249;207;16;48;2;255;206;0m▄\x1b[38;2;3;2;0;48;2;22;7;0m▄\x1b[38;2;5;0;0;48;2;2;0;2m▄ \x1b[38;2;4;0;1;48;2;3;0;0m▄\x1b[49m   \x1b[m\n"
        "\x1b[49m    \x1b[49;38;2;0;0;0m▀\x1b[49;38;2;1;1;0m▀\x1b[49m \x1b[38;2;0;2;1;48;2;130;133;132m▄\x1b[38;2;2;4;3;48;2;38;40;40m▄\x1b[49;38;2;129;131;130m▀\x1b[38;2;41;35;17;49m▄\x1b[38;2;3;0;6;49m▄\x1b[38;2;46;31;27;49m▄\x1b[49;38;2;0;0;13m▀\x1b[38;2;46;39;37;48;2;2;0;1m▄\x1b[38;2;0;6;9;48;2;1;1;1m▄\x1b[38;2;38;42;57;49m▄\x1b[38;2;0;10;47;48;2;0;153;255m▄\x1b[38;2;1;10;48;48;2;0;154;255m▄\x1b[38;2;0;10;48;48;2;0;155;255m▄\x1b[38;2;0;10;48;48;2;0;154;255m▄\x1b[38;2;0;55;75;48;2;0;154;255m▄\x1b[38;2;0;0;0;48;2;0;4;12m▄\x1b[38;2;4;9;1;48;2;0;0;0m▄\x1b[38;2;252;208;9;48;2;250;212;18m▄\x1b[38;2;255;208;3;48;2;255;204;4m▄\x1b[38;2;255;208;0;48;2;254;208;0m▄\x1b[38;2;255;210;0;48;2;254;207;4m▄\x1b[38;2;252;209;0;48;2;254;209;0m▄\x1b[38;2;241;200;88;48;2;241;208;33m▄\x1b[38;2;0;0;1;48;2;0;0;0m▄▄\x1b[49;38;2;98;95;99m▀\x1b[49m   \x1b[m\n"
        "\x1b[49m         \x1b[38;2;0;1;0;48;2;96;100;99m▄\x1b[38;2;135;137;136;48;2;0;1;0m▄\x1b[49;38;2;8;10;8m▀\x1b[38;2;1;0;0;49m▄\x1b[38;2;0;1;0;48;2;0;2;0m▄\x1b[38;2;0;2;1;48;2;0;1;0m▄\x1b[38;2;128;130;129;48;2;0;0;0m▄\x1b[38;2;0;0;0;48;2;0;1;0m▄\x1b[38;2;0;2;1;48;2;0;1;0m▄\x1b[48;2;0;2;1m  \x1b[38;2;1;3;3;48;2;0;2;1m▄\x1b[38;2;0;0;0;48;2;0;1;0m▄\x1b[38;2;0;1;0;48;2;0;0;0m▄\x1b[38;2;0;0;0;48;2;0;1;0m▄\x1b[38;2;3;1;0;48;2;0;0;0m▄\x1b[38;2;5;0;0;48;2;7;0;0m▄\x1b[38;2;0;1;10;48;2;248;208;44m▄\x1b[38;2;8;4;0;48;2;255;205;4m▄\x1b[38;2;225;195;112;48;2;255;217;11m▄\x1b[38;2;0;2;0;48;2;14;3;1m▄\x1b[38;2;0;0;0;48;2;3;0;0m▄\x1b[48;2;0;0;0m \x1b[49m    \x1b[m\n"
        "\x1b[49m                      \x1b[49;38;2;130;130;130m▀\x1b[49;38;2;0;0;0m▀\x1b[49;38;2;1;2;0m▀\x1b[38;2;43;43;43;48;2;0;0;0m▄\x1b[48;2;0;0;0m \x1b[38;2;1;0;0;48;2;0;0;0m▄\x1b[38;2;0;1;0;48;2;1;1;1m▄\x1b[38;2;0;0;0;48;2;1;1;0m▄\x1b[38;2;0;1;1;48;2;1;1;1m▄\x1b[49m     \x1b[m\n"
        "\x1b[49m                           \x1b[49;38;2;0;0;0m▀▀\x1b[38;2;6;6;6;48;2;0;0;0m▄\x1b[38;2;39;38;38;48;2;1;1;1m▄\x1b[49m     \x1b[m\n");
}

// Print formatted line with color
void PrintLine(const WCHAR* label, const WCHAR* value, int color)
{
    static int lineNum = 3;

    // Position cursor at row=lineNum, col=40
    // Then emit ANSI foreground color, print text, and reset.
    wprintf(L"\x1b[%d;40H\x1b[%dm%-16s: %s\x1b[0m\n",
        lineNum,
        color,
        label,
        value);

    lineNum++;
}

// ANSI color codes
#define FG_RED 31
#define FG_GREEN 32
#define FG_YELLOW 33
#define FG_BLUE 34
#define FG_MAGENTA 35
#define FG_CYAN 36
#define FG_WHITE 37

// Main presentation function
void PresentSysInfo(const _SysInfo& info) {
    // Clear screen
    system("cls");

    // Print ASCII art (left 40 cols)
    PrintASCIIArt();

	// Print the system information (right 40 cols)
    PrintLine(L"User", info.pszUsername, FG_GREEN);
    PrintLine(L"Computer", info.pszComputername, FG_GREEN);
    PrintLine(L"IP Address", info.pszIPAddress, FG_MAGENTA);
    PrintLine(L"Uptime", info.pszUptime, FG_MAGENTA);
    PrintLine(L"OS", info.pszOSName, FG_WHITE);
    PrintLine(L"Terminal", info.pszTerminal, FG_WHITE);
    PrintLine(L"Motherboard", info.pszMotherboard, FG_RED);
    PrintLine(L"CPU", info.pszCPU, FG_RED);
    PrintLine(L"GPU", info.pszGPU, FG_RED);

    //SetColor(FG_YELLOW);

	int percentUsed = (int)(((info.nMemoryTotal - info.nMemoryFree) / info.nMemoryTotal) * 100);
    wprintf(L"\x1b[%d;40H\x1b[33mRAM    : %.0f GB Total / %.0f GB Free\n", 13, info.nMemoryTotal, info.nMemoryFree);
	
    // Display memory usage bar
	int nBarChars = 25;  // Width of the memory usage bar in characters
	int nUsedChars = (percentUsed * nBarChars) / 100;

	wprintf(L"\x1b[%d;76H[", 13);
    for (int i = 0; i < nBarChars; i++)
    {
        wprintf(i < nUsedChars 
            ? L"\x1b[48;2;255;0;0m \x1b[0m"
            : L"\x1b[48;2;0;255;0m \x1b[0m");
    }
    wprintf(L"]");

    // Display HDD usage and bar
    //SetColor(FG_YELLOW);
    percentUsed = (int)(((info.nDiskTotal - info.nDiskFree) / info.nDiskTotal) * 100);
    //wprintf(L"\x1b[%d;40HDisk   : %.0f GB Total / %.0f GB Free\n", 14, info.nDiskTotal, info.nDiskFree);
    wprintf(
        L"\x1b[%d;40H\x1b[33mDisk   : %.0f GB Total / %.0f GB Free\x1b[0m\n",
        14,
        info.nDiskTotal,
        info.nDiskFree
    );

     
    // Display HDD usage bar
    nUsedChars = (percentUsed * nBarChars) / 100;

    wprintf(L"\x1b[%d;76H[", 14);
    for (int i = 0; i < nBarChars; i++)
    {
        wprintf(i < nUsedChars
            ? L"\x1b[48;2;255;0;0m \x1b[0m"
            : L"\x1b[48;2;0;255;0m \x1b[0m");
    }
	wprintf(L"]");

	wprintf(L"\n\n");

    //SetColor(FG_WHITE);
}