#include "procmon.h"
#include "scmDriver.h"
#include <stdio.h>

#define DRIVER_FILENAME TEXT(PROCMON_SYS)

static BOOL procmon_installDriver(SC_HANDLE SchSCManager)
{
    WCHAR driverPath[MAX_PATH];
    GetModuleFileNameW(NULL, driverPath, MAX_PATH);
    WCHAR* ptr = wcsrchr(driverPath, L'\\');
    ptr++;
    wcscpy_s(ptr, MAX_PATH - (ptr - driverPath), DRIVER_FILENAME);

    // sc create procmon type= filesys binPath= c:\procmon.sys group= "FSFilter Activity Monitor" display= procmon
    SC_HANDLE schService = CreateServiceW(SchSCManager, // SCManager database
        PROCMON_DRV,           // name of service
        L"Procmon",           // name to display
        SERVICE_ALL_ACCESS,    // desired access
        SERVICE_FILE_SYSTEM_DRIVER, // service type
        SERVICE_DEMAND_START,  // start type
        SERVICE_ERROR_NORMAL,  // error control type
        driverPath,            // service's binary
        L"FSFilter Activity Monitor",   // no load ordering group
        NULL,                  // no tag identifier
        L"FltMgr\0",                  // dependencies
        NULL,                  // LocalSystem account
        NULL                   // no password
    );
    if (schService == NULL) {
        return FALSE;
    }

    // add registry
    // HKLM\System\CurrentControlSet\Service\PROCMON_DRV\Instances
    // HKLM\System\CurrentControlSet\Service\PROCMON_DRV\Instances\DefaultInstance       REG_SZ    Procmon Instance
    // HKLM\System\CurrentControlSet\Service\PROCMON_DRV\Instances\Procmon Instance
    // HKLM\System\CurrentControlSet\Service\PROCMON_DRV\Instances\Procmon Instance\Altitude  REG_SZ    385220
    // HKLM\System\CurrentControlSet\Service\PROCMON_DRV\Instances\Procmon Instance\Flags     REG_DWORD 0
    HKEY hKey;
    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\" PROCMON_DRV L"\\Instances", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        DeleteService(schService);
        CloseServiceHandle(schService);
        return FALSE;
    }

#define PROCMON_INSTANCE L"ProcmonInst"
#define PROCMON_ALTITUDE L"385220"
    RegSetValueEx(hKey, L"DefaultInstance", 0, REG_SZ, (LPBYTE)PROCMON_INSTANCE, sizeof(PROCMON_INSTANCE));

    HKEY hKeyInstance;
    RegCreateKeyEx(hKey, PROCMON_INSTANCE, 0, NULL, 0, KEY_WRITE, NULL, &hKeyInstance, NULL);
    RegCloseKey(hKey);

    RegSetValueEx(hKeyInstance, L"Altitude", 0, REG_SZ, (LPBYTE)PROCMON_ALTITUDE, sizeof(PROCMON_ALTITUDE));
    DWORD flags = 0;
    RegSetValueEx(hKeyInstance, L"Flags", 0, REG_DWORD, (LPBYTE)&flags, sizeof(flags));

    RegCloseKey(hKeyInstance);

    CloseServiceHandle(schService);
    return TRUE;
}

BOOL procmon_loadDevice(PHANDLE phDevice)
{
    BOOL bResult = scmOpenDevice(PROCMON_DRV, phDevice);
    if (!bResult) {
        if (procmon_startDriver()) {
            bResult = scmOpenDevice(PROCMON_DRV, phDevice);
        }
    }
    return bResult;
}

void procmon_unloadDevice(HANDLE hDevice)
{
    CloseHandle(hDevice);
    scmUnloadDeviceDriver(PROCMON_DRV);
}

BOOL procmon_startDriver()
{
    SC_HANDLE schSCManager;
    BOOL      bResult = FALSE;

    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager) {
        bResult = scmStartDriver(schSCManager, PROCMON_DRV);
        if (!bResult) {
            scmRemoveDriver(schSCManager, PROCMON_DRV);
            procmon_installDriver(schSCManager);
            bResult = scmStartDriver(schSCManager, PROCMON_DRV);
        }
        CloseServiceHandle(schSCManager);
    }
    return bResult;
}

void procmon_stopDriver()
{
    scmStopDeviceDriver(PROCMON_DRV);
}
