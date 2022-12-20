#pragma once

#include "global.h"

BOOL scmInstallDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName,
    _In_opt_ LPCTSTR ServiceExe
);

BOOL scmStartDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName
);

BOOL scmOpenDevice(
    _In_ LPCTSTR DriverName,
    _Inout_opt_ PHANDLE lphDevice
);

BOOL scmStopDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName
);

BOOL scmRemoveDriver(
    _In_ SC_HANDLE SchSCManager,
    _In_ LPCTSTR DriverName
);

BOOL scmUnloadDeviceDriver(
    _In_ LPCTSTR Name
);

BOOL scmStopDeviceDriver(
    _In_ LPCTSTR Name
);

BOOL scmStartDeviceDriver(
    _In_		LPCTSTR Name,
    _In_opt_	LPCTSTR Path
);

BOOL scmLoadDeviceDriver(
    _In_		LPCTSTR Name,
    _In_opt_	LPCTSTR Path,
    _Inout_		PHANDLE lphDevice
);

BOOL scmStartDriver2(_In_ LPCTSTR Name);
