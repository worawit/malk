#pragma once

#include "global.h"

#define PROCMON_DRV L"procmon391"
#define PROCMON_SYS "procmon391.sys"

BOOL procmon_loadDevice(PHANDLE phDevice);
void procmon_unloadDevice(HANDLE hDevice);
BOOL procmon_startDriver();
void procmon_stopDriver();
