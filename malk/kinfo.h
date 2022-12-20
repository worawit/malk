#pragma once

#include "global.h"

typedef struct DriverMap {
	char name[40];
	ULONG64 va;
} DriverMap;

BOOL initKernelInfo();

ULONG64 findKernelExportVa(const char* name);
ULONG64 findDriverVa(const char* name);
DriverMap* findDriverFromAddress(ULONG64 addr);

ULONG64 getNtKernelVa();
ULONG64 getNtKernelEndVa();
ULONG64 getKeServiceDescriptorTableVa();
ULONG64 getPspCreateProcessNotifyRoutineVa();
ULONG64 getSeCiValidateImageHeaderVa();
