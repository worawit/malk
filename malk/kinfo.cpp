#include "kinfo.h"
#include <Psapi.h>

typedef struct ExportMap {
	char name[64];
	ULONG64 va;
} ExportMap;

typedef struct NtKrnlInfo {
	ULONG64 ntkrnlVa;
	ULONG64 ntkrnlEndVa;
	DWORD ethreadThreadListEntryOffset;
	DWORD eprocessThreadListHeadOffset;
	ULONG64 KeServiceDescriptorTableVa;
	ULONG64 KiServiceTableVa;
	ULONG64 KiServiceTableNumber;
	ULONG64 ExAllocatePool2Va;
	ULONG64 PspLoadImageNotifyRoutineVa;
	ULONG64 PspCreateThreadNotifyRoutineVa;
	ULONG64 PspCreateProcessNotifyRoutineVa;
	ULONG64 SeCiValidateImageHeaderVa; // next 8 bytes is SeValidateImageData
	ULONG64 GuardCFDispatchFunctionPointerVa;
	ExportMap* kernelExportMap;
	int numKernelExports;
	DriverMap* driverMap;
	int numDrivers;
} NtKrnlInfo;

static NtKrnlInfo kernelInfo;

static BOOL isInited()
{
	return kernelInfo.ntkrnlVa != 0;
}

static IMAGE_SECTION_HEADER* peFindSectionHeader(IMAGE_NT_HEADERS64* ntHeader, DWORD rva)
{
	IMAGE_SECTION_HEADER* section = (IMAGE_SECTION_HEADER*)((BYTE*)&ntHeader->OptionalHeader + ntHeader->FileHeader.SizeOfOptionalHeader);
	for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		if (section->VirtualAddress <= rva && rva < section->VirtualAddress + section->SizeOfRawData) {
			// found section
			return section;
		}
		section++;
	}

	return NULL;
}

static DWORD peFileOffsetToRva(IMAGE_NT_HEADERS64* ntHeader, DWORD fileOffset)
{
	IMAGE_SECTION_HEADER* section = (IMAGE_SECTION_HEADER*)((BYTE*)&ntHeader->OptionalHeader + ntHeader->FileHeader.SizeOfOptionalHeader);
	for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		if (section->PointerToRawData <= fileOffset && fileOffset < section->PointerToRawData + section->SizeOfRawData) {
			// found section
			return fileOffset + section->VirtualAddress - section->PointerToRawData;
		}
		section++;
	}

	return 0;
}

static DWORD peRvaToFileOffset(IMAGE_NT_HEADERS64* ntHeader, DWORD rva)
{
	IMAGE_SECTION_HEADER* section = peFindSectionHeader(ntHeader, rva);
	if (section == NULL) {
		return 0;
	}
	return rva - (section->VirtualAddress - section->PointerToRawData);
}

static BOOL loadDriversMap()
{
	LPVOID drivers[1024];
	DWORD cbNeeded;

	if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
		//printf("EnumDeviceDrivers failed; array size needed is %zd\n", cbNeeded / sizeof(LPVOID));
		return FALSE;
	}

	int cDrivers = cbNeeded / sizeof(drivers[0]);
	kernelInfo.driverMap = (DriverMap*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cDrivers * sizeof(DriverMap));
	if (kernelInfo.driverMap == NULL) {
		//printf("Cannot allocate memory for drivers info\n");
		return FALSE;
	}
	kernelInfo.numDrivers = cDrivers;

	char szDriver[40];
	for (int i = 0; i < cDrivers; i++) {
		if (GetDeviceDriverBaseNameA(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))) {
			//printf("%d: %s => 0x%llx\n", i, szDriver, (ULONG64)drivers[i]);
			strncpy_s(kernelInfo.driverMap[i].name, szDriver, 39);
			kernelInfo.driverMap[i].va = (ULONG64)drivers[i];
		}
	}

	return TRUE;
}

BOOL initKernelInfo()
{
	if (isInited()) {
		return TRUE;
	}

	if (!loadDriversMap()) {
		//printf("load driver address failed!\n");
		return FALSE;
	}

	if (_stricmp(kernelInfo.driverMap[0].name, "ntoskrnl.exe") != 0) {
		return FALSE;
	}
	ULONG64 ntkrnlVa = kernelInfo.driverMap[0].va;

	HANDLE handleToFile = CreateFileW(L"C:\\Windows\\System32\\ntoskrnl.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE handleToMap = CreateFileMapping(handleToFile, NULL, PAGE_READONLY, 0, 0, NULL);
	PBYTE libBase = (PBYTE)MapViewOfFile(handleToMap, FILE_MAP_READ, 0, 0, 0);
	if (!libBase) {
		//printf("Failed to open ntoskrnl!\n");
		return FALSE;
	}
	CloseHandle(handleToMap);
	CloseHandle(handleToFile);
	//printf("ntoskrnl is mapped to 0x%p\n", libBase);

	kernelInfo.ntkrnlVa = ntkrnlVa;

	IMAGE_NT_HEADERS64* ntHeader = (IMAGE_NT_HEADERS64*)(libBase + ((IMAGE_DOS_HEADER*)libBase)->e_lfanew);
	kernelInfo.ntkrnlEndVa = ntkrnlVa + ntHeader->OptionalHeader.SizeOfImage;

	IMAGE_DATA_DIRECTORY* exportDirInfo = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	//IMAGE_SECTION_HEADER* exportSection = RtlSectionTableFromVirtualAddress(ntHeader, libBase, exportDirInfo->VirtualAddress);
	IMAGE_SECTION_HEADER* exportSection = peFindSectionHeader(ntHeader, exportDirInfo->VirtualAddress);
	if (exportSection == NULL) {
		//printf("Cannot find export section\n");
		return FALSE;
	}
	IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(libBase + exportSection->PointerToRawData);
	DWORD exportFileVaDiff = exportDirInfo->VirtualAddress - exportSection->PointerToRawData;

	DWORD* funcRvas = (DWORD*)(libBase + exportDir->AddressOfFunctions - exportFileVaDiff);
	DWORD* funcNames = (DWORD*)(libBase + exportDir->AddressOfNames - exportFileVaDiff);
	USHORT* funcOrdinals = (USHORT*)(libBase + exportDir->AddressOfNameOrdinals - exportFileVaDiff);
	int numKernelExports = exportDir->NumberOfNames;
	kernelInfo.numKernelExports = numKernelExports;
	//printf("numKernelExports: %d\n", numKernelExports);
	kernelInfo.kernelExportMap = (ExportMap*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numKernelExports * sizeof(ExportMap));
	for (int i = 0; i < numKernelExports; i++) {
		if (funcNames[i]) {
			char* name = (char*)libBase + funcNames[i] - exportFileVaDiff;
			DWORD fnRva = funcRvas[funcOrdinals[i]];
			//printf("0x%x => %s\n", fnRva, name);
			strcpy_s(kernelInfo.kernelExportMap[i].name, name);
			kernelInfo.kernelExportMap[i].va = ntkrnlVa + fnRva;

			if (strcmp(kernelInfo.kernelExportMap[i].name, "PsGetThreadExitStatus") == 0) {
				BYTE* fnPtr = libBase + peRvaToFileOffset(ntHeader, fnRva);
				// PsGetThreadExitStatus uses ETHREAD.RundomProtection (which is after ETHREAD.ThreadListEntry)
				memcpy(&kernelInfo.ethreadThreadListEntryOffset, fnPtr + 0xd, sizeof(kernelInfo.ethreadThreadListEntryOffset));
				kernelInfo.ethreadThreadListEntryOffset -= 0x10;
				//printf("ethreadThreadListEntryOffset: 0x%x\n", kernelInfo.ethreadThreadListEntryOffset);
			}
			else if (strcmp(kernelInfo.kernelExportMap[i].name, "PsGetProcessImageFileName") == 0) {
				BYTE* fnPtr = libBase + peRvaToFileOffset(ntHeader, fnRva);
				// get offset of EPROCESS.ImageFileName
				memcpy(&kernelInfo.eprocessThreadListHeadOffset, fnPtr + 0x3, sizeof(kernelInfo.eprocessThreadListHeadOffset));
				if (kernelInfo.eprocessThreadListHeadOffset < 0x400) // win7
					kernelInfo.eprocessThreadListHeadOffset += 0x28;
				else
					kernelInfo.eprocessThreadListHeadOffset += 0x38;
				//printf("eprocessThreadListHeadOffset: 0x%x\n", kernelInfo.eprocessThreadListHeadOffset);
			}
			else if (strcmp(kernelInfo.kernelExportMap[i].name, "PsRemoveLoadImageNotifyRoutine") == 0) {
				BYTE* fnPtr = libBase + peRvaToFileOffset(ntHeader, fnRva);
				DWORD imm;
				memcpy(&imm, fnPtr + 0x35, sizeof(imm)); // lea  rcx, PspLoadImageNotifyRoutine
				kernelInfo.PspLoadImageNotifyRoutineVa = ntkrnlVa + fnRva + 0x35 + 4 + imm; // skip its instruction
				//printf("PspLoadImageNotifyRoutineVa: 0x%llx\n", kernelInfo.PspLoadImageNotifyRoutineVa);
			}
			else if (strcmp(kernelInfo.kernelExportMap[i].name, "PsRemoveCreateThreadNotifyRoutine") == 0) {
				BYTE* fnPtr = libBase + peRvaToFileOffset(ntHeader, fnRva);
				DWORD imm;
				memcpy(&imm, fnPtr + 0x35, sizeof(imm)); // lea  rcx, PspCreateThreadNotifyRoutine
				kernelInfo.PspCreateThreadNotifyRoutineVa = ntkrnlVa + fnRva + 0x35 + 4 + imm; // skip its instruction
				//printf("PspCreateThreadNotifyRoutineVa: 0x%llx\n", kernelInfo.PspCreateThreadNotifyRoutineVa);
			}
			else if (strcmp(kernelInfo.kernelExportMap[i].name, "PsSetCreateProcessNotifyRoutine") == 0) {
				BYTE* fnPtr = libBase + peRvaToFileOffset(ntHeader, fnRva);
				DWORD imm;
				memcpy(&imm, fnPtr + 0xe, sizeof(imm)); // call  PspSetCreateProcessNotifyRoutine
				// tempory use PspCreateProcessNotifyRoutineVa for PspSetCreateProcessNotifyRoutine RVA
				DWORD PspSetCreateProcessNotifyRoutineRva = fnRva + 0xe + 4 + imm; // skip its instruction
				//printf("  PspSetCreateProcessNotifyRoutineVa: 0x%llx", PspCreateProcessNotifyRoutineVa);
				fnPtr = libBase + peRvaToFileOffset(ntHeader, PspSetCreateProcessNotifyRoutineRva);
				// TODO: verify instruction opcode before copy
				memcpy(&imm, fnPtr + 0x65, sizeof(imm)); // lea  r13, PspCreateProcessNotifyRoutine
				kernelInfo.PspCreateProcessNotifyRoutineVa = ntkrnlVa + PspSetCreateProcessNotifyRoutineRva + 0x65 + 4 + imm; // skip its instruction
				//printf("PspCreateProcessNotifyRoutineVa: 0x%llx\n", kernelInfo.PspCreateProcessNotifyRoutineVa);
			}
			else if (strcmp(kernelInfo.kernelExportMap[i].name, "SeGetCachedSigningLevel") == 0) {
				BYTE* fnPtr = libBase + peRvaToFileOffset(ntHeader, fnRva);
				DWORD imm;
				memcpy(&imm, fnPtr + 0x7, sizeof(imm)); //  mov r11, cs:SeCiGetCachedSigningLevel
				ULONG64 pSeGetCachedSigningLevelVa = ntkrnlVa + fnRva + 0xb + imm;
				kernelInfo.SeCiValidateImageHeaderVa = pSeGetCachedSigningLevelVa + 0x10;
			}
		}
	}

	// 0F01F8               swapgs
	// 6548892425 10000000  mov   gs:10h, rsp
	// 65488B24 25A8010000  mov   rsp, gs:1A8h
	int cnt = 0;
	DWORD KiSystemCall32Offset = 0;
	DWORD KiSystemCall64Offset = 0;
	for (DWORD i = ntHeader->OptionalHeader.BaseOfCode; i < ntHeader->OptionalHeader.SizeOfCode; i += 0x20) {
		ULONG64* data = (ULONG64*)(libBase + i);
		if (data[0] == 0x2524894865f8010f && data[1] == 0x248b486500000010) {
			// first is KiSystemCall32
			if (KiSystemCall32Offset == 0) {
				KiSystemCall32Offset = i;
			}
			else {
				KiSystemCall64Offset = i;
				break;
			}
		}
	}
	//printf("KiSystemCall64Offset: 0x%x\n", KiSystemCall64Offset);
	//printf("KiSystemCall64Va: 0x%x\n", getVirtualAddressFromFileOffset(ntHeader, KiSystemCall64Offset));


	// 4C8D15 xxxxxxxx  lea  r10, KeServiceDescriptorTable
	// 4C8D1D xxxxxxxx  lea  r11, KeServiceDescriptorTableShadow
	DWORD leaKeServiceDescriptorTableOffset = 0;
	for (DWORD i = KiSystemCall64Offset; i < KiSystemCall64Offset + 0x1000; i++) {
		if (!(libBase[i] == 0x4c && libBase[i + 1] == 0x8d && libBase[i + 2] == 0x15)) {
			continue;
		}
		if (!(libBase[i + 7] == 0x4c && libBase[i + 8] == 0x8d && libBase[i + 9] == 0x1d)) {
			continue;
		}
		// found
		leaKeServiceDescriptorTableOffset = i;
		break;
	}
	//printf("leaKeServiceDescriptorTableOffset: 0x%x\n", leaKeServiceDescriptorTableOffset);
	DWORD leaKeServiceDescriptorTableVa = peFileOffsetToRva(ntHeader, leaKeServiceDescriptorTableOffset);
	//printf("leaKeServiceDescriptorTableVa: 0x%x\n", leaKeServiceDescriptorTableVa);

	DWORD ripOffset;
	memcpy(&ripOffset, libBase + leaKeServiceDescriptorTableOffset + 3, sizeof(kernelInfo.KeServiceDescriptorTableVa));
	kernelInfo.KeServiceDescriptorTableVa = ntkrnlVa + leaKeServiceDescriptorTableVa + ripOffset + 7; // skip its instruction
	//printf("KeServiceDescriptorTableVa: 0x%llx\n", kernelInfo.KeServiceDescriptorTableVa);

	IMAGE_DATA_DIRECTORY* loadConfigDirInfo = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	IMAGE_LOAD_CONFIG_DIRECTORY64* loadConfigDir = (IMAGE_LOAD_CONFIG_DIRECTORY64*)(libBase + peRvaToFileOffset(ntHeader, loadConfigDirInfo->VirtualAddress));
	kernelInfo.GuardCFDispatchFunctionPointerVa = ntkrnlVa + loadConfigDir->GuardCFDispatchFunctionPointer - ntHeader->OptionalHeader.ImageBase;

	UnmapViewOfFile(libBase);

	return TRUE;
}

ULONG64 findKernelExportVa(const char* name)
{
	for (int i = 0; i < kernelInfo.numKernelExports; i++) {
		if (strcmp(kernelInfo.kernelExportMap[i].name, name) == 0) {
			return kernelInfo.kernelExportMap[i].va;
		}
	}
	return 0;
}

ULONG64 findDriverVa(const char* name)
{
	for (int i = 0; i < kernelInfo.numDrivers; i++) {
		if (_stricmp(kernelInfo.driverMap[i].name, name) == 0)
			return kernelInfo.driverMap[i].va;
	}
	return 0;
}

DriverMap* findDriverFromAddress(ULONG64 addr)
{
	// find the maximum base address but less than addr
	DriverMap* pDriver = NULL;
	for (int i = 0; i < kernelInfo.numDrivers; i++) {
		if (addr < kernelInfo.driverMap[i].va)
			continue;
		if (pDriver == NULL) {
			pDriver = &kernelInfo.driverMap[i];
		}
		else if (pDriver->va < kernelInfo.driverMap[i].va) {
			pDriver = &kernelInfo.driverMap[i];
		}
	}
	return pDriver;
}

ULONG64 getNtKernelVa()
{
	return kernelInfo.ntkrnlVa;
}

ULONG64 getNtKernelEndVa()
{
	return kernelInfo.ntkrnlEndVa;
}

ULONG64 getKeServiceDescriptorTableVa()
{
	return kernelInfo.KeServiceDescriptorTableVa;
}

ULONG64 getPspCreateProcessNotifyRoutineVa()
{
	return kernelInfo.PspCreateProcessNotifyRoutineVa;
}

ULONG64 getSeCiValidateImageHeaderVa()
{
	return kernelInfo.SeCiValidateImageHeaderVa;
}