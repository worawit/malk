#pragma once

#include "global.h"

// MUST be called before calling any kernel function
BOOL patchSddt();

ULONG64 KeGetCurrentThread();
ULONG64 PsLookupProcessByProcessId(DWORD pid);
ULONG64 ExAllocatePool2(ULONG64 Flags, SIZE_T NumberOfBytes, ULONG Tag);
void ExFreePool(ULONG64 va);
NTSTATUS KernelOpenProcess(PVOID eprocessVa, PHANDLE outHandle); // ObOpenObjectByPointer to avoid logging and tracing
NTSTATUS KernelClose(HANDLE handle); // ZwClose

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(_In_ PVOID ThreadParameter);

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
	_Out_opt_ PCLIENT_ID ClientId);
NTSTATUS KernelCreateRemoteThread(HANDLE hProcess, PUSER_THREAD_START_ROUTINE StartAddress, PVOID Parameter, PHANDLE Thread, PCLIENT_ID ClientId);

NTSTATUS KeSetEvent(ULONG64/*PRKEVENT*/ EventVa, KPRIORITY Increment, BOOLEAN Wait);
NTSTATUS KeClearEvent(ULONG64/*PRKEVENT*/ EventVa);
