#pragma once

#include "global.h"

void setPagerVerbose(BOOL b);

typedef struct SavePageEntry {
	ULONG64* pEntry;
	ULONG64 value;
} SavePageEntry;

typedef struct NonPagedInfo {
	BYTE* buffer; // the accessible address to modify data in page
	ULONG64 physicalAddress;
} NonPagedInfo;

BOOL pager_init();

ULONG64 walkPage(ULONG64 virtualAddress);

ULONG64 pager_readU64(ULONG64 virtualAddress);

ULONG64* getPtePointer(ULONG64 virtualAddress);
ULONG64 getPteValue(ULONG64 virtualAddress);

// get the mapped memory (which is writable) from the pte value
// pte can be physical address too
BYTE* getMappedMemory(ULONG64 pte);

BOOL getFreeNonpaged(NonPagedInfo* pageInfo);

void restorePageEntry(SavePageEntry* info);

typedef struct PageChainInfo {
	NonPagedInfo pdp;
	NonPagedInfo pd;
	NonPagedInfo pt;
	NonPagedInfo data;
} PageChainInfo;

BYTE* newPageTableChain(ULONG64 targetVa, PageChainInfo *pageChainInfo, SavePageEntry* oldPml4e);

// expect present in PDE
BOOL newDataPte(ULONG64 targetVa, NonPagedInfo* pageInfo, SavePageEntry* oldPte);
