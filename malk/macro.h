#pragma once

#define PTE_MASK ~(((1ULL << 21) - 1))
#define SHARED_USER_DATA_VADDR (PVOID)0x7ffe0000
#define PAGE_SIZE (1 << 12)
#define PAGE_MASK 0xfff
#define PAGE_OFFSET(v) (v & PAGE_MASK)
#define PAGE2M_MASK 0x1fffff
#define PAGE2M_OFFSET(v) (v & PAGE2M_MASK)
#define SHIFT_2M 21
#define MASK_2M ((1 << SHIFT_2M) - 1)
#define SHIFT_1G 30
#define MASK_1G ((1 << SHIFT_1G) - 1)
#define NEXT_1G(v) (((ULONG64)v + MASK_1G) & ~((ULONG64)MASK_1G))

#define TABLE_ENTRY_PA(a) ((ULONG64)a & 0x0000fffffffff000)
#define TABLE_IDX_MASK ((1 << 9) - 1)

#define PML4_OFFSET (9 + 9 + 9 + 12)
#define PML4_IDX(v) (((ULONG64)v >> PML4_OFFSET) & TABLE_IDX_MASK)
#define PDPT_OFFSET (9 + 9 + 12)
#define PDPT_IDX(v) (((ULONG64)v >> PDPT_OFFSET) & TABLE_IDX_MASK)
#define PD_OFFSET (9 + 12)
#define PD_IDX(v) (((ULONG64)v >> PD_OFFSET) & TABLE_IDX_MASK)
#define PT_OFFSET (12)
#define PT_IDX(v) (((ULONG64)v >> PT_OFFSET) & TABLE_IDX_MASK)

#define PRESENT_FLAG 1
#define PAGESIZE_FLAG (1 << 7)
#define PAGEGLOBAL_FLAG (1 << 8)
