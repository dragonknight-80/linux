/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef UEFI_PE_IMAGE_H
#define UEFI_PE_IMAGE_H

#include <linux/types.h>

#define UEFI_PE_MAX_FILE (64U * 1024U * 1024U)
#define UEFI_PE_MAX_IMAGE (128U * 1024U * 1024U)

enum uefi_pe_machine {
	UEFI_PE_MACHINE_AMD64 = 0x8664,
	UEFI_PE_MACHINE_ARM64 = 0xaa64,
	UEFI_PE_MACHINE_RISCV64 = 0x5064,
};

struct uefi_pe_info {
	u64 preferred_base;
	u32 image_size;
	u32 entry_rva;
	u16 sections;
	u16 machine;
};

/* Immutable input must remain valid throughout each call. */
int uefi_pe_inspect(const void *file, size_t size, struct uefi_pe_info *info);
/* Output must not alias input. Output is unspecified on failure. Never executes. */
int uefi_pe_map(const void *file, size_t size, void *image, size_t capacity,
		u64 load_address, struct uefi_pe_info *info);

#endif
