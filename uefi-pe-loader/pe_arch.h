/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef UEFI_PE_ARCH_H
#define UEFI_PE_ARCH_H

#include "pe_image.h"

/* Only the machine backend interprets architecture-specific relocation types. */
struct uefi_pe_arch {
	u16 machine;
	/* Return zero for unsupported types. ABSOLUTE padding is handled by core. */
	unsigned int (*reloc_size)(u16 type);
	/* Called only after the core validates type and the entire target range. */
	void (*relocate)(u16 type, u8 *target, u64 delta);
};

/* A defined machine ID alone does not imply that a backend is available. */
const struct uefi_pe_arch *uefi_pe_arch_find(u16 machine);

#endif
