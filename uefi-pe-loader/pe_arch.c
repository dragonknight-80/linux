// SPDX-License-Identifier: GPL-2.0-only
#ifdef __KERNEL__
#include <linux/stddef.h>
#endif
#include "pe_arch.h"

static unsigned int amd64_reloc_size(u16 type)
{
	return type == 10 ? 8 : 0; /* IMAGE_REL_BASED_DIR64 */
}

static void amd64_relocate(u16 type, u8 *target, u64 delta)
{
	u64 value = 0;
	int i;

	(void)type; /* The core has already checked amd64_reloc_size(type). */
	/* Byte accesses also support unaligned values, regardless of host ISA. */
	for (i = 7; i >= 0; i--)
		value = (value << 8) | target[i];
	value += delta;
	for (i = 0; i < 8; i++)
		target[i] = value >> (i * 8);
}

static const struct uefi_pe_arch amd64 = {
	.machine = UEFI_PE_MACHINE_AMD64,
	.reloc_size = amd64_reloc_size,
	.relocate = amd64_relocate,
};

const struct uefi_pe_arch *uefi_pe_arch_find(u16 machine)
{
	if (machine == amd64.machine)
		return &amd64;
	return NULL;
}
