/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef UEFI_PE_IMAGE_ARENA_H
#define UEFI_PE_IMAGE_ARENA_H

#include "pe_image.h"

#define UEFI_PE_MAX_RUNTIME (256U * 1024U * 1024U)

struct uefi_pe_arena_layout {
	size_t image_span;
	size_t runtime_offset;
	size_t runtime_size;
	size_t total_size;
};

/* Alignment is the host allocation granule, independent of PE section size. */
int uefi_pe_plan_arena(u32 image_size, size_t runtime_size, size_t alignment,
		       struct uefi_pe_arena_layout *layout);

#endif
