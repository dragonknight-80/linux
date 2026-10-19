// SPDX-License-Identifier: GPL-2.0-only
#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif
#include "image_arena.h"

int uefi_pe_plan_arena(u32 image_size, size_t runtime_size, size_t alignment,
		       struct uefi_pe_arena_layout *layout)
{
	struct uefi_pe_arena_layout result;

	/* Bounds keep rounding and addition safe, including for 32-bit size_t. */
	if (!layout || !image_size || image_size > UEFI_PE_MAX_IMAGE ||
	    runtime_size > UEFI_PE_MAX_RUNTIME || alignment < 4096 ||
	    alignment > 65536 || (alignment & (alignment - 1)))
		return -EINVAL;
	result.image_span = (image_size + alignment - 1) & ~(alignment - 1);
	result.runtime_offset = result.image_span;
	result.runtime_size = (runtime_size + alignment - 1) & ~(alignment - 1);
	result.total_size = result.image_span + result.runtime_size;
	*layout = result;
	return 0;
}
