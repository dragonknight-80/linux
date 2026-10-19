/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef UEFI_PE_LOADER_H
#define UEFI_PE_LOADER_H

#include "image_arena.h"

/**
 * struct uefi_pe_loaded_image - retained image and future runtime arena
 * @arena_base: writable, non-executable virtual mapping of the contiguous arena
 * @arena_phys_base: first physical address of the contiguous CMA allocation
 * @layout: page-aligned allocation sizes and runtime offset
 * @image_base: mapped image base, currently equal to arena_base
 * @runtime_base: zeroed runtime workspace, or NULL if runtime_size is zero
 * @entry: image_base + pe.entry_rva; an address, not an executable callback
 * @entry_phys: arena_phys_base + pe.entry_rva; no physical execution ABI implied
 * @pe: validated PE metadata, including actual SizeOfImage and machine ID
 *
 * Valid only while the caller holds a reference from uefi_pe_image_get().
 * The descriptor is read-only; its backing image/workspace bytes are writable.
 * Consumers must coordinate their own writes to the shared arena.
 */
struct uefi_pe_loaded_image {
	void *arena_base;
	phys_addr_t arena_phys_base;
	struct uefi_pe_arena_layout layout;
	void *image_base;
	void *runtime_base;
	void *entry;
	phys_addr_t entry_phys;
	struct uefi_pe_info pe;
};

/**
 * uefi_pe_image_get - acquire the singleton image and pin its owner module
 *
 * The caller must already have a valid reference to these API symbols, through
 * normal module dependency resolution or symbol_get().
 * Return: a descriptor to be released with uefi_pe_image_put(), or NULL if the
 * image is not ready or the owner is unloading. Does not allocate or sleep.
 */
const struct uefi_pe_loaded_image *uefi_pe_image_get(void);

/**
 * uefi_pe_image_put - release exactly one successful image acquisition
 * @image: the descriptor returned by uefi_pe_image_get()
 *
 * Do not access the descriptor or arena after this call unless another image
 * reference is held. Never call this for a failed acquisition.
 */
void uefi_pe_image_put(const struct uefi_pe_loaded_image *image);

#endif
