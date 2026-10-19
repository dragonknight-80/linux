// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cma.h>
#include <linux/dma-map-ops.h>
#include <linux/firmware.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include "pe_arch.h"
#include "uefi_pe_loader.h"

static char *firmware;
module_param(firmware, charp, 0400);
MODULE_PARM_DESC(firmware, "EFI PE32+ filename relative to /lib/firmware");

static unsigned int runtime_mb = 16;
module_param(runtime_mb, uint, 0400);
MODULE_PARM_DESC(runtime_mb, "Runtime workspace in MiB, 0 to 256 (default 16)");

static struct uefi_pe_loaded_image loaded;
static bool image_ready;

#if IS_ENABLED(CONFIG_DMA_CMA)
static struct cma *arena_cma;
static struct page *arena_pages;

static void free_arena(void)
{
	vunmap(loaded.arena_base);
	if (arena_pages) {
		WARN_ON_ONCE(!cma_release(arena_cma, arena_pages,
					  loaded.layout.total_size >> PAGE_SHIFT));
		arena_pages = NULL;
	}
	loaded.arena_base = NULL;
}

static int allocate_arena(void)
{
	unsigned long count = loaded.layout.total_size >> PAGE_SHIFT;
	struct page **pages;
	unsigned long i;

	/* This module has no device-specific pool: use the boot-time default. */
	arena_cma = dev_get_cma_area(NULL);
	if (!arena_cma) {
		pr_err("uefi_pe_loader: no default CMA pool; configure cma= at boot\n");
		return -ENODEV;
	}
	arena_pages = cma_alloc(arena_cma, count, 0, false);
	if (!arena_pages) {
		pr_err("uefi_pe_loader: CMA could not allocate %zu contiguous bytes\n",
		       loaded.layout.total_size);
		return -ENOMEM;
	}
	pages = kvmalloc_array(count, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		goto fail;
	for (i = 0; i < count; i++)
		pages[i] = pfn_to_page(page_to_pfn(arena_pages) + i);
	/* Physical contiguity comes from CMA; PAGE_KERNEL provides a data mapping. */
	loaded.arena_base = vmap(pages, count, VM_MAP, PAGE_KERNEL);
	kvfree(pages);
	if (!loaded.arena_base)
		goto fail;
	loaded.arena_phys_base = page_to_phys(arena_pages);
	/* CMA allocations may contain old data. Clear image, padding, and runtime. */
	memset(loaded.arena_base, 0, loaded.layout.total_size);
	return 0;
fail:
	free_arena();
	return -ENOMEM;
}
#else
static int allocate_arena(void)
{
	pr_err("uefi_pe_loader: physical arena requires CONFIG_CMA and CONFIG_DMA_CMA\n");
	return -EOPNOTSUPP;
}

static void free_arena(void)
{
}
#endif

static u16 native_machine(void)
{
#if defined(CONFIG_X86_64)
	return UEFI_PE_MACHINE_AMD64;
#elif defined(CONFIG_ARM64)
	return UEFI_PE_MACHINE_ARM64;
#elif defined(CONFIG_RISCV) && defined(CONFIG_64BIT)
	return UEFI_PE_MACHINE_RISCV64;
#else
	return 0;
#endif
}

const struct uefi_pe_loaded_image *uefi_pe_image_get(void)
{
	if (!try_module_get(THIS_MODULE))
		return NULL;
	/* Pair with init's release store to observe all descriptor fields. */
	if (!smp_load_acquire(&image_ready)) {
		module_put(THIS_MODULE);
		return NULL;
	}
	return &loaded;
}
EXPORT_SYMBOL_GPL(uefi_pe_image_get);

void uefi_pe_image_put(const struct uefi_pe_loaded_image *image)
{
	if (WARN_ON_ONCE(image != &loaded))
		return;
	module_put(THIS_MODULE);
}
EXPORT_SYMBOL_GPL(uefi_pe_image_put);

static int __init uefi_pe_loader_init(void)
{
	const struct firmware *fw;
	int ret;

	if (!firmware || !*firmware)
		return -EINVAL;
	if (!uefi_pe_arch_find(native_machine()))
		return -EOPNOTSUPP;
	if (runtime_mb > UEFI_PE_MAX_RUNTIME / SZ_1M)
		return -EINVAL;
	ret = request_firmware_direct(&fw, firmware, NULL);
	if (ret)
		return ret;
	ret = uefi_pe_inspect(fw->data, fw->size, &loaded.pe);
	if (ret)
		goto release;
	if (loaded.pe.machine != native_machine()) {
		ret = -ENOEXEC;
		goto release;
	}
	ret = uefi_pe_plan_arena(loaded.pe.image_size,
				 (size_t)runtime_mb * SZ_1M, PAGE_SIZE,
				 &loaded.layout);
	if (ret)
		goto release;
	ret = allocate_arena();
	if (ret)
		goto release;
	loaded.image_base = loaded.arena_base;
	if (loaded.layout.runtime_size)
		loaded.runtime_base = (u8 *)loaded.arena_base +
				      loaded.layout.runtime_offset;
	ret = uefi_pe_map(fw->data, fw->size, loaded.image_base,
			  loaded.layout.image_span,
			  (unsigned long)loaded.image_base, &loaded.pe);
	if (ret) {
		free_arena();
		goto release;
	}
	loaded.entry = (u8 *)loaded.image_base + loaded.pe.entry_rva;
	loaded.entry_phys = loaded.arena_phys_base + loaded.pe.entry_rva;
	/* The descriptor is immutable after publication. Module refs protect it. */
	smp_store_release(&image_ready, true);
	pr_info("uefi_pe_loader: image %u bytes, runtime %zu bytes, arena %zu bytes, entry RVA %#x; execution disabled\n",
		loaded.pe.image_size, loaded.layout.runtime_size,
		loaded.layout.total_size, loaded.pe.entry_rva);
release:
	release_firmware(fw);
	if (ret)
		pr_err("uefi_pe_loader: image rejected: %d\n", ret);
	return ret;
}

static void __exit uefi_pe_loader_exit(void)
{
	free_arena();
}

module_init(uefi_pe_loader_init);
module_exit(uefi_pe_loader_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("UEFI PE32+ image and runtime arena with retained entry metadata");
