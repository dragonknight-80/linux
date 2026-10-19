// SPDX-License-Identifier: GPL-2.0-only
/* Bounded EFI PE32+ mapper with machine-specific relocation backends. */
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif
#include "pe_image.h"
#include "pe_arch.h"

#define COFF_SIZE 24U /* Includes the four-byte PE signature. */
#define OPT_SIZE 112U
#define SEC_SIZE 40U
#define MAX_SECTIONS 96U
#define EXECUTE 0x20000000U

struct pe_view {
	const u8 *file;
	const u8 *sections;
	const struct uefi_pe_arch *arch;
	u32 headers;
	u32 reloc_rva;
	u32 reloc_size;
	struct uefi_pe_info info;
};

static u16 rd16(const u8 *p)
{
	return (u16)p[0] | (u16)p[1] << 8;
}

static u32 rd32(const u8 *p)
{
	return (u32)rd16(p) | (u32)rd16(p + 2) << 16;
}

static u64 rd64(const u8 *p)
{
	return (u64)rd32(p) | (u64)rd32(p + 4) << 32;
}

static int within(size_t offset, size_t count, size_t limit)
{
	return offset <= limit && count <= limit - offset;
}

static u32 extent(const u8 *section)
{
	u32 virt = rd32(section + 8);
	u32 raw = rd32(section + 16);

	return virt > raw ? virt : raw;
}

static int overlaps(u32 a, u32 an, u32 b, u32 bn)
{
	return an && bn && (u64)a < (u64)b + bn &&
		(u64)b < (u64)a + an;
}

/* Resolve only fully file-backed ranges, never zero-fill or RVA holes. */
static const u8 *file_rva(const struct pe_view *v, u32 rva, u32 size)
{
	const u8 *s;
	unsigned int i;
	u32 start;
	u32 raw;

	if (within(rva, size, v->headers))
		return v->file + rva;
	for (i = 0; i < v->info.sections; i++) {
		s = v->sections + i * SEC_SIZE;
		start = rd32(s + 12);
		raw = rd32(s + 16);
		if (rva >= start && within(rva - start, size, raw))
			return v->file + rd32(s + 20) + (rva - start);
	}
	return NULL;
}

static int section_contains(const struct pe_view *v, u32 rva, u32 size,
			    u32 required_flags)
{
	const u8 *s;
	unsigned int i;
	u32 start;

	for (i = 0; i < v->info.sections; i++) {
		s = v->sections + i * SEC_SIZE;
		start = rd32(s + 12);
		if (rva >= start && within(rva - start, size, extent(s)) &&
		    (rd32(s + 36) & required_flags) == required_flags)
			return 1;
	}
	return 0;
}

static int parse(const void *file, size_t size, struct pe_view *v)
{
	const u8 *f = file;
	const u8 *coff;
	const u8 *opt;
	const u8 *s;
	const u8 *prev;
	const u8 *d;
	u32 pe;
	u32 dirs;
	u32 file_align;
	u32 rva;
	u32 raw;
	u32 off;
	u32 span;
	u32 header_end;
	u16 opt_size;
	u16 flags;
	unsigned int i;
	unsigned int j;

	if (!file || size < 64 || size > UEFI_PE_MAX_FILE)
		return -ENOEXEC;
	if (rd16(f) != 0x5a4d)
		return -ENOEXEC;
	pe = rd32(f + 0x3c);
	if (pe < 64 || !within(pe, COFF_SIZE, size))
		return -ENOEXEC;
	coff = f + pe;
	if (rd32(coff) != 0x00004550)
		return -ENOEXEC;
	v->arch = uefi_pe_arch_find(rd16(coff + 4));
	if (!v->arch)
		return -EOPNOTSUPP;
	v->info.machine = v->arch->machine;
	flags = rd16(coff + 22);
	if (!(flags & 2) || (flags & 0x2000)) /* Executable, not a DLL. */
		return -ENOEXEC;
	if (flags & 1) /* RELOCS_STRIPPED: fixed-address images unsupported. */
		return -EOPNOTSUPP;
	v->info.sections = rd16(coff + 6);
	opt_size = rd16(coff + 20);
	if (!v->info.sections || v->info.sections > MAX_SECTIONS ||
	    opt_size < OPT_SIZE || !within(pe + COFF_SIZE, opt_size, size))
		return -ENOEXEC;
	opt = coff + COFF_SIZE;
	if (rd16(opt) != 0x20b || rd16(opt + 68) != 10)
		return -ENOEXEC;
	v->info.entry_rva = rd32(opt + 16);
	v->info.preferred_base = rd64(opt + 24);
	v->info.image_size = rd32(opt + 56);
	v->headers = rd32(opt + 60);
	file_align = rd32(opt + 36);
	dirs = rd32(opt + 108);
	/* A deliberately narrow, common UEFI layout: 4 KiB sections. */
	if (rd32(opt + 32) != 4096 || file_align < 512 || file_align > 4096 ||
	    (file_align & (file_align - 1)) ||
	    (v->info.preferred_base & 0xffff) ||
	    !v->info.image_size || v->info.image_size > UEFI_PE_MAX_IMAGE ||
	    (v->info.image_size & 4095) || !v->headers ||
	    (v->headers % file_align) || v->headers > size ||
	    v->headers > v->info.image_size || dirs > 16 ||
	    !within(OPT_SIZE, dirs * 8, opt_size))
		return -ENOEXEC;
	if (v->info.preferred_base > ~(u64)0 - v->info.image_size)
		return -ENOEXEC;
	header_end = pe + COFF_SIZE + opt_size;
	if (!within(header_end, v->info.sections * SEC_SIZE, v->headers))
		return -ENOEXEC;
	v->file = f;
	v->sections = f + header_end;
	for (i = 0; i < v->info.sections; i++) {
		s = v->sections + i * SEC_SIZE;
		rva = rd32(s + 12);
		raw = rd32(s + 16);
		off = rd32(s + 20);
		span = extent(s);
		if ((rva & 4095) || (span && rva < v->headers) ||
		    !within(rva, span, v->info.image_size) ||
		    (raw && (off < v->headers || off % file_align ||
			     raw % file_align || !within(off, raw, size))))
			return -ENOEXEC;
		for (j = 0; j < i; j++) {
			prev = v->sections + j * SEC_SIZE;
			if (overlaps(rva, span, rd32(prev + 12), extent(prev)) ||
			    overlaps(off, raw, rd32(prev + 20), rd32(prev + 16)))
				return -ENOEXEC;
		}
	}
	if (!section_contains(v, v->info.entry_rva, 1, EXECUTE))
		return -ENOEXEC;
	v->reloc_rva = 0;
	v->reloc_size = 0;
	for (i = 0; i < dirs; i++) {
		d = opt + OPT_SIZE + i * 8;
		rva = rd32(d);
		span = rd32(d + 4);
		if (!rva && !span)
			continue;
		if (!rva || !span)
			return -ENOEXEC;
		/* Certificate directory uses a file offset, unlike other dirs. */
		if (i == 4) {
			if ((rva & 7) || !within(rva, span, size))
				return -ENOEXEC;
			continue;
		}
		if (!file_rva(v, rva, span))
			return -ENOEXEC;
		/* Imports, TLS, load config, IAT, delay imports, managed code. */
		if (i == 1 || i == 9 || i == 10 || i == 12 || i == 13 || i == 14)
			return -EOPNOTSUPP;
		if (i == 5) {
			v->reloc_rva = rva;
			v->reloc_size = span;
		}
	}
	if (!v->reloc_size)
		return -EOPNOTSUPP;
	return 0;
}

/* Read relocation metadata from the immutable file, not the patched image. */
static int relocate(const struct pe_view *v, u8 *image, u64 delta)
{
	const u8 *table = file_rva(v, v->reloc_rva, v->reloc_size);
	const u8 *block;
	u32 pos = 0;
	u32 bytes;
	u32 page;
	u32 i;
	u32 target;
	u16 entry;
	u16 type;
	unsigned int width;

	while (pos < v->reloc_size) {
		if (!within(pos, 8, v->reloc_size))
			return -ENOEXEC;
		block = table + pos;
		page = rd32(block);
		bytes = rd32(block + 4);
		if ((page & 4095) || page >= v->info.image_size ||
		    bytes < 8 || (bytes & 3) ||
		    !within(pos, bytes, v->reloc_size))
			return -ENOEXEC;
		for (i = 8; i < bytes; i += 2) {
			entry = rd16(block + i);
			type = entry >> 12;
			if (!type) /* IMAGE_REL_BASED_ABSOLUTE padding */
				continue;
			width = v->arch->reloc_size(type);
			if (!width)
				return -EOPNOTSUPP;
			target = page + (entry & 4095);
			if (!section_contains(v, target, width, 0))
				return -ENOEXEC;
			if (image)
				v->arch->relocate(type, image + target, delta);
		}
		pos += bytes;
	}
	return 0;
}

int uefi_pe_inspect(const void *file, size_t size, struct uefi_pe_info *info)
{
	struct pe_view v;
	int ret;

	if (!info)
		return -EINVAL;
	ret = parse(file, size, &v);
	if (!ret)
		ret = relocate(&v, NULL, 0);
	if (!ret)
		*info = v.info;
	return ret;
}

int uefi_pe_map(const void *file, size_t size, void *image, size_t capacity,
		u64 load_address, struct uefi_pe_info *info)
{
	struct pe_view v;
	const u8 *s;
	unsigned int i;
	int ret;

	if (!image || !info || (load_address & 4095))
		return -EINVAL;
	ret = parse(file, size, &v);
	if (ret)
		return ret;
	if (capacity < v.info.image_size)
		return -ENOSPC;
	if (load_address > ~(u64)0 - v.info.image_size)
		return -EINVAL;
	/* Validate all relocation records before modifying output. */
	ret = relocate(&v, NULL, 0);
	if (ret)
		return ret;
	memset(image, 0, v.info.image_size);
	memcpy(image, file, v.headers);
	for (i = 0; i < v.info.sections; i++) {
		s = v.sections + i * SEC_SIZE;
		if (rd32(s + 16))
			memcpy((u8 *)image + rd32(s + 12),
			       (const u8 *)file + rd32(s + 20), rd32(s + 16));
	}
	ret = relocate(&v, image, load_address - v.info.preferred_base);
	if (!ret)
		*info = v.info;
	return ret;
}
