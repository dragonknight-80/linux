// SPDX-License-Identifier: GPL-2.0-only
/* Exercise the exact parser/relocator linked into the kernel module. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pe_image.h"
#include "pe_arch.h"
#include "image_arena.h"

#define FILE_SIZE 0x800
#define IMAGE_SIZE 0x4000
#define OPT 0x98
#define SECTIONS 0x188
#define PREFERRED 0x140000000ULL
#define LOAD 0x200000000ULL
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

static unsigned int checks;

#define CHECK(expr) do { \
	checks++; \
	if (!(expr)) { \
		fprintf(stderr, "line %d: %s\n", __LINE__, #expr); \
		exit(1); \
	} \
} while (0)

static void put16(u8 *p, u16 value)
{
	p[0] = value;
	p[1] = value >> 8;
}

static void put32(u8 *p, u32 value)
{
	put16(p, value);
	put16(p + 2, value >> 16);
}

static void put64(u8 *p, u64 value)
{
	put32(p, value);
	put32(p + 4, value >> 32);
}

static u64 get64(const u8 *p)
{
	u64 value = 0;
	int i;

	for (i = 7; i >= 0; i--)
		value = (value << 8) | p[i];
	return value;
}

static void section(u8 *p, const char *name, u32 virt, u32 rva,
		    u32 offset, u32 flags)
{
	memcpy(p, name, strlen(name));
	put32(p + 8, virt);
	put32(p + 12, rva);
	put32(p + 16, 0x200);
	put32(p + 20, offset);
	put32(p + 36, flags);
}

static void fixture(u8 *f)
{
	memset(f, 0, FILE_SIZE);
	put16(f, 0x5a4d);
	put32(f + 0x3c, 0x80);
	put32(f + 0x80, 0x4550);
	put16(f + 0x84, 0x8664);
	put16(f + 0x86, 3);
	put16(f + 0x94, 240);
	put16(f + 0x96, 2);
	put16(f + OPT, 0x20b);
	put32(f + OPT + 16, 0x1000);
	put64(f + OPT + 24, PREFERRED);
	put32(f + OPT + 32, 4096);
	put32(f + OPT + 36, 512);
	put32(f + OPT + 56, IMAGE_SIZE);
	put32(f + OPT + 60, 512);
	put16(f + OPT + 68, 10);
	put32(f + OPT + 108, 16);
	put32(f + OPT + 112 + 5 * 8, 0x3000);
	put32(f + OPT + 116 + 5 * 8, 12);
	section(f + SECTIONS, ".text", 0x200, 0x1000, 0x200, 0x60000020);
	section(f + SECTIONS + 40, ".data", 0x1000, 0x2000, 0x400, 0xc0000040);
	section(f + SECTIONS + 80, ".reloc", 0x200, 0x3000, 0x600, 0x42000040);
	f[0x200] = 0xc3; /* RET; never executed. */
	put64(f + 0x400, PREFERRED + 0x1234);
	put32(f + 0x600, 0x2000);
	put32(f + 0x604, 12);
	put16(f + 0x608, 0xa000); /* DIR64 at .data + 0 */
}

static void valid_image(u8 *f, u8 *image)
{
	struct uefi_pe_info info;
	unsigned int i;

	fixture(f);
	CHECK(!uefi_pe_inspect(f, FILE_SIZE, &info));
	CHECK(info.sections == 3 && info.image_size == IMAGE_SIZE);
	CHECK(info.entry_rva == 0x1000 && info.preferred_base == PREFERRED);
	CHECK(info.machine == UEFI_PE_MACHINE_AMD64);
	memset(image, 0xa5, IMAGE_SIZE);
	CHECK(!uefi_pe_map(f, FILE_SIZE, image, IMAGE_SIZE, LOAD, &info));
	CHECK(!memcmp(image, f, 0x200));
	CHECK(image[0x1000] == 0xc3);
	CHECK(get64(image + 0x2000) == LOAD + 0x1234);
	CHECK(get64(f + 0x400) == PREFERRED + 0x1234);
	for (i = 0x2200; i < 0x3000; i++)
		CHECK(image[i] == 0); /* BSS */
	for (i = 0x200; i < 0x1000; i++)
		CHECK(image[i] == 0); /* Header-to-section gap */
	CHECK(!uefi_pe_map(f, FILE_SIZE, image, IMAGE_SIZE, 0x40000000, &info));
	CHECK(get64(image + 0x2000) == 0x40001234);
	CHECK(!uefi_pe_map(f, FILE_SIZE, image, IMAGE_SIZE, PREFERRED, &info));
	CHECK(get64(image + 0x2000) == PREFERRED + 0x1234);
	CHECK(uefi_pe_map(f, FILE_SIZE, image, IMAGE_SIZE - 1, LOAD, &info) == -ENOSPC);
	CHECK(uefi_pe_map(f, FILE_SIZE, image, IMAGE_SIZE, LOAD + 1, &info) == -EINVAL);
	CHECK(uefi_pe_map(f, FILE_SIZE, image, IMAGE_SIZE, ~(u64)4095, &info) == -EINVAL);
	CHECK(uefi_pe_inspect(NULL, FILE_SIZE, &info) == -ENOEXEC);
	CHECK(uefi_pe_inspect(f, FILE_SIZE, NULL) == -EINVAL);
}

static void rejection_tests(u8 *f)
{
	struct uefi_pe_info info;
	unsigned int i;
	u8 *short_file;

	fixture(f);
	/* Allocate exact lengths so ASan detects reads beyond declared input. */
	for (i = 0; i < FILE_SIZE; i++) {
		short_file = malloc(i ? i : 1);
		CHECK(short_file);
		memcpy(short_file, f, i);
		CHECK(uefi_pe_inspect(short_file, i, &info) < 0);
		free(short_file);
	}

#define REJECT(change, error) do { \
	fixture(f); \
	change; \
	CHECK(uefi_pe_inspect(f, FILE_SIZE, &info) == (error)); \
} while (0)
	REJECT(f[0] = 0, -ENOEXEC);
	REJECT(put32(f + 0x3c, 0xfffffff0), -ENOEXEC);
	REJECT(put16(f + 0x84, UEFI_PE_MACHINE_ARM64), -EOPNOTSUPP);
	REJECT(put16(f + 0x84, UEFI_PE_MACHINE_RISCV64), -EOPNOTSUPP);
	REJECT(put16(f + 0x84, 0xffff), -EOPNOTSUPP);
	REJECT(put16(f + 0x86, 97), -ENOEXEC);
	REJECT(put16(f + 0x94, 110), -ENOEXEC);
	REJECT(put16(f + OPT, 0x10b), -ENOEXEC);
	REJECT(put16(f + OPT + 68, 3), -ENOEXEC);
	REJECT(put32(f + OPT + 56, 0xfffff000), -ENOEXEC);
	REJECT(put32(f + OPT + 60, 0x100), -ENOEXEC);
	REJECT(put32(f + OPT + 108, 17), -ENOEXEC);
	REJECT(put32(f + OPT + 16, 0x2000), -ENOEXEC); /* NX entry */
	REJECT(put32(f + OPT + 16, 0x1800), -ENOEXEC); /* RVA hole */
	REJECT(put32(f + SECTIONS + 12, 0), -ENOEXEC);
	REJECT(put32(f + SECTIONS + 40 + 12, 0x1000), -ENOEXEC);
	REJECT(put32(f + SECTIONS + 40 + 20, 0x200), -ENOEXEC);
	REJECT(put32(f + SECTIONS + 20, 0xfffffe00), -ENOEXEC);
	REJECT(put32(f + SECTIONS + 8, 0xffffffff), -ENOEXEC);
	REJECT(put32(f + 0x604, 0), -ENOEXEC);
	REJECT(put32(f + 0x604, 10), -ENOEXEC);
	REJECT(put32(f + 0x604, 16), -ENOEXEC);
	REJECT(put32(f + 0x600, 0xfffff000), -ENOEXEC);
	REJECT(put16(f + 0x608, 0x3000), -EOPNOTSUPP);
	REJECT(put32(f + 0x600, 0x1000);
	       put16(f + 0x608, 0xa800), -ENOEXEC);
	REJECT(put32(f + 0x600, 0);
	       put16(f + 0x608, 0xa080), -ENOEXEC);
	REJECT(put32(f + 0x600, 0x3000);
	       put16(f + 0x608, 0xaffc), -ENOEXEC);
	REJECT(put16(f + 0x96, 3), -EOPNOTSUPP);
	REJECT(put32(f + OPT + 112 + 5 * 8, 0x2800), -ENOEXEC);
	REJECT(put32(f + OPT + 116 + 5 * 8, 0), -ENOEXEC);
	REJECT(put32(f + OPT + 112 + 5 * 8, 0);
	       put32(f + OPT + 116 + 5 * 8, 0), -EOPNOTSUPP);
	REJECT(put32(f + OPT + 112 + 1 * 8, 0x2000);
	       put32(f + OPT + 116 + 1 * 8, 8), -EOPNOTSUPP);
#undef REJECT
}

static u32 random_word(u32 *seed)
{
	*seed ^= *seed << 13;
	*seed ^= *seed >> 17;
	*seed ^= *seed << 5;
	return *seed;
}

static void mutation_tests(u8 *f, u8 *image)
{
	struct uefi_pe_info info;
	u32 seed = 0x12345678;
	unsigned int i;
	unsigned int j;
	unsigned int count;
	int ret;

	for (i = 0; i < 20000; i++) {
		fixture(f);
		count = random_word(&seed) % 8 + 1;
		for (j = 0; j < count; j++) {
			u32 pos = random_word(&seed) % FILE_SIZE;

			f[pos] ^= random_word(&seed);
		}
		ret = uefi_pe_inspect(f, FILE_SIZE, &info);
		if (!ret && info.image_size <= IMAGE_SIZE)
			CHECK(!uefi_pe_map(f, FILE_SIZE, image, IMAGE_SIZE, LOAD, &info));
	}
}

static void arena_tests(u8 *f)
{
	struct uefi_pe_arena_layout layout;
	struct uefi_pe_info info;
	const struct uefi_pe_arch *arch;
	const size_t granules[] = { 4096, 16384, 65536 };
	const size_t runtimes[] = { 0, 1, 4097, 16385 };
	size_t i;
	size_t j;
	size_t k;
	u8 *arena;
	u8 *entry;

	fixture(f);
	arch = uefi_pe_arch_find(UEFI_PE_MACHINE_AMD64);
	CHECK(arch && arch->machine == UEFI_PE_MACHINE_AMD64);
	CHECK(arch->reloc_size(10) == 8);
	CHECK(arch->reloc_size(3) == 0);
	CHECK(!uefi_pe_arch_find(UEFI_PE_MACHINE_ARM64));
	CHECK(!uefi_pe_arch_find(UEFI_PE_MACHINE_RISCV64));
	for (i = 0; i < ARRAY_SIZE(granules); i++) {
		for (j = 0; j < ARRAY_SIZE(runtimes); j++) {
			CHECK(!uefi_pe_plan_arena(IMAGE_SIZE, runtimes[j], granules[i], &layout));
			CHECK(layout.image_span >= IMAGE_SIZE);
			CHECK(layout.image_span - IMAGE_SIZE < granules[i]);
			CHECK(layout.runtime_offset == layout.image_span);
			CHECK(layout.runtime_offset % granules[i] == 0);
			CHECK(layout.runtime_size >= runtimes[j]);
			CHECK(layout.runtime_size - runtimes[j] < granules[i]);
			CHECK(layout.total_size % granules[i] == 0);
			CHECK(layout.total_size == layout.runtime_offset + layout.runtime_size);
			/* The mapper must leave padding, runtime, and the end canary untouched. */
			arena = malloc(layout.total_size + 16);
			CHECK(arena);
			memset(arena, 0x5a, layout.total_size + 16);
			CHECK(!uefi_pe_map(f, FILE_SIZE, arena, layout.image_span, LOAD, &info));
			entry = arena + info.entry_rva;
			CHECK(entry == arena + 0x1000 && *entry == 0xc3);
			CHECK(get64(arena + 0x2000) == LOAD + 0x1234);
			for (k = IMAGE_SIZE; k < layout.total_size + 16; k++)
				CHECK(arena[k] == 0x5a);
			free(arena);
		}
	}
	CHECK(!uefi_pe_plan_arena(UEFI_PE_MAX_IMAGE, UEFI_PE_MAX_RUNTIME, 65536, &layout));
	CHECK(layout.total_size == (size_t)UEFI_PE_MAX_IMAGE + UEFI_PE_MAX_RUNTIME);
	CHECK(!uefi_pe_plan_arena(1, 1, 65536, &layout));
	CHECK(layout.image_span == 65536 && layout.runtime_size == 65536);
	CHECK(uefi_pe_plan_arena(0, 4096, 4096, &layout) == -EINVAL);
	CHECK(uefi_pe_plan_arena(UEFI_PE_MAX_IMAGE + 1, 0, 4096, &layout) == -EINVAL);
	CHECK(uefi_pe_plan_arena(4096, UEFI_PE_MAX_RUNTIME + 1, 4096, &layout) == -EINVAL);
	CHECK(uefi_pe_plan_arena(4096, ~(size_t)0, 4096, &layout) == -EINVAL);
	CHECK(uefi_pe_plan_arena(4096, 4096, 0, &layout) == -EINVAL);
	CHECK(uefi_pe_plan_arena(4096, 4096, 2048, &layout) == -EINVAL);
	CHECK(uefi_pe_plan_arena(4096, 4096, 12288, &layout) == -EINVAL);
	CHECK(uefi_pe_plan_arena(4096, 4096, 131072, &layout) == -EINVAL);
	CHECK(uefi_pe_plan_arena(4096, 4096, 4096, NULL) == -EINVAL);
}

int main(void)
{
	u8 *file = malloc(FILE_SIZE);
	u8 *image = malloc(IMAGE_SIZE);

	CHECK(file && image);
	valid_image(file, image);
	rejection_tests(file);
	mutation_tests(file, image);
	arena_tests(file);
	free(image);
	free(file);
	printf("PASS: %u checks, all %u truncations, 20000 mutated images\n",
	       checks, FILE_SIZE);
	return 0;
}
