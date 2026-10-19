# UEFI PE32+ loader and runtime arena

This out-of-tree sample loads and relocates a UEFI application's PE image into
Linux kernel memory. It retains one allocation for the image and a future
runtime, and exposes the relocated entry address through a kernel reference
API. **It does not execute the application.** The allocation remains writable
and non-executable and is released when the module unloads.

## Memory ownership and layout

```text
arena_base / image_base
    | PE headers, mapped sections, BSS (pe.image_size bytes)
    | padding to the host PAGE_SIZE (layout.image_span total)
runtime_base = arena_base + layout.runtime_offset
    | zeroed runtime workspace (layout.runtime_size bytes)
end = arena_base + layout.total_size
```

`runtime_mb` reserves 16 MiB by default, configurable from 0 to 256 MiB at
module load. Zero disables the workspace and gives a NULL `runtime_base`.
Both regions belong to one **physically contiguous CMA allocation**, mapped
into contiguous kernel virtual space using `vmap(..., PAGE_KERNEL)`. The entire
arena is explicitly zeroed before mapping the image; the mapper is given only
the image region's capacity. Runtime space is currently raw storage
for future stacks, heap, service tables, or other state, with no runtime
allocator or stack setup yet. Consumers coordinate access to this shared space.

The CMA pages remain allocated until normal module unload, which unmaps the
virtual arena and releases the entire physical range back to the same pool.
Allocation fails if CMA is unavailable or cannot provide a single contiguous
range; there is no scattered-page fallback. CMA's pool is reserved at boot,
while the module claims its part of that pool when it loads. This does not
create an EFI reserved-memory descriptor or reserve an arbitrary fixed address.

`arena_phys_base` identifies the start of the physical range. Image and runtime
physical addresses are this base plus their respective arena offsets. Use these
fields rather than `virt_to_phys()` on the `vmap` address. Physical addresses are
not necessarily device DMA addresses; this is not a device DMA mapping.
Image relocations currently use the Linux virtual base. A future identity-mapped
or other virtual execution address therefore requires relocating again from the
original image. Acquired references prevent normal unload, not forced removal.

## Acquiring the image and entry

Include `uefi_pe_loader.h` from another kernel module and link against this
module's exported GPL symbols:

```c
const struct uefi_pe_loaded_image *image;

image = uefi_pe_image_get();
if (!image)
	return -ENODEV;

/* image->entry == (u8 *)image->image_base + image->pe.entry_rva */
/* image->entry_phys == image->arena_phys_base + image->pe.entry_rva */
/* image->runtime_base and image->layout.runtime_size describe workspace. */
/* Keep this reference for as long as any pointer into the arena is used. */

uefi_pe_image_put(image);
```

The descriptor also exposes the physical arena base and entry address, virtual
arena base and layout, actual PE image size,
preferred base, entry RVA, section count, and machine ID. `entry` is an untyped
kernel virtual address: no callable ABI or executable permission is implied.
The descriptor is immutable after publication. Each successful `get()` pins the
loader module and must have exactly one matching `put()`. Do not retain any
arena pointer after the final reference is released. Ordinary symbol linking
also creates a module dependency; dynamic users must retain their `symbol_get()`
references while using the API.

When building a consumer separately, pass
`KBUILD_EXTRA_SYMBOLS=/path/to/uefi-pe-loader/Module.symvers` so modpost can
resolve `uefi_pe_image_get` and `uefi_pe_image_put`. Load the loader first with
its firmware parameter, then load the consumer. An explicit `rmmod` of the
loader remains blocked while a consumer module depends on it or image references
are outstanding. No raw kernel pointers are published through userspace files.

## Future execution

Linux has already called `ExitBootServices()`. Firmware Boot Services such as
`LoadImage`, `StartImage`, `AllocatePages`, and `GetMemoryMap` cannot be used by
a Linux module. Passing a firmware system-table pointer to an application's
entry point would not restore those services. Executing general UEFI apps here
would require a separately implemented UEFI environment and protocols, the
x86-64 EFI calling convention, executable memory management, and an explicit
lifetime/cleanup contract. Entry exposure does not establish those prerequisites.

## Supported format

- AMD64 PE32+, EFI application subsystem, at most 96 sections.
- 4 KiB section alignment; power-of-two file alignment from 512 to 4096 bytes.
- Headers and sections are checked before mapping; section and file ranges
  cannot overlap, wrap, or run beyond their containing image/file.
- Entry point must lie in an executable section. Section data is copied and
  BSS and unused image space are zeroed.
- Base relocation blocks support `DIR64` and `ABSOLUTE` padding. Relocations
  must address a complete eight-byte value within a mapped section. Metadata
  is read from the immutable source file, even if relocations patch `.reloc`.
- Relocation information is required. Fixed-address images, PE32, TE images,
  Windows DLLs, imports/IAT/delay imports, TLS, load configuration, and managed
  images are rejected. This is a deliberately limited image mapper.
- File and image limits are 64 MiB and 128 MiB respectively. Directory ranges
  must be fully file-backed in one section or in the headers; certificate
  table bounds are checked as file offsets.

## Architecture extension points

`pe_image.c` handles PE layout, bounds, section copying, and relocation block
walking. `pe_arch.c` selects a backend by PE machine ID and provides relocation
width and patch callbacks; only the AMD64 backend is implemented. Unknown or
unimplemented machines return `-EOPNOTSUPP`. The kernel wrapper also requires the
image machine to match the host. Defining an ARM64 or RISC-V machine ID does not
enable support for that target.

`image_arena.c` takes the host allocation granule separately from the PE section
alignment. Its layout is tested with 4 KiB, 16 KiB, and 64 KiB host pages, so
larger arm64 pages do not place runtime state in an image page. PE section
alignment is still restricted to 4 KiB; supporting other image layouts is a
separate parser change.

For arm64 or RISC-V 64, add and test a native backend in `pe_arch.c` (the native
machine selection is already in the kernel wrapper). Relocation type numbers
must be interpreted for that machine; RISC-V instruction relocations cannot be
treated as AMD64 relocations. Then cross-build and validate the kernel module
on that architecture. Future execution additionally needs the appropriate EFI
ABI, stack alignment, instruction-cache synchronization, per-page permissions,
and any required page-table/CPU-state transition. Those are separate from
mapping an image, and this API deliberately exposes no function-pointer type.

PE certificate presence does **not** establish trust: this sample does not
verify Authenticode signatures or enforce firmware Secure Boot policy. It
only maps bytes and applies relocations. No memory map is fabricated or handed
off, and no firmware runtime service is invoked.

## Build

Use a configured, fully built x86-64 kernel tree matching the intended target:

```sh
cd /path/to/linux/samples/uefi-pe-loader
make KDIR=/path/to/kernel-build
```

The target needs `CONFIG_MODULES=y`, `CONFIG_CMA=y`, `CONFIG_DMA_CMA=y`, and
`CONFIG_FW_LOADER=y` (or `m`, with its module available). Enable
`CONFIG_MODULE_UNLOAD=y` to support unloading.
Distribution kernel development packages may supply the
prepared build tree at `/lib/modules/$(uname -r)/build`, the default `KDIR`.
For a custom kernel with module versioning, `modules_prepare` alone is not
enough: use its full build and matching `Module.symvers`.

Configure a default CMA pool at boot, for example with the kernel command-line
argument `cma=512M`, or an equivalent nonzero `CONFIG_CMA_SIZE_MBYTES`. It must
have a free contiguous range at least as large as the rounded image plus runtime
workspace. A 512 MiB pool covers this sample's maximum 128 MiB image plus
256 MiB runtime request when the necessary range is available. CMA can fail
because of other consumers or unmovable pages even when its total free count
appears sufficient. Reserving or enlarging this pool requires rebooting the
target; the module cannot establish an early-boot reservation after Linux boots.

On a matching test machine, install an image in the firmware search path and
load the module as root:

```sh
install -m 0644 MyApp.efi /lib/firmware/MyApp.efi
insmod ./uefi_pe_loader_sample.ko firmware=MyApp.efi runtime_mb=16
dmesg | tail
rmmod uefi_pe_loader_sample
```

The `firmware` parameter names a file relative to the standard firmware search
paths. A successful load logs image, runtime, and arena sizes and the entry RVA,
followed by `execution disabled`. Kernel consumers use the reference API; there
is no userspace pointer exposure or execution switch. Module signing requirements
of the target kernel still apply. Reload the module to load another image.

`-ENOEXEC` indicates malformed or incompatible input; `-EOPNOTSUPP` indicates
an unsupported PE feature or architecture. Invalid arena settings return
`-EINVAL`; unavailable CMA support returns `-EOPNOTSUPP`, a missing default pool
returns `-ENODEV`, and allocation or mapping failure returns `-ENOMEM`.
Firmware retrieval failures preserve
their underlying errno. Only use administrator-provided local firmware files:
the firmware API reads a file before the parser enforces its size limit.

## Tests

```sh
make test
```

Tests compile the same mapper, architecture backend, and arena planner linked
into the module as a host program with AddressSanitizer and
UndefinedBehaviorSanitizer, using the types from the kernel's `tools/include`
headers. They verify section
mapping, zero-fill, positive/negative/zero relocation deltas, input immutability,
capacity/alignment checks, every truncation of a valid fixture, malformed
headers and relocations, unsupported features, and 20,000 deterministic input
mutations. Arena tests cover page granules, runtime boundaries, entry address
calculation, zero/maximum workspace, invalid sizes, and mapping without touching
runtime storage. No PE code is executed. These host tests do not exercise kernel
physical allocation, virtual mapping, or module reference counting; those need
a matching test kernel booted with a CMA pool.
The test executable defaults to `/tmp/uefi-pe-loader-test`; override `TEST_BIN`
for concurrent runs.
