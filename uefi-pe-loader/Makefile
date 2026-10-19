# SPDX-License-Identifier: GPL-2.0-only
ifneq ($(KERNELRELEASE),)
obj-m := uefi_pe_loader_sample.o
uefi_pe_loader_sample-y := uefi_pe_loader.o pe_image.o pe_arch.o image_arena.o
else
KDIR ?= /lib/modules/$(shell uname -r)/build
HOSTCC ?= cc
HOSTCPPFLAGS += -I../../tools/include
TEST_BIN ?= /tmp/uefi-pe-loader-test
TEST_CFLAGS ?= -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer

.PHONY: all modules test clean
all: modules
modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
test:
	$(HOSTCC) $(HOSTCPPFLAGS) -std=c11 -Wall -Wextra -Werror $(TEST_CFLAGS) \
		pe_image.c pe_arch.c image_arena.c pe_image_test.c -o $(TEST_BIN)
	$(TEST_BIN)
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
endif
