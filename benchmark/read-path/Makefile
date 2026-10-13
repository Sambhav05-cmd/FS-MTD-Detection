CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool
BUILD := build
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)

.PHONY: all clean
all: $(BUILD)/read_lsm.bpf.o $(BUILD)/read-lsm

$(BUILD):
	mkdir -p $@

$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@

$(BUILD)/read_lsm.bpf.o: read_lsm.bpf.c read_common.h $(BUILD)/vmlinux.h
	$(CLANG) -O2 -g -target bpf -I$(BUILD) $(LIBBPF_CFLAGS) -c $< -o $@

$(BUILD)/read-lsm: read_lsm.c read_common.h | $(BUILD)
	$(CC) -O2 -g -Wall -Wextra -Werror $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

clean:
	rm -rf $(BUILD)
