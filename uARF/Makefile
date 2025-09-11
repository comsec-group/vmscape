uARF_ROOT := $(abspath $(CURDIR))

CONFIG := $(uARF_ROOT)/.config
include $(CONFIG)

ifeq ($(PLATFORM),)
	$(error Please define PLATFORM)
endif

PLATFORM_CONFIG := $(uARF_ROOT)/config/$(PLATFORM).config
include $(PLATFORM_CONFIG)

COMMON_DEFINE := -Dzen4=1 -Dzen5=2 -Dskylake=3

ifeq ($(HOSTNAME), ee-tik-cn128)
    COMMON_DEFINE += -DUARCH=zen4
else ifeq ($(HOSTNAME), ee-tik-cn145)
    COMMON_DEFINE += -DUARCH=zen5
else ifeq ($(HOSTNAME), jcarch)
    COMMON_DEFINE += -DUARCH=skylake
else
    $(warning "Unrecognised system '${HOSTNAME}'")
endif


uARF_SRC := $(uARF_ROOT)/src
uARF_INCL := $(uARF_ROOT)/include
uARF_TEST := $(uARF_ROOT)/tests
uARF_KMOD := $(uARF_ROOT)/kmods

CC := gcc
AR := ar

COMMON_INCLUDES := -I$(uARF_INCL)

# ifdef KTF_ROOT
# export __KTF__
# COMMON_INCLUDES += -I$(KTF_ROOT)/include
# endif

COMMON_FLAGS := $(COMMON_INCLUDES) $(COMMON_DEFINE) -MP -MMD
AFLAGS := $(COMMON_FLAGS) -D__ASSEMBLY__
# WARNING Changing the optimisation leads to different overheads of the measurement function
CFLAGS := $(COMMON_FLAGS) -Wall -Wextra -g -static -O3

SOURCES     := $(shell find $(uARF_SRC) -name \*.c)
HEADERS     := $(shell find $(uARF_INCL) $(uARF_KMOD) -name \*.h)
ASM_SOURCES := $(shell find $(uARF_SRC) $(uARF_INCL) -name \*.S)

OBJS := $(SOURCES:%.c=%.o)
OBJS += $(ASM_SOURCES:%.S=%.o)

LIBRARY_NAME := uarf
LIBRARY := lib$(LIBRARY_NAME).a

LIBRARY_PREFIX = /usr/local
LIBRARY_INCLUDE_DIR = $(LIBRARY_PREFIX)/include/$(LIBRARY_NAME)
LIBRARY_LIB_DIR = $(LIBRARY_PREFIX)/lib

# LDFLAGS := -L $(uARF_ROOT) -l$(LIBRARY_NAME)

ifneq ($(TESTCASE),)
TESTCASE_BASE := $(uARF_TEST)/$(TESTCASE)
TESTCASE_BIN := $(notdir $(TESTCASE)).bin
TESTCASE_C := $(TESTCASE_BASE).c
TESTCASE_H := $(wildcard $(TESTCASE_BASE).h)
TESTCASE_ASM := $(wildcard $(TESTCASE_BASE)_asm.S)
TESTCASE_OBJS := $(TESTCASE_C:%.c=%.o) $(TESTCASE_ASM:%.S=%.o)
endif

ifneq ($(V), 1)
	VERBOSE=@
endif

all: $(LIBRARY) kmods test

$(LIBRARY): $(OBJS)
	@echo "AR " $@
	$(VERBOSE) $(AR) rcs $@ $^

%.o: %.S
	@echo "AS " $@
	$(VERBOSE) $(CC) -c -o $@ $(AFLAGS) $<

%.o: %.c
	@echo "CC " $@
	$(VERBOSE) $(CC) -c -o $@ $(CFLAGS) $<

DEPFILES := $(OBJS:.o=.d)
-include $(wildcard $(DEPFILES))

.PHONY: test
test: $(TESTCASE_C) $(OBJS) $(TESTCASE_OBJS)
	@echo "CC Test " $(TESTCASE)
	$(VERBOSE) $(CC) $(CFLAGS) -o $(TESTCASE_BIN) $(filter %.o, $^)

.PHONY: clean
clean:
	@echo "Clean"
	$(VERBOSE) find $(uARF_ROOT) -name \*.d -delete
	$(VERBOSE) find $(uARF_ROOT) -name \*.o -delete
	$(VERBOSE) find $(uARF_ROOT) -name $(LIBRARY) -delete
	$(VERBOSE) find $(uARF_ROOT) -name \*.bin -delete

.PHONY: kmods
kmods:
	@echo "Building kmods with kdir $(KDIR)"
	$(VERBOSE) $(MAKE) -C $(uARF_KMOD) KDIR=$(KDIR)

.PHONY: kmods_clean
kmods_clean:
	@echo "Clean KMOD"
	$(VERBOSE) $(MAKE) -C $(uARF_KMOD) KDIR=$(KDIR) clean

# Install library
.PHONY: install
install: $(LIBRARY) uninstall
	@echo "Install library"
	$(VERBOSE) mkdir -p $(LIBRARY_LIB_DIR) $(LIBRARY_INCLUDE_DIR)
	$(VERBOSE) cp $(LIBRARY) $(LIBRARY_LIB_DIR)/
	$(VERBOSE) cp -r include/* $(LIBRARY_INCLUDE_DIR)/

# Uninstall library
.PHONY: uninstall
uninstall:
	@echo "Uninstall library"
	$(VERBOSE) rm -f $(LIBRARY_LIB_DIR)/$(LIBRARY)
	$(VERBOSE) rm -rf $(LIBRARY_INCLUDE_DIR)
