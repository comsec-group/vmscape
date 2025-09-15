PWD = $(CURDIR)

ifeq ($(KDIR),)
$(error Do not run this makefile directly, but via its parent)
endif

SOURCES := $(shell find $(PWD) -name \*.c)
DIRS := $(sort $(dir $(SOURCES)))
OBJS := $(SOURCES:%.c=%.ko)

all: $(OBJS)

%.ko: %.c
	@echo "Building kernel module $@"
	@echo "With KDIR $(KDIR)"
	$(MAKE) -C $(KDIR) M=$(dir $@)


.PHONY: clean
clean:
	@for dir in $(DIRS); do \
		$(MAKE) -C $(KDIR) M=$$dir clean; \
	done
