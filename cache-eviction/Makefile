CC := gcc
UARF_DIR := ../uARF
UARF_SRC := $(UARF_DIR)/src
UARF_INCLUDE := $(UARF_DIR)/include
MARCH ?= MARCH_ZEN4
CUSTOM_DEFS ?=
CFLAGS := -O3 -Wall -g -static -no-pie -I$(UARF_INCLUDE) $(CUSTOM_DEFS) -D$(MARCH)

all: measure_window evict_eval

measure_window: $(UARF_SRC)/mem.o $(UARF_SRC)/log.o $(UARF_SRC)/jita.o $(UARF_SRC)/stub.o $(UARF_SRC)/vsnip.o
evict_eval: $(UARF_SRC)/mem.o $(UARF_SRC)/log.o

.PHONY: clean
clean:
	rm -f measure_window evict_eval
