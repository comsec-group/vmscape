CC := gcc
UARF_DIR := ../../uARF
UARF_SRC := $(UARF_DIR)/src
UARF_INCLUDE := $(UARF_DIR)/include
MARCH ?= MARCH_ZEN4
CFLAGS := -O3 -Wall -g -static -no-pie -I$(UARF_INCLUDE) -D$(MARCH)

attack: break_aslr.o $(UARF_SRC)/mem.o $(UARF_SRC)/log.o $(UARF_SRC)/jita.o $(UARF_SRC)/stub.o $(UARF_SRC)/vsnip.o

.PHONY: clean
clean:
	rm -f attack break_aslr.o