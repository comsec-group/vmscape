CC := gcc
UARF_DIR := ../../uARF
UARF_SRC := $(UARF_DIR)/src
UARF_INCLUDE := $(UARF_DIR)/include
CFLAGS := -O3 -Wall -g -static -no-pie -I$(UARF_INCLUDE)

measure_window: $(UARF_SRC)/mem.o $(UARF_SRC)/log.o $(UARF_SRC)/jita.o $(UARF_SRC)/stub.o $(UARF_SRC)/vsnip.o

.PHONY: clean
clean:
	rm -f measure_window
