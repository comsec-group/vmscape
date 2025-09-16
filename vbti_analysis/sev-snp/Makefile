CC := gcc
CFLAGS := -O3 -Wall -g -static -no-pie -I ../../uARF/include

amd_sev_snp: amd_sev_snp.c ../uARF/src/mem.o ../uARF/src/log.o ../uARF/src/jita.o ../uARF/src/stub.o ../uARF/src/vsnip.o

.PHONY: clean
clean:
	rm -f amd_sev_snp