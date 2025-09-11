#include <stdint.h>
#include <stdio.h>
#include <uarf/mem.h>

int main(int argc, char **argv) {
  if (argc != 3) {
    printf("Invalid arguments\n");
    return 1;
  }

  uint64_t va = strtoull(argv[1], NULL, 16);
  uint64_t pid = strtoull(argv[1], NULL, 16);

  uint64_t pa = uarf_va_to_pa(va, pid);
  printf("%lu\n", pa);
}
