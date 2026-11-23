/* minimal devmem: devmem ADDR [w VALUE]  (32-bit) */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
int main(int c, char **v) {
    if (c < 2) { fprintf(stderr, "usage: %s ADDR [w VAL]\n", v[0]); return 1; }
    uint64_t a = strtoull(v[1], 0, 0), pg = a & ~0xfffULL;
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) { perror("/dev/mem"); return 1; }
    volatile uint8_t *m = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, pg);
    if (m == MAP_FAILED) { perror("mmap"); return 1; }
    volatile uint32_t *r = (volatile uint32_t *)(m + (a - pg));
    if (c >= 4 && v[2][0] == 'w') *r = (uint32_t)strtoul(v[3], 0, 0);
    printf("0x%08x\n", *r);
    return 0;
}
