/* i2crw BUS ADDR REG [COUNT]          read COUNT bytes from REG
 * i2crw BUS ADDR REG w B0 [B1 ...]    write bytes starting at REG */
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
int main(int c, char **v) {
    if (c < 4) { fprintf(stderr, "usage: %s BUS ADDR REG [COUNT | w B...]\n", v[0]); return 1; }
    char dev[32]; snprintf(dev, sizeof dev, "/dev/i2c-%s", v[1]);
    int fd = open(dev, O_RDWR); if (fd < 0) { perror(dev); return 1; }
    if (ioctl(fd, I2C_SLAVE_FORCE, strtol(v[2], 0, 0)) < 0) { perror("I2C_SLAVE_FORCE"); return 1; }
    unsigned char buf[256]; buf[0] = strtol(v[3], 0, 0);
    if (c > 4 && v[4][0] == 'w') {
        int n = 1; for (int i = 5; i < c && n < 256; i++) buf[n++] = strtol(v[i], 0, 0);
        if (write(fd, buf, n) != n) { perror("write"); return 1; }
        return 0;
    }
    int cnt = c > 4 ? atoi(v[4]) : 1; if (cnt > 255) cnt = 255;
    if (write(fd, buf, 1) != 1) { perror("write reg"); return 1; }
    if (read(fd, buf, cnt) != cnt) { perror("read"); return 1; }
    for (int i = 0; i < cnt; i++) printf("%02x%c", buf[i], (i % 16 == 15 || i == cnt - 1) ? '\n' : ' ');
    return 0;
}
