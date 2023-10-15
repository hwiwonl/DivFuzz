#ifndef FORKSERVER_H
#define FORKSERVER_H

#define FORKSRV_FD 200
#define CHILD_START 0x41414141
#define PARENT_ALIVE 0x42424242

#define FUZZ_ITERATION 10000

#include <unistd.h>

size_t read_all(int fd, void *s, size_t n) {
    unsigned char *ss = (unsigned char *)s;
    size_t read_bytes_total = 0;
    ssize_t read_bytes;
    do {
        read_bytes = read(fd, ss + read_bytes_total, n - read_bytes_total);
        if (read_bytes < 0)
            break;
        read_bytes_total += read_bytes;
    } while(read_bytes_total != n);
    return read_bytes_total;
}

#endif
