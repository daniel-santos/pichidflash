



#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <sys/stat.h>
#ifndef WIN
# include <sys/mman.h>
#else
# include <windows.h>
#endif

#include "mphidflash.h"

int open_stat_mmap_file(const char *const name, struct stat *stat,
                        const void **data)
{
    int ret;
    int fd;
    size_t name_len = strlen(name);

    assert(fd && stat && data);

    if ((fd = open(name, O_RDONLY)) < 0) {
        ret = errno;
        perror("open");
        return -ret;
    }

    if (fstat(fd, stat)) {
        ret = errno;
        perror("fstat");
        goto exit_close;
    }

#if defined(HAVE_MMAP) && defined(HAVE_MUNMAP)
    *data = mmap(0, stat->st_size, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
    if (*data == MAP_FAILED) {
        ret = errno;
        perror("mmap");
        goto exit_close;
    }
#elif defined(TARGET_WINDOWS)
    {
        HANDLE h = CreateFileMapping((HANDLE)_get_osfhandle(fd), NULL,
                                     PAGE_WRITECOPY, 0, 0, NULL);
        if (!h) {
            err("CreateFileMapping of file %s failed with %u\n", name,
                GetLastError());
            ret = 1;
            goto exit_close;
        }

        *data = MapViewOfFile(h, FILE_MAP_COPY, 0, 0, stat->st_size);
        ret = GetLastError();
        CloseHandle(h);
        if (!*data) {
            err("MapViewOfFile of file %s failed with %u\n", name, ret);
            ret = 1;
            goto exit_close;
        }
    }
#endif

    return fd;

exit_close:
    close (fd);
    return -ret;
}
