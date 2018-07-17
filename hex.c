/****************************************************************************
 File        : hex.c
 Description : Code for dealing with Intel hex files.

 History     : 2009-02-19  Phillip Burgess
                 * Initial implementation
               2009-12-26  Thomas Fischl, Dominik Fisch (www.FundF.net)
                 * Ported mmap functions to windows
               2018-07-16  Daniel Santos
                 * Rewrite

 License     : Copyright (C) 2009 Phillip Burgess
               Copyright (C) 2009 Thomas Fischl, Dominik Fisch (www.FundF.net)
               Copyright (C) 2018 Daniel Santos, Global Sattelite Engineering
                             (www.gsat.us)

               This file is part of 'mphidflash' program.

               'mphidflash' is free software: you can redistribute it and/or
               modify it under the terms of the GNU General Public License
               as published by the Free Software Foundation, either version
               3 of the License, or (at your option) any later version.

               'mphidflash' is distributed in the hope that it will be useful,
               but WITHOUT ANY WARRANTY; without even the implied warranty
               of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
               See the GNU General Public License for more details.

               You should have received a copy of the GNU General Public
               License along with 'mphidflash' source code.  If not,
               see <http://www.gnu.org/licenses/>.

 ****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#ifndef WIN
#include <sys/mman.h>
#else
#include <windows.h>
#endif

#include <sys/stat.h>
#include "mphidflash.h"

enum intel_hex_record_types {
    TYPE_DATA,
    TYPE_EOF,
    TYPE_SEG_ADDR_EXT,
    TYPE_SEG_ADDR_START,
    TYPE_LINEAR_ADDR_EXT,
    TYPE_LINEAR_ADDR_START
};

/**
 * Open and memory-map an Intel hex file.
 */
struct hex_file *hex_file_open(char *const name)
{
    struct hex_file *hex;
    int ret;
    size_t name_len = strlen(name);

    if (!(hex = malloc(sizeof(*hex) + name_len)))
        return ERR_PTR(-ENOMEM);

    memset(hex, 0, sizeof(*hex));
    strcpy((char*)hex->name, name);

    if ((hex->fd = open(name, O_RDONLY)) < 0) {
        ret = errno;
        perror("open");
        goto exit_free;
    }

    if (fstat(hex->fd, &hex->stat)) {
        ret = errno;
        perror("fstat");
        goto exit_close;
    }

#ifndef WIN
    hex->data = mmap(0, hex->stat.st_size, PROT_READ, MAP_FILE | MAP_SHARED,
                     hex->fd, 0);
    if(hex->data == MAP_FAILED) {
        ret = errno;
        perror("mmap");
        goto exit_close;
    }
#else
    {
        HANDLE handle;
        handle = CreateFileMapping((HANDLE)_get_osfhandle(hex->fd),
                                   NULL, PAGE_WRITECOPY, 0, 0, NULL);
        if (handle == NULL) {
            ret = errno;
            perror("CreateFileMapping");
            goto exit_close;
        }
        hex->data = MapViewOfFile(handle, FILE_MAP_COPY, 0, 0, hex->size);
        hex->data_plus_one = &hex->data[1];
        CloseHandle(handle);
        if (!hex->data) {
            ret = errno;
            perror("MapViewOfFile");
            goto exit_close;
        }
}
#endif

    return hex;

exit_close:
    close (hex->fd);

exit_free:
    free (hex);
    return ERR_PTR(-ret);
}

/**
 *
 * @param c a hex digit character
 * @return The result or a number > 16 if the input was invalid
 */
unsigned char parse_hex_digit(unsigned char c)
{
    if ((c -= '0') < 10)
        return c;
    c -= 'A' - '0';
    if (c > 5)
        c -= 'a' - 'A';
    return c > 5 ? 0xff : c + 10;
}

/**
 *
 * @param str pointer to string of two hex bytes
 * @param dest destination
 * @return zero upon success
 */
static int parse_hex_byte(const char *str, unsigned char *dest)
{
    unsigned char nibble[2];
    if ((nibble[0] = parse_hex_digit(str[0])) & 0xf0)
        return 1;
    if ((nibble[1] = parse_hex_digit(str[1])) & 0xf0)
        return 1;
    *dest = nibble[0] << 4 | nibble[1];
    return 0;
}

const char *const pass_names[PASS_COUNT]  = {
    "Validating", "Writing", "Verifying"
};

/* A really stupid diff function. */
static void show_diff(uint32_t addr, unsigned size, const uint8_t *a,
                      const uint8_t *b)
{
    unsigned i, j, col;
    unsigned cols = 8;
    const uint8_t *ab[2] = {a, b};

    for (i = 0; i < size; i += cols) {
        fprintf(stderr, "%04x:  ", addr + i);
        for (j = 0; j < 2; ++j) {
            for (col = 0; col < cols; ++col) {
                if (i + col < size)
                    fprintf(stderr, "%02x ", ab[j][i + col]);
                else
                    fputs("   ", stderr);
            }
            if (j == 0)
                fputs(" |  ", stderr);
        }
        fputs("\n", stderr);
    }
}

enum hex_record_sections {
    HEX_SECTION_START,
    HEX_SECTION_BYTE_COUNT,
    HEX_SECTION_ADDR,
    HEX_SECTION_REC_TYPE,
    HEX_SECTION_DATA,
    HEX_SECTION_CHECKSUM,

    HEX_SECTION_COUNT
};

/**
 * Some ANSI colors to make your day bright.
 */
const char *ansi_colors[HEX_SECTION_COUNT] = {
    "\x1b[48;2;255;255;204m",
    "\x1b[48;2;204;255;204m",
    "\x1b[48;2;204;204;255m",
    "\x1b[48;2;255;204;204m",
    "\x1b[48;2;204;255;255m",
    "\x1b[48;2;204;204;204m",
};
const char *ansi_forground_blk = "\x1b[38;2;0;0;0m";
const char *ansi_reset = "\x1b[0m";

static inline void hex_record_print(const char *line_end, const char *line_start)
{
    char data_fmt[8];
    unsigned data_len = line_end - line_start - 11;

    if (data_len > 255)
        data_len = 255;
    fprintf(stderr, "%s", ansi_forground_blk);
    fprintf(stderr,
            "%s%c%s%.2s%s%.4s%s%.2s%s",
            ansi_colors[HEX_SECTION_START],
            line_start[0],
            ansi_colors[HEX_SECTION_BYTE_COUNT],
            line_start + 1,
            ansi_colors[HEX_SECTION_ADDR],
            line_start + 3,
            ansi_colors[HEX_SECTION_REC_TYPE],
            line_start + 7,
            ansi_colors[HEX_SECTION_DATA]);

    snprintf(data_fmt, sizeof(data_fmt), "%%.%us", data_len);
    fprintf(stderr, data_fmt, line_start + 9);
    fprintf(stderr,
            "%s%.2s%s\n",
            ansi_colors[HEX_SECTION_CHECKSUM],
            line_end - 2,
            ansi_reset);
}

int hex_file_parse(struct hex_file *hex, struct usb_hid_bootloader *bl, enum hex_file_passes pass) {
    unsigned col = 0;
    struct hex_record r;
    unsigned size;
    unsigned checksum;
    unsigned i;
    int ret;
    struct parse_state state = {0, 0, 0, 0};
    const char *p = hex->data;
    const char *const end = hex->data + hex->stat.st_size;
    const char *line_start;
    const char *line_end;

    /* Each line in file */
    for (state.line = 0; p < end; ++state.line) {
        line_start = p;
        if (*(p++) != ':') {
            err("malformed start of line\n");
            goto bad_hex;
        }

        /* Parse hex pairs into record buffer */
        r.addr = 0;
        r.rec_size = 0;
        for (col = 0; col < 260 && p + 1 < end; ++col) {
            if (*p == '\n' || *p == '\r')
                break;
            if (parse_hex_byte(p, r.bytes + col)) {
                err("malformed\n");
                goto bad_hex;
            }
            p += 2;
        }
        r.addr = be16_to_cpu(r.addr_be16);
        r.rec_size = (line_end = p) - line_start - 1;

#ifdef DEBUG
        hex_record_print(line_start, line_end);
#endif

        if (col == 260) {
            err("malformed: record too long\n");
            goto bad_hex;
        }

        size = col;

        if (size < 5) {
            err("malformed: line not long enough\n");
            goto bad_hex;
        }

        if (r.size != size - 5) {
            err("malformed: byte count doesn't match record size.\n");
            goto bad_hex;
        }

        /* Checksum is twos compliment of the sum of all bytes, so just adding them
         * all together should give a zero in the least significant byte. */
        for (checksum = 0, i = 0; i < size; ++i)
            checksum += r.bytes[i];

        if (checksum & 0xff) {
            err("checksum mismatch\n");
            goto bad_hex;
        }

        switch (r.type) {
        case TYPE_DATA:
            if (pass != PASS_VERIFY) {
                if ((ret = bl_write_data(bl, &state, &r, pass == PASS_VALIDATE))) {
                    err("Failure at line %u of %s\n", state.line, hex->name);
                    return -1;
                }
            } else {
                const void *data;
                uint32_t addr = state.addr_hi + r.addr;
                if (IS_ERR(data = bl_get_data(bl, addr, r.size))) {
                    int err = -PTR_ERR(data);
                    if (err == EAGAIN) {
                        info("Skipping validation of configuration...\n");
                        break;
                    } else if (err == EPERM) {
                        err("Cannot change configuration without --unlock.\n");
                        return EPERM;
                    } else {
                        err("Failed to verify due to command failure.\n");
                        return err;
                    }
                }
                if (memcmp(r.data, data, r.size)) {
                    err("Verification failure for record at line %u, addr "
                        "0x%08x\n", state.line, addr);
                    show_diff(addr, r.size, r.data, data);
                    return -1;
                }
            }
            break;

        case TYPE_EOF:
            goto done;

        case TYPE_SEG_ADDR_EXT:
        case TYPE_SEG_ADDR_START:
            err("Segment Addresses in hex file are not supported by any PIC "
                "architecture.\n");
            goto bad_hex;

        case TYPE_LINEAR_ADDR_EXT:
            if (r.size != 2) {
                err("Extended Linear Address record has wrong size.\n");
                goto bad_hex;
            }

            state.addr_hi = be16_to_cpu(*(uint32_t*)(r.data)) << 16;
            state.addr = state.addr_hi;

            if (pass != PASS_VERIFY) {
                /* Assume this means a noncontiguous address jump; issue block
                 * and start anew.  The prior noncontiguous address code should
                 * already have this covered, but in the freak case of an
                 * extended address record with no subsequent data, make sure
                 * the last of the data is issued.  */
                if ((ret = bl_program_complete(bl, pass == PASS_VALIDATE)))
                    return ret;
            }
            break;

        case TYPE_LINEAR_ADDR_START:
            err("Start Linear Address not supported by PIC architecture.\n");
            goto bad_hex;
        }

        /* Advance to start of next line (skip CR/LF/etc.), unless EOF */
        for (; p < end && isspace(*p); ++p);

        if (p == end) {
            err("Unexpected end of file %s\n", hex->name);
            goto bad_hex;
        }
    }
done:

    /* Flush buffers and commit any final writes. */
    if (pass != PASS_VERIFY) {
        if ((ret = bl_program_complete(bl, pass == PASS_VALIDATE)))
            return ret;
    }
    return 0;

bad_hex:
    fail("bad format: line %u, col %u in file %s\n", state.line, col + 1,
         hex->name);
    return -1;
}

/****************************************************************************
 Function    : hexClose
 Description : Unmaps and closes previously-opened hex file.
 Parameters  : None
 Returns     : Nothing
 Notes       : File is assumed to have already been successfully opened
               by the time this function is called; no checks performed here.
 ****************************************************************************/
void hex_close(struct hex_file *hex) {
#ifndef WIN
    munmap((void*)hex->data, hex->stat.st_size);
#else
    UnmapViewOfFile(hex->data);
#endif
    hex->data = NULL;
    close(hex->fd);
    free(hex);
}

