/****************************************************************************
 File        : main.c
 Description : Main source file for 'mphidflash, ' a simple command-line tool for
               communicating with Microchips USB HID-Bootloader and downloading new
               firmware.

 History     : 2009-02-19  Phillip Burgess
                 * Initial implementation
               2009-12-26  Thomas Fischl, Dominik Fisch (www.FundF.net)
                 * Renamed 'ubw32' to 'mphidflash'
               2010-12-28  Petr Olivka
                 * program and verify only data for defined memory areas
                 * send only even length of data to PIC
               2018-07-16  Daniel Santos
                 * Rewrite

 License     : Copyright (C) 2009 Phillip Burgess
               Copyright (C) 2009 Thomas Fischl, Dominik Fisch (www.FundF.net)
               Copyright (C) 2010 Petr Olivka
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

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include "mphidflash.h"
#include "config.h"

#define DEFAULT_VENDOR_ID   0x04d8
#define DEFAULT_PRODUCT_ID  0x003c

//VERSION

static struct options opts = {
    .file_name  = NULL,
    .idVendor   = DEFAULT_VENDOR_ID,
    .idProduct  = DEFAULT_PRODUCT_ID,
    .bus        = 0,
    .devnum     = 0,
    .actions    = 0,
    .opts       = 0
};

const struct options *get_opts(void)
{
    return &opts;
}

static void print_options(const char *argv0)
{
    fprintf(stderr,
"%s v" VERSION ": a Microchip PIC USB HID Bootloader utility\n"
"\n"
"USAGE\n"
"    %s <action> [options] [hex_file]\n"
"\n"
"action is one of\n"
"-w, --write     Write hex file to device (implies --erase --verify).\n"
"-c, --check\n"
"-e, --erase     Erase program memory.\n"
"-E, --no-erase  Do not erase (only meaningful with --write).\n"
"-s, --sign      Sign firmware image (recent PIC bootloaders).\n"
"-r, --reset     Reset device.\n"
"-v, --verify    Verify program memory.  When used without --write, will\n"
"                check if hex file has already been programmed.\n"
"-V, --no-verify Do not perform verfication (only meaningful with --write)\n"
"-u, --unlock    Unlock configuration memory before erase/write and allow\n"
"                hex file to overwrite configuration bytes\n"
"-v, --vid <hex> USB device vendor ID  (default %04x)\n"
"-p, --pid <hex> USB device product ID (default %04x)\n"
"-C, --no-color  No pretty colors.\n"
"-d, --debug [category[,category]]\n"
"                Enable debuging.  Optional (additional) catagories are:\n"
"                    general    \n"
"                    hex        display hex file as it is parsed\n"
"                    urbs       display all in and out URBs to the bootloader\n"
"-h, --help      Help\n", argv0, argv0, DEFAULT_VENDOR_ID, DEFAULT_PRODUCT_ID);
}


int main(int argc, char *argv[]) {
    int ret;
    struct hex_file *hex = NULL;
    struct usb_hid_bootloader *bl = NULL;

    /* To create a sensible sequence of operations, all command-line
       input is processed prior to taking any actions.  The sequence
       of actions performed may not always directly correspond to the
       order or quantity of input; commands follow precedence, not
       input order.  For example, the action corresponding to the "-u"
       (unlock) command must take place early on, before any erase or
       write operations, even if specified late on the command line;
       conversely, "-r" (reset) should always be performed last
       regardless of input order.  In the case of duplicitous
       commands (e.g. if multiple "-w" (write) commands are present),
       only the last one will take effect.

       The precedence of commands (first to last) is:

       -v and -p <hex>  USB vendor and/or product IDs
       -u               Unlock configuration memory
       -e               Erase program memory
       -n               No verify after write
       -w <file>        Write program memory
       -r               Reset */


    while (1) {
        int c;
        int option_index = 0;
        static struct option long_options[] = {
            {"check",       no_argument,        0, 'c'},
            {"unlock",      no_argument,        0, 'u'},
            {"erase",       no_argument,        0, 'e'},
            {"no-erase",    no_argument,        0, 'E'},
            {"write",       no_argument,        0, 'w'},
            {"verify",      no_argument,        0, 'v'},
            {"no-verify",   no_argument,        0, 'V'},
            {"sign",        no_argument,        0, 's'},
            {"reset",       no_argument,        0, 'r'},
            {"slot",        required_argument,  0, 's'},
            {"debug",       no_argument,        0, 'd'},
            {"help",        no_argument,        0, 'h'},
            {0,             0,                  0, 0}
        };
struct optiaons {
    const char *file_name;
    uint16_t vendorID;
    uint16_t productID;
    enum actions actions;
    union {
        int opts;
        struct {
            int validate:1;
            int write:1;
            int erase:1;
            int no_erase:1;
            int unlock:1;
            int no_unlock:1;
            int verify:1;
            int no_verify:1;
            int sign:1;
            int reset:1;
            int debug:1;
            int debug_hex:1;
            int debug_urbs:1;
        };
    };
};

        c = getopt_long(argc, argv, "w:esrvVuv:p:h?", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 0:
            fprintf(stderr, "option %s\n", long_options[option_index].name);
            printf("\n");
            break;

        case 'w':
            opts.write = true;
            opts.file_name = optarg;
            break;

        case 'e':
            opts.erase = true;
            //opts.flags |= ACTION_ERASE;
            break;

        case 's':
            opts.sign = true;
            //opts.flags |= ACTION_SIGN;
            break;

        case 'r':
            opts.reset = true;
            //actions |= ACTION_RESET;
            break;

        case 'n':
            opts.no_verify = true;
            //opts.flags &= ~ACTION_VERIFY;
            break;

        case 'u':
            opts.unlock = true;
            //opts.flags |= ACTION_UNLOCK;
            break;

        case 'v':
            if (sscanf(optarg, "%hx", &opts.idVendor) != 1)
                fail("Failed to parse -v");
            break;

        case 'p':
            if (sscanf(optarg, "%hx", &opts.idProduct) != 1)
                fail("Failed to parse -p");
            break;

        case 'h':
        case '?':
            print_options(argv[0]);
            return -1;
        }
    }

    if (opts.file_name && !(hex = hex_file_open(opts.file_name)))
        fail("Failed to open file %s\n", opts.file_name);

    /* After successful command-line parsage, find/open USB device. */

    if (IS_ERR(bl = bl_open())) {
        errno = -PTR_ERR(bl);
        perror("bl_open");
        return -1;
    }
    printf("USB HID device found...\n");

    /* And start doing stuff... */

    if ((ret = bl_query(bl)))
        fail("Device query failed.\n");

    if (bl->free_program_memory)
        printf("%d bytes free\n", bl->free_program_memory);

    putchar('\n');

    printf("Reading file '%s'...", hex->name);
    if (hex_file_validate(hex, bl))
        fail("\nHex file validation failed.\n");
    printf("done.\n");

    if (opts.actions & ACTION_UNLOCK) {
        puts("Unlocking configuration memory...");
        if (bl_unlock_config(bl))
            fail("Unlock command failed.\n");
    } else
        /* Otherwise make sure we don't try to modify it. */
        bl_protect_config(bl);

    if (opts.actions & ACTION_ERASE) {
        puts("Erasing...");
        if (bl_erase(bl))
            fail("Erase failed");
    }

    if (hex) {
        printf("Writing hex file '%s':", opts.file_name);
        if (hex_file_write(hex, bl))
            fail("\nFlashing failed.");
        putchar('\n');
    }

    if (hex && (opts.actions & ACTION_VERIFY)) {
        printf("Verifying...");
        if (hex_file_verify(hex, bl))
            fail("\nVeryfing failed.");
        putchar('\n');
    }

    if (opts.actions & ACTION_SIGN) {
        puts("Signing image...");
        if (bl_sign(bl))
            fail("Signing failed.");
    }

    if (opts.actions & ACTION_RESET) {
        puts("Resetting device...");
        if (bl_reset(bl))
            fail("Reset failed.\n");
    }

    bl_close(bl);
    free(bl);

    return 0;
}
