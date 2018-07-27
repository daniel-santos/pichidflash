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

static struct options opts;

const struct options *get_opts(void)
{
    return &opts;
}

const char *const help_str =
PACKAGE_TARNAME " v" VERSION ": a Microchip PIC USB HID Bootloader utility\n"
"\n"
"USAGE\n"
"    " PACKAGE_TARNAME " <action> [options] [hex_file]\n"
"\n"
"action is one of\n"
"-w, --write     Write hex file to device (implies --check, --erase, --verify).\n"
"-c, --check     Only read the .hex file and validate it can be programmed to device.\n"
"-e, --erase     Erase program memory.\n"
"-E, --no-erase  Do not erase (only meaningful with --write).\n"
"-S, --sign      Sign firmware image (recent PIC bootloaders).\n"
"-r, --reset     Reset device.\n"
"-v, --verify    Verify program memory.  When used without --write, will\n"
"                check if hex file has already been programmed.\n"
"-V, --no-verify Do not perform verfication (only meaningful with --write)\n"
"-u, --unlock    Unlock configuration memory before erase/write and allow\n"
"                hex file to overwrite configuration bytes\n"
"-D, --device vid:pid\n"
"                Specify 4 digit hexidecimal Vendor ID and Product ID.\n"
"                Defaults to %04hx:%04hx if --slot is unspecified, unset\n"
"                otherwise.\n"
"-b, --bus n     Look only search the specified USB bus\n"
"-s, --slot n:n  Specify the exact USB bus and device number, ignoring the\n"
"                default vid:pid filter.  To restrict vid:pid when using,\n"
"                --slot, you must supply an explicit --device specification.\n"
"-d, --debug     Enable debug messages\n"
"-H, --debug-hex Prints each HEX record as they are processed.  Unless\n"
"               --no-color, the records are printed with ANSI coloriziation\n"
"                to demarcate fields.\n"
"-U, --debug-urbs Dumps each in and out URB.  This is helpful when trying to\n"
"                troubleshoot communications problems or debug the\n"
"                bootloader.\n"
"-C, --no-color  No pretty colors.\n"
"-h, --help      Help\n";

static void print_options(const char *argv0)
{
    fprintf(stderr, help_str, DEFAULT_ID_VENDOR, DEFAULT_ID_PRODUCT);
    exit(-1);
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
            {"write",       no_argument,        0, 'w'},
            {"verify",      no_argument,        0, 'v'},
            {"sign",        no_argument,        0, 'S'},
            {"reset",       no_argument,        0, 'r'},
            {"no-erase",    no_argument,        0, 'E'},
            {"no-verify",   no_argument,        0, 'V'},
            {"slot",        required_argument,  0, 's'},
            {"bus",         required_argument,  0, 'b'},
            {"device",      required_argument,  0, 'D'},
            {"debug",       no_argument,        0, 'd'},
            {"debug-hex",   no_argument,        0, 'H'},
            {"debug-urbs",  no_argument,        0, 'U'},
            {"no-color",    no_argument,        0, 'C'},
            {"help",        no_argument,        0, 'h'},
            {0,             0,                  0, 0}
        };


        c = getopt_long(argc, argv, "cuewvSrEVs:b:D:d:Ch", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
#if 0
        case 0:
            fprintf(stderr, "option %s\n", long_options[option_index].name);
            printf("\n");
            break;
#endif
        case 'c':
            opts.check = true;
            break;

        case 'u':
            opts.unlock = true;
            break;

        case 'e':
            opts.erase = true;
            break;

        case 'w':
            opts.write = true;
            break;

        case 'v':
            opts.verify = true;
            break;

        case 'S':
            opts.sign = true;
            break;

        case 'r':
            opts.reset = true;
            break;

        case 'E':
            opts.no_erase = true;
            break;

        case 'V':
            opts.no_verify = true;
            break;

        case 's':
            if (sscanf(optarg, "%u:%hhu", &opts.bus, &opts.devnum) != 2)
                fail("Failed to parse --slot");
            opts.have_bus = true;
            opts.have_devnum = true;
            break;

        case 'b':
            if (sscanf(optarg, "%u", &opts.bus) != 1)
                fail("Failed to parse --bus");
            opts.have_bus = true;
            break;

        case 'D':
            if (sscanf(optarg, "%hx:%hx", &opts.idVendor, &opts.idProduct) != 2)
                fail("Failed to parse --device");
            opts.have_vid = true;
            opts.have_pid = true;
            break;

        case 'd':
            opts.debug = true;
            break;

        case 'H':
            opts.debug_hex = true;
            break;

        case 'U':
            opts.debug_urbs = true;
            break;

        case 'C':
            opts.no_color = true;
            break;

        case 'h':
        case '?':
            print_options(argv[0]);
            return -1;
        }
    }

    if (optind < argc)
        opts.file_name = argv[optind++];

    if (optind < argc) {
        err("Too many arguments");
        print_options(argv[0]);
    }

    if (opts.erase && opts.no_erase) {
        err("Cannot specify --erase and --no-erase.\n");
        print_options(argv[0]);
    }

    if (opts.verify && opts.no_verify) {
        err("Cannot specify --verify and --no-verify.\n");
        print_options(argv[0]);
    }

    /* Supply default vid:pid unless --slot was used. */
    if (!(opts.have_bus && opts.have_devnum)) {
        opts.idVendor  = DEFAULT_ID_VENDOR;
        opts.idProduct = DEFAULT_ID_PRODUCT;
        opts.have_vid  = true;
        opts.have_pid  = true;
    }

    opts.actions = (opts.check  ? ACTION_CHECK  : 0)
                 | (opts.unlock ? ACTION_UNLOCK : 0)
                 | (opts.erase  ? ACTION_ERASE  : 0)
                 | (opts.write  ? ACTION_WRITE | ACTION_CHECK
                                  | (!opts.no_erase  ? ACTION_ERASE  : 0)
                                  | (!opts.no_verify ? ACTION_VERIFY : 0)
                                : 0)
                 | (opts.verify ? ACTION_VERIFY | ACTION_CHECK : 0)
                 | (opts.sign   ? ACTION_SIGN   : 0)
                 | (opts.reset  ? ACTION_RESET  : 0);

    if (!opts.actions) {
        err("Nothing to do.\n");
        print_options(argv[0]);
    }

    if (!opts.file_name && (opts.actions & (ACTION_CHECK | ACTION_WRITE
                                                        | ACTION_VERIFY))) {
        err("No input file specified.\n");
        print_options(argv[0]);
    }

    if (opts.file_name && !(hex = hex_file_open(opts.file_name)))
        fail("Failed to open file %s\n", opts.file_name);

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

    if (opts.actions & ACTION_CHECK) {
        printf("Reading file '%s'...", hex->name);
        if (hex_file_validate(hex, bl))
            fail("\nFailed to parse file %s.\n",opts.file_name);
        puts("done\n");
    }

    if (opts.actions & ACTION_UNLOCK) {
        puts("Unlocking configuration...");
        if (bl_unlock_config(bl))
            fail("Unlock command failed.\n");
        puts("done\n");
    } else
        /* Otherwise make sure we don't try to modify it. */
        bl_protect_config(bl);

    if (opts.actions & ACTION_ERASE) {
        puts("Erasing...");
        if (bl_erase(bl))
            fail("Erase failed");
        puts("done\n");
    }

     if (opts.actions & ACTION_WRITE) {
        printf("Writing hex file '%s':", opts.file_name);
        if (hex_file_write(hex, bl))
            fail("\nFlashing failed.");
        putchar('\n');
    }

    if (hex && (opts.actions & ACTION_VERIFY)) {
        printf("Verifying...");
        if (hex_file_verify(hex, bl))
            fail("\nVeryfing failed.");
        puts("done\n");
    }

    if (opts.actions & ACTION_SIGN) {
        puts("Signing image...");
        if (bl_sign(bl))
            fail("Signing failed.");
        puts("done\n");
    }

    if (opts.actions & ACTION_RESET) {
        puts("Resetting device...");
        if (bl_reset(bl))
            fail("Reset failed.\n");
        puts("done\n");
    }

    bl_close(bl);
    free(bl);
    if (hex)
        hex_close(hex);

    return 0;
}
