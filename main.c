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

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>

#include "mphidflash.h"

static struct options opts;

static void dump_opts(struct pbuf *dest, unsigned ind, const struct options *opts);
static void dump_pic_info(struct pbuf *dest, unsigned ind, const struct pic_info *o);
static void dump_info(struct pbuf *dest, unsigned ind, const struct usb_hid_bootloader *o);

const struct options *get_opts(void)
{
    return &opts;
}

const char *const help_str =
PACKAGE_TARNAME " v" VERSION ": a Microchip PIC USB HID Bootloader utility\n"
"\n"
"USAGE\n"
"    " PACKAGE_TARNAME " <action(s)> [options] [hex_file]\n"
"\n"
"Actions:\n"
"-w, --write     Write hex file to device (implies --check, --erase, --verify).\n"
"-c, --check-hex Only read the .hex file and validate it can be programmed to device.\n"
"-e, --erase     Erase program memory.\n"
"-E, --no-erase  Do not erase (only meaningful with --write).\n"
"-S, --sign      Sign firmware image (recent PIC bootloaders).\n"
"-r, --reset     Reset device.\n"
"-v, --verify    Verify program memory.  When used without --write, will\n"
"                check if hex file has already been programmed.\n"
"-V, --no-verify Do not perform verfication (only meaningful with --write)\n"
"-u, --unlock    Unlock configuration memory before erase/write and allow\n"
"                hex file to overwrite configuration bytes\n"
"-l, --lock      (Re)lock configuration memory after all other operations \n"
"                have been performed\n"
"-q, --query     Only query the device and exit\n"
"\n"
"Options:\n"
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
"-O, --debug-opts Dump options and exit.\n"
"-C, --no-color  No pretty colors.\n"
"-h, --help      Help\n";

static void print_options(const char *argv0)
{
    fprintf(stderr, help_str, DEFAULT_ID_VENDOR, DEFAULT_ID_PRODUCT);
    exit(-1);
}

char debug_buf[0x1000];
struct pbuf pbuf = PBUF_INIT(debug_buf);

int main(int argc, char *argv[]) {
    int ret = -1;
    struct hex_file *hex = NULL;
    struct usb_hid_bootloader *bl = NULL;
    bool need_file;
    bool need_dev;
    bool have_dev;

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
            {"check-hex",   no_argument,        0, 'c'},
            {"unlock",      no_argument,        0, 'u'},
            {"lock",        no_argument,        0, 'l'},
            {"erase",       no_argument,        0, 'e'},
            {"write",       no_argument,        0, 'w'},
            {"verify",      no_argument,        0, 'v'},
            {"sign",        no_argument,        0, 'S'},
            {"reset",       no_argument,        0, 'r'},
            {"query",       no_argument,        0, 'q'},
            {"no-erase",    no_argument,        0, 'E'},
            {"no-verify",   no_argument,        0, 'V'},
            {"slot",        required_argument,  0, 's'},
            {"bus",         required_argument,  0, 'b'},
            {"device",      required_argument,  0, 'D'},
            {"debug",       no_argument,        0, 'd'},
            {"debug-hex",   no_argument,        0, 'H'},
            {"debug-urbs",  no_argument,        0, 'U'},
            {"debug-opts",  no_argument,        0, 'O'},
            {"no-color",    no_argument,        0, 'C'},
            {"help",        no_argument,        0, 'h'},
            {0,             0,                  0, 0}
        };


        c = getopt_long(argc, argv, "cuewvSrqEVs:b:D:dHUOCh", long_options, &option_index);

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

        case 'l':
            opts.lock = true;
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

        case 'q':
            opts.query = true;
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

        case 'O':
            opts.debug_opts = true;
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

    opts.log_config.level		= LOG_DEBUG;
    opts.log_config.prog_name		= argv[0];
    opts.log_config.syslog		= false;
    opts.log_config.dbg_timestamps	= true;
    opts.log_config.dbg_src	 	= false;
    log_config = &opts.log_config;

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
                 | (opts.lock   ? ACTION_LOCK : 0)
                 | (opts.erase  ? ACTION_ERASE  : 0)
                 | (opts.write  ? ACTION_WRITE | ACTION_CHECK
                                  | (!opts.no_erase  ? ACTION_ERASE  : 0)
                                  | (!opts.no_verify ? ACTION_VERIFY : 0)
                                : 0)
                 | (opts.verify ? ACTION_VERIFY | ACTION_CHECK : 0)
                 | (opts.sign   ? ACTION_SIGN   : 0)
                 | (opts.reset  ? ACTION_RESET  : 0)
                 | (opts.query  ? ACTION_QUERY_ONLY  : 0);

    if (!opts.actions) {
        err("Nothing to do.\n");
        print_options(argv[0]);
    }

    need_file = !!(opts.actions & (ACTION_CHECK | ACTION_WRITE
				   | ACTION_VERIFY));
    need_dev = !!(opts.actions & (~ACTION_CHECK));

    if (!opts.file_name && need_file) {
        err("No input file specified.\n");
        print_options(argv[0]);
    }

    if (opts.debug_opts) {
	dump_opts(&pbuf, 0, &opts);
	trace(LOG_DEBUG, "%s", pbuf.buf);
	pbuf_reset(&pbuf);
	exit(0);
    }

    if (opts.file_name && !(hex = hex_file_open(opts.file_name)))
        fail("Failed to open file %s\n", opts.file_name);

    if (!IS_ERR(bl = bl_open())) {
	have_dev = true;
    } else {
	have_dev = false;
	errno = -PTR_ERR(bl);
	perror("bl_open");
	if (need_dev) {
	    goto close_hex;
	} else {
	    fprintf(stderr, "Proceeding without USB device...\n");
	    if (IS_ERR(bl = bl_open_sim())) {
		errno = -PTR_ERR(bl);
		perror("bl_open");
		goto close_hex;
	    }
	}
    }

    info("USB HID device found...\n");

    /* And start doing stuff... */

    if (have_dev && (ret = bl_query(bl)))
        fail("Device query failed.\n");

    if (opts.debug) {
	dump_info(&pbuf, 0, bl);
	trace(LOG_DEBUG, "%s", pbuf.buf);
	pbuf_reset(&pbuf);
    }

    if (bl->free_program_memory)
        info("%d bytes free\n", bl->free_program_memory);

    putchar('\n');

    if (opts.actions & ACTION_UNLOCK) {
        info("Unlocking configuration...");
        if (bl_unlock_config(bl))
            fail("Unlock command failed.\n");
        info("done\n");
    } else
        /* Otherwise make sure we don't try to modify it. */
        bl_protect_config(bl);

    if (opts.actions & ACTION_CHECK) {
        info("Reading file '%s'...", hex->name);
        bl_set_simulation_mode(bl, true);
        if (hex_file_validate(hex, bl))
            fail("\nFailed to parse file %s.\n",opts.file_name);
        bl_set_simulation_mode(bl, false);
        info("done\n");
    }

    if (opts.actions & ACTION_ERASE) {
        info("Erasing...");
        if (bl_erase(bl))
            fail("Erase failed");
        info("done\n");
    }

     if (opts.actions & ACTION_WRITE) {
        info("Writing hex file '%s':", opts.file_name);
        if (hex_file_write(hex, bl))
            fail("\nFlashing failed.");
        info("\n");
    }

    if (hex && (opts.actions & ACTION_VERIFY)) {
        info("Verifying...");
        if (hex_file_verify(hex, bl))
            fail("\nVeryfing failed.");
        info("done\n");
    }

    if (opts.actions & ACTION_SIGN) {
        info("Signing image...");
        if (bl_sign(bl))
            fail("Signing failed.");
        info("done\n");
    }

    if (opts.actions & ACTION_LOCK) {
        info("Locking configuration...");
        if (bl_lock_config(bl))
            fail("Lock command failed.\n");
        info("done\n");
    }

    if (opts.actions & ACTION_RESET) {
        info("Resetting device...");
        if (bl_reset(bl))
            fail("Reset failed.\n");
        info("done\n");
    }

    bl_close(bl);
    free(bl);

close_hex:
    if (hex)
        hex_close(hex);

    return 0;
}

const char *format_actions(enum actions actions) {
    static char buf[7 * 10] = { 0 };
    size_t pos = 0;
    int i;

    for (i = 0; i < 7; ++i) {
	if (actions & (1 << i)) {
	    const char *name = actions_str[i];

	    if (pos) {
		strncat(buf + pos, " | ", sizeof(buf) - pos);
		pos += 3;
	    }

	    strncat(buf + pos, name, sizeof(buf) - pos);
	    pos += strlen(name);
	}
    }
    buf[pos] = 0;
    return buf;
}

#define PBUF_INIT(buf_) {	\
    .buf	= buf_,		\
    .size	= sizeof(buf_),	\
    .pos	= buf_,		\
    .err	= 0		\
}

static void dump_opts(struct pbuf *dest, unsigned ind, const struct options *opts)
{
    pbuf_printf(dest,
	    "%sstruct options %p = {\n"
	    "%s  file_name	= %s\n"
	    "%s  idVendor	= 0x%04hx\n"
	    "%s  idProduct	= 0x%04hx\n"
	    "%s  bus\t	= %u\n"
	    "%s  devnum	= %hhu\n"
	    "%s  actions	= 0x%02x (%s)\n"
	    "%s  flags\t	= 0x%08x {\n"
	    "%s    /* Action flags */\n"
	    "%s    check	= %u\n"
	    "%s    unlock	= %u\n"
	    "%s    erase	= %u\n"
	    "%s    write	= %u\n"
	    "%s    verify	= %u\n"
	    "%s    sign	= %u\n"
	    "%s    reset	= %u\n"
	    "%s    /* Anti-action flags */\n"
	    "%s    no_erase	= %u\n"
	    "%s    no_verify	= %u\n"
	    "%s    /* Data populated flags */\n"
	    "%s    have_bus	= %u\n"
	    "%s    have_devnum	= %u\n"
	    "%s    have_vid	= %u\n"
	    "%s    have_pid	= %u\n"
	    "%s    /* Debug flags */\n"
	    "%s    debug	= %u\n"
	    "%s    debug_hex	= %u\n"
	    "%s    debug_urbs	= %u\n"
	    "%s    debug_opts	= %u\n"
	    "%s    no_color	= %u\n"
	    "%s  }\n",
	    indent(ind), opts,
	    indent(ind), opts->file_name,
	    indent(ind), opts->idVendor,
	    indent(ind), opts->idProduct,
	    indent(ind), opts->bus,
	    indent(ind), opts->devnum,

	    /** The actions that are to be performed. */
	    indent(ind), opts->actions, format_actions(opts->actions),

	    /**
	     * Options that were explicitly selected at the command line or, after
	     * command line parsing, were assigned as default values.
	     */

	    indent(ind), opts->flags,
	    indent(ind),

	    /* Actions */
	    indent(ind), !!opts->check,
	    indent(ind), !!opts->unlock,
	    indent(ind), !!opts->erase,
	    indent(ind), !!opts->write,
	    indent(ind), !!opts->verify,
	    indent(ind), !!opts->sign,
	    indent(ind), !!opts->reset,
	    indent(ind),

	    /* Anti-actions */
	    indent(ind), !!opts->no_erase,
	    indent(ind), !!opts->no_verify,
	    indent(ind),

	    /* Flags to indicate if a data item is populated. */
	    indent(ind), !!opts->have_bus,
	    indent(ind), !!opts->have_devnum,
	    indent(ind), !!opts->have_vid,
	    indent(ind), !!opts->have_pid,
	    indent(ind),

	    /* Debugging and output */
	    indent(ind), !!opts->debug,
	    indent(ind), !!opts->debug_hex,
	    indent(ind), !!opts->debug_urbs,
	    indent(ind), !!opts->debug_opts,
	    indent(ind), !!opts->no_color,
	    indent(ind)
    );
}

static void dump_pic_info(struct pbuf *dest, unsigned ind, const struct pic_info *o)
{
    unsigned i;
    pbuf_printf(dest,
	    "%sstruct options %p = {\n"
	    "%s  Command		= 0x%02hhx (%s)\n"
	    "%s  PacketDataFieldSize	= %hhu\n"
	    "%s  BytesPerAddress	= %uuh\n"
	    "%s  mem			= {\n",
	    indent(ind), o,
	    indent(ind), o->Command, cmd_name(o->Command),
	    indent(ind), o->PacketDataFieldSize,
	    indent(ind), o->BytesPerAddress,
	    indent(ind)
    );

    for (i = 0; i < sizeof(o->mem) / sizeof(o->mem[0]); ++i) {
	const struct pic_info_mem *m = o->mem + i;
	pbuf_printf(dest,
	    "%s    [%u] = {0x%02hhx, 0x%08x, 0x%08x}\n",
	     indent(ind), i, m->Type, m->Address, m->Length
	);
    }

    pbuf_printf(dest,
	    "%s  VersionFlag		= 0x%02hhx\n"
	    "%s}\n",
	    indent(ind), o->VersionFlag,
	    indent(ind)
    );
}

static void dump_info(struct pbuf *dest, unsigned ind, const struct usb_hid_bootloader *o)
{
    unsigned i, max;

    pbuf_printf(dest,
	    "%sstruct usb_hid_bootloader %p = {\n"
	    "%s  h			= %p\n"
	    "%s  have_info		= %u\n"
	    "%s  dirty			= %u\n"
	    "%s  writing		= %u\n"
	    "%s  simulating		= %u\n"
	    "%s  protect_config		= %u\n"
	    "%s  stupid_byte_written	= %u\n"
	    "%s  ignore_config		= %u\n"
	    "%s  info = {\n",
	    indent(ind), o,
	    indent(ind), o->h,
	    indent(ind), !!o->have_info,
	    indent(ind), !!o->dirty,
	    indent(ind), !!o->writing,
	    indent(ind), !!o->simulating,
	    indent(ind), !!o->protect_config,
	    indent(ind), !!o->stupid_byte_written,
	    indent(ind), !!o->ignore_config,
	    indent(ind)
    );

    dump_pic_info(dest, ind + 2, &o->info);

    pbuf_printf(dest,
	    "%s  free_program_memory	= 0x%08x (%u)\n"
	    "%s  mem_region_count	= %u\n"
	    "%s  mem			= {\n",
	    indent(ind), o->free_program_memory, o->free_program_memory,
	    indent(ind), o->mem_region_count,
	    indent(ind)
    );

    max = o->mem_region_count;
    if (max > sizeof(o->mem) / sizeof(o->mem[0]))
	max = sizeof(o->mem) / sizeof(o->mem[0]);

    for (i = 0; i < max; ++i) {
	const struct memory_region *m = o->mem + i;
	pbuf_printf(dest,
	    "%s    [%u] = {0x%08x, 0x%08x, %u}\n",
	     indent(ind), i, m->start, m->end, m->type
	);
    }
    pbuf_printf(dest,
		"%s}\n",
		indent(ind)
    );
}
