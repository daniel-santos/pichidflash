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

 License     : Copyright (C) 2009 Phillip Burgess
               Copyright (C) 2009 Thomas Fischl, Dominik Fisch (www.FundF.net)
               Copyright (C) 2010 Petr Olivka

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

unsigned short vendorID  = 0x04d8;
unsigned short productID = 0x003c;

/* Program's actions aren't necessarily performed in command-line order.
 * Bit flags keep track of options set or cleared during input parsing,
 * then are singularly checked as actions are performed.  Some actions
 * (such as writing) don't have corresponding bits here; certain non-NULL
 * string values indicate such actions should occur. */
enum actions {
	ACTION_UNLOCK = 1 << 0,
	ACTION_ERASE  = 1 << 1,
	ACTION_VERIFY = 1 << 2,
	ACTION_SIGN   = 1 << 3,
	ACTION_RESET  = 1 << 4,
	ACTION_WRITE_CONFIG = 1 << 5,
};

static void print_options(const char *argv0)
{
fprintf(stderr,
"%s v%s: a Microchip HID Bootloader utility\n"
"Option     Description                                      Default\n"
"-------------------------------------------------------------------------\n"
"-w <file>  Write hex file to device (will erase first)      None\n"
"-e         Erase device code space (implicit if -w)         No erase\n"
"-s         Sign firmware image (recent PIC bootloaders)     No\n"
"-r         Reset device on program exit                     No reset\n"
"-n         No verify after write                            Verify on\n"
"-u         Unlock configuration memory before erase/write   Config locked\n"
"-v <hex>   USB device vendor ID                             %04hx\n"
"-p <hex>   USB device product ID                            %04hx\n"
"-h or -?   Help\n", argv0, VERSION, vendorID, productID);

}

/****************************************************************************
 Function    : main
 Description : mphidflash program startup; parse command-line input and issue
               commands as needed; return program status.
 Returns     : int  0 on success, else various numeric error codes.
 ****************************************************************************/
int main(int argc, char *argv[])
{
	int ret;
	char        *hexFile   = NULL,
	             actions   = ACTION_VERIFY;
	struct hex_file *hex = NULL;
	struct usb_hid_bootloader *bl = NULL;
	//struct pic_info *info;
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
			{"write",	required_argument,	0, 'w'},
			{"erase",	no_argument,		0, 'e'},
			{"sign",	no_argument,		0, 's'},
			{"reset",	no_argument,		0, 'r'},
			{"no-verify", no_argument,		0, 'n'},
			{"unlock",	no_argument,		0, 'u'},
			{"vid",		required_argument,	0, 'v'},
			{"pid",		required_argument,	0, 'p'},
			{"help",	no_argument,		0, 'h'},
			{0,			0,					0, 0}
		};

		c = getopt_long(argc, argv, "w:esrnuv:p:h?", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			fprintf(stderr, "option %s\n", long_options[option_index].name);
			printf("\n");
			break;

		case 'w':
			hexFile = optarg;
			/* Intentional fall-through */
break;
		case 'e':
			actions |= ACTION_ERASE;
			break;

		case 's':
			actions |= ACTION_SIGN;
			break;

		case 'r':
			actions |= ACTION_RESET;
			break;

		case 'n':
			actions &= ~ACTION_VERIFY;
			break;

		case 'u':
			actions |= ACTION_UNLOCK;
			break;

		case 'v':
			if (sscanf(optarg, "%hx", &vendorID) != 1)
				fail("Failed to parse -v");
			break;

		case 'p':
			if (sscanf(optarg, "%hx", &productID) != 1)
				fail("Failed to parse -p");
			break;

		case 'h':
		case '?':
			print_options(argv[0]);
			return -1;
		}
	}

	if (hexFile && !(hex = hex_file_open(hexFile)))
		fail("Failed to open file %s\n", hexFile);

	/* After successful command-line parsage, find/open USB device. */

	if (IS_ERR(bl = bl_open(vendorID, productID))) {
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

	if (actions & ACTION_UNLOCK) {
		puts("Unlocking configuration memory...");
		if (bl_unlock_config(bl))
			fail("Unlock command failed.\n");
	} else
		/* Otherwise make sure we don't try to modify it. */
		bl_protect_config(bl);

	if (actions & ACTION_ERASE) {
		puts("Erasing...");
		if (bl_erase(bl))
			fail("Erase failed");
	}

	if (hex) {
		printf("Writing hex file '%s':", hexFile);
		if (hex_file_write(hex, bl))
			fail("\nFlashing failed.");
		putchar('\n');
	}

	if (hex && (actions & ACTION_VERIFY)) {
		printf("Verifying...");
		if (hex_file_verify(hex, bl))
			fail("\nVeryfing failed.");
		putchar('\n');
	}

	if (actions & ACTION_SIGN) {
		puts("Signing image...");
		if (bl_sign(bl))
			fail("Signing failed.");
	}

	if (actions & ACTION_RESET) {
		puts("Resetting device...");
		if (bl_reset(bl))
			fail("Reset failed.\n");
	}

	bl_close(bl);

	return 0;
}
