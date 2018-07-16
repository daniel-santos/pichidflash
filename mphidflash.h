/****************************************************************************
 File        : mphidflash.h
 Description : Common header file for all mphidflash sources.

 History     : 2009-02-19  Phillip Burgess
                 * Initial implementation
               2009-04-16  Phillip Burgess
                 * Bug fix for non-Intel and 64-bit platforms.
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

#ifndef _MPHIDFLASH_H_
#define _MPHIDFLASH_H_

#include <stdbool.h>
#include <usb.h>
#include <stdarg.h>
#include <byteswap.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*arr))

#ifdef __GNUC__
# define likely(x)    __builtin_expect(!!(x), 1)
# define unlikely(x)  __builtin_expect(!!(x), 0)
# define __must_check __attribute__((warn_unused_result))
//# define __force      __attribute__((force))
# define __aligned(x) __attribute__((aligned(x)))
#else
# define likely(x)   (x)
# define unlikely(x) (x)
# define __must_check
# define __aligned(x)
#endif
# define __force

#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void * __must_check ERR_PTR(long error)
{
	return (void *) error;
}

static inline long __must_check PTR_ERR(__force const void *ptr)
{
	return (long) ptr;
}

static inline bool __must_check IS_ERR(__force const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool __must_check IS_ERR_OR_NULL(__force const void *ptr)
{
	return unlikely(!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

/* FIXME: GCC extensions used here.  Use Wine-style macros?  */
#ifdef DEBUG
# define debug(fmt, ...) fprintf(stderr, "debug: %s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#else
# define debug(fmt, ...) do {} while (0)
#endif /* DEBUG */
#define info(fmt, ...) fprintf(stderr, "info: %s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define warn(fmt, ...) fprintf(stderr, "WARNING: %s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define err(fmt, ...) fprintf(stderr, "ERROR: %s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define fail(fmt, ...) do {err(fmt, ##__VA_ARGS__); exit(-1);} while (0)

#if 1
/* On Intel architectures, can make some crass endianism optimizations */

#if defined(i386) || defined(__x86_64__)
#define bufWrite32(dest, pos, val) *(unsigned int *)&dest[pos] = val
#define bufRead32(src, pos)          *(unsigned int *)&src[pos]
#else
#define bufWrite32(dest, pos, val) dest[pos    ] =  val        & 0xff; \
                                dest[pos + 1] = (val >>  8) & 0xff; \
                                dest[pos + 2] = (val >> 16) & 0xff; \
                                dest[pos + 3] = (val >> 24)
#define bufRead32(src, pos)         ( src[pos    ]        | \
                                (src[pos + 1] <<  8) | \
                                (src[pos + 2] << 16) | \
                                (src[pos + 3] << 24) )
#endif /* i386 || __x86_64__ */
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
# define cpu_to_le16 bswap_16
# define cpu_to_le32 bswap_32
# define le16_to_cpu bswap_16
# define le32_to_cpu bswap_32
# define cpu_to_be16
# define cpu_to_be32
# define cpu_to_be64
# define be16_to_cpu
# define be32_to_cpu
#else
# define cpu_to_le16
# define cpu_to_le32
# define le16_to_cpu
# define le32_to_cpu
# define cpu_to_be16 bswap_16
# define cpu_to_be32 bswap_32
# define be16_to_cpu bswap_16
# define be32_to_cpu bswap_32
#endif

#pragma pack(push)
#pragma pack(1)


#define USB_PACKET_SIZE             0x40
#define MAX_REQUEST_DATA_BLOCK_SIZE 0x3a
#define PIC_ERASE_VALUE				0xff

/** protocol struct copied from bootloader, reformatted and with fixed size types. */
struct pic_usb_hid_packet {
	union {
		uint8_t cmd;
		uint8_t Contents[USB_PACKET_SIZE];
		char char_arr[USB_PACKET_SIZE];

		/**
		 * General command (with data in it) packet structure used by
		 * PROGRAM_DEVICE and GET_DATA commands
		 */
		struct {
			uint8_t Command;
			uint32_t Address;
			uint8_t Size;
			uint8_t Data[MAX_REQUEST_DATA_BLOCK_SIZE];
		} data;

		/**
		 * This struct used for responding to QUERY_DEVICE command (on a device
		 * with four programmable sections)
		 */
		struct pic_info {
			uint8_t Command;
			uint8_t PacketDataFieldSize;

			/* FIXME: This field may have once been the product family, so we
			 * may need different behaviour for older versions of the
			 * bootloader code.
			 */
			uint8_t BytesPerAddress;
			struct pic_info_mem {
				uint8_t Type;
				uint32_t Address;
				uint32_t Length;
			} mem[6];

			/* Used by host software to identify if device is new enough to
			 * support QUERY_EXTENDED_INFO command */
			uint8_t VersionFlag;
			uint8_t pad[7];
		} info;

		/** For UNLOCK_CONFIG command */
		struct {
			uint8_t Command;
			uint8_t LockValue;
		} lock;

		/** Structure for the QUERY_EXTENDED_INFO command (and response) */
		struct pic_ext_info {
			uint8_t Command;
			uint16_t BootloaderVersion;
			uint16_t ApplicationVersion;
			uint32_t SignatureAddress;
			uint16_t SignatureValue;
			uint32_t ErasePageSize;
			struct {
				uint8_t low;
				uint8_t high;
			} config_mask[7];
		} ext_info;
	};

	/** True if endianness of packet is the host CPU, false if remote. */
	bool is_host_endianness;
};

/**
 * A binary representation of an Intel HEX record.  While the Microchip tools
 * only write records with up to 58 data bytes, the standard actually supports
 * up to 255, so this should (in theory) work with a .hex file generated
 * from any other program that compiles with the Intel HEX standard.
 */
struct hex_record {
	/** The address in host cpu endianness */
	uint16_t addr;
	uint16_t rec_size;
	union {
		uint8_t bytes[259];
		struct {
			uint8_t size;
			uint16_t addr_be16;
			uint8_t type;
			uint8_t data[255];
		};
	};
};

#pragma pack(pop)

enum memory_region_type {
	MEMORY_REGION_PROGRAM_MEM   = 0x01,
	MEMORY_REGION_EEDATA        = 0x02,
	MEMORY_REGION_CONFIG        = 0x03,
	MEMORY_REGION_USERID        = 0x04,
	MEMORY_REGION_END           = 0xFF
};

/**
 * The USB HID Bootloader
 */
struct usb_hid_bootloader {
	usb_dev_handle *h;
	uint8_t have_info:1;	/**< True after successful query. */

	/**
	 * True if there is data waiting to be written in buf.  When true,
	 * buf.data's Command, Address and Size will be valid.  CMD_PROGRAM_DEVICE
	 * is the only command that might persist across API bl_* API calls.
	 */
	uint8_t dirty:1;

	/**
	 * True if we have begun writing program data and (eventually) need to send
	 * CMD_PROGRAM_COMPLETE.  When true, next_addr will be valid. */
	uint8_t writing:1;
	uint8_t protect_config:1;
	uint8_t stupid_byte_written:1;
	uint8_t ignore_config:1;

	struct pic_info info;
	//uint8_t bytes_per_addr;
	uint32_t free_program_memory;
	unsigned mem_region_count;
	struct memory_region {
		uint32_t start;
		uint32_t end;
		uint8_t type;
	} mem[6];

	struct pic_usb_hid_packet buf;
	char data_buf[MAX_REQUEST_DATA_BLOCK_SIZE];

	/**
	 * Valid only when `writing' is set.  This is the next address to write to
	 * for a contiguous write.  If a write is made to any other address, we
	 * have to flush and issue a PROGRAM_COMPLETE first.  */
	uint32_t next_addr;
    //uint32_t addr_hi;
};

/* An Intel HEX file. */
struct hex_file {
	int fd;
	struct stat stat;
	const char *data;
	//unsigned char buf[58];
	size_t name_len;	/* size w/o null-terminator */
	const char name[1];
};

struct parse_state {
    uint32_t addr;
    uint32_t addr_hi;
    uint16_t addr_lo;
	uint32_t line;
};

enum hex_file_passes {
	PASS_VALIDATE,
	PASS_WRITE,
	PASS_VERIFY,

	PASS_COUNT
};

/* Functions defined in hex.c */
struct hex_file *hex_file_open(char *const name);
int hex_file_parse(struct hex_file *hex, struct usb_hid_bootloader *bl, enum hex_file_passes pass);
void hex_close(struct hex_file *hex);

static inline int hex_file_validate(struct hex_file *hex, struct usb_hid_bootloader *bl)
{
	return hex_file_parse(hex, bl, PASS_VALIDATE);
}

static inline int hex_file_write(struct hex_file *hex, struct usb_hid_bootloader *bl)
{
	return hex_file_parse(hex, bl, PASS_WRITE);
}

static inline int hex_file_verify(struct hex_file *hex, struct usb_hid_bootloader *bl)
{
	return hex_file_parse(hex, bl, PASS_VERIFY);
}

/* Functions defined in usb-hid-bootloader.c */
struct usb_hid_bootloader *bl_open(const unsigned short vendorID,
								   const unsigned short productID);
void bl_protect_config(struct usb_hid_bootloader *bl);
int bl_lock_unlock_config(struct usb_hid_bootloader *bl, bool locked);
int bl_erase(struct usb_hid_bootloader *bl);
int bl_write_data(struct usb_hid_bootloader *bl, struct parse_state *state,
				  const struct hex_record *r, bool simulate_only);
int bl_program_complete(struct usb_hid_bootloader *bl, bool simulate_only);
const void *bl_get_data(struct usb_hid_bootloader *bl, uint32_t addr, uint8_t size);
int bl_reset(struct usb_hid_bootloader *bl);
int bl_sign(struct usb_hid_bootloader *bl);
int bl_query(struct usb_hid_bootloader *bl);
void bl_close(struct usb_hid_bootloader *bl);

static inline int bl_lock_config(struct usb_hid_bootloader *bl) {
	return bl_lock_unlock_config(bl, true);
}

static inline int bl_unlock_config(struct usb_hid_bootloader *bl) {
	return bl_lock_unlock_config(bl, false);
}


#endif /* _MPHIDFLASH_H_ */
