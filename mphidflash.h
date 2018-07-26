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
               Copyright (C) 2018 Daniel Santos <daniel.santos@pobox.com>
                                  Global Sattelite Engineering (www.gsat.us)

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

#include "config.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(*arr))

/* A few helpful macros and inlines stolen from Linux. */
#ifdef __GNUC__
# define likely(x)    __builtin_expect(!!(x), 1)
# define unlikely(x)  __builtin_expect(!!(x), 0)
# define __must_check __attribute__((warn_unused_result))
# define __aligned(x) __attribute__((aligned(x)))
#else
# define likely(x)   (x)
# define unlikely(x) (x)
# define __must_check
# define __aligned(x)
#endif

#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void * __must_check ERR_PTR(long error)
{
    return (void *) error;
}

static inline long __must_check PTR_ERR(const void *ptr)
{
    return (long) ptr;
}

static inline bool __must_check IS_ERR(const void *ptr)
{
    return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool __must_check IS_ERR_OR_NULL(const void *ptr)
{
    return unlikely(!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

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

enum actions {
    ACTION_CHECK        = 1 << 0,
    ACTION_UNLOCK       = 1 << 1,
    ACTION_ERASE        = 1 << 2,
    ACTION_WRITE        = 1 << 3,
    ACTION_VERIFY       = 1 << 4,
    ACTION_SIGN         = 1 << 5,
    ACTION_RESET        = 1 << 6,
};

#define DEFAULT_VENDOR_ID   ((uint16_t)0x04d8)
#define DEFAULT_PRODUCT_ID  ((uint16_t)0x003c)


struct options {
    const char *file_name;
    uint16_t idVendor;
    uint16_t idProduct;
    uint32_t bus;
    uint8_t devnum;

    /** The actions that are to be performed. */
    enum actions actions;

    /**
     * Options that were explicitly selected at the command line or, after
     * command line parsing, were assigned as default values.
     */
    union {
        int flags;
        struct {
            /* Actions */
            int check:1;
            int unlock:1;
            int erase:1;
            int write:1;
            int verify:1;
            int sign:1;
            int reset:1;

            /* Anti-actions */
            int no_erase:1;
            int no_verify:1;

            /* Flags to indicate if a data item is populated. */
            int have_bus:1;
            int have_devnum:1;
            int have_vid:1;
            int have_pid:1;

            /* Debugging and output */
            int debug:1;
            int debug_hex:1;
            int debug_urbs:1;
            int no_color:1;
        };
    };
};

const struct options *get_opts(void);

static inline void debug0(const char *const fmt, ...)
{
    if (get_opts()->debug) {
        va_list argp;

        va_start(argp, fmt);
        vfprintf(stderr, fmt, argp);
        va_end(argp);
    }
}

#define debug(fmt, ...) debug0("debug: %s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define info(fmt, ...) fprintf(stderr, "info: %s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define warn(fmt, ...) fprintf(stderr, "warning: %s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define err(fmt, ...)  fprintf(stderr, "ERROR: %s: " fmt, __FUNCTION__, ##__VA_ARGS__)
#define sim(fmt, ...)  fprintf(stderr, "simulation: " fmt, ##__VA_ARGS__)
#define fail(fmt, ...) do {err(fmt, ##__VA_ARGS__); exit(-1);} while (0)

#define USB_PACKET_SIZE             0x40
#define MAX_REQUEST_DATA_BLOCK_SIZE 0x3a
#define PIC_ERASE_VALUE             0xff

#pragma pack(push)
#pragma pack(1)

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
 * from any other program that compiles with the Intel HEX standard and
 * conforms with the memory layout of the target.
 */
struct hex_record {
    /** The address in host cpu endianness */
    uint16_t addr;

    /** Size of the record. */
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

enum mem_region_type {
    MEM_REGION_PROGRAM_MEM   = 0x01,
    MEM_REGION_EEDATA        = 0x02,
    MEM_REGION_CONFIG        = 0x03,
    MEM_REGION_USERID        = 0x04,
    MEM_REGION_END           = 0xFF
};

/**
 * The USB HID Bootloader
 */
struct usb_hid_bootloader {
    usb_dev_handle *h;

    /**
     * True after successful query.
     */
    uint8_t have_info:1;

    /**
     * True if there is data waiting to be written in buf.  When true,
     * buf.data's Command, Address and Size will be valid.  CMD_PROGRAM_DEVICE
     * is the only command that might persist across API bl_* API calls.
     */
    uint8_t dirty:1;

    /**
     * True if we have begun writing program data and (eventually) need to send
     * CMD_PROGRAM_COMPLETE.  When true, next_addr will be valid.
     */
    uint8_t writing:1;

    /**
     * True when the dirty or writing flag are the result of a practice run.
     */
    uint8_t simulating:1;
    uint8_t protect_config:1;
    uint8_t stupid_byte_written:1;
    uint8_t ignore_config:1;

    struct pic_info info;
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
     * have to flush and issue a PROGRAM_COMPLETE first.
     */
    uint32_t next_addr;     /* FIXME: This should probably be in struct parse_state */
};

/* An Intel HEX file. */
struct hex_file {
    int fd;
    struct stat stat;
    const char *data;       /**< mmapped file contents. */
    size_t name_len;        /**< Size of name w/o null-terminator. Struct size
                             *   is sizeof(struct hex_file) + name_len.  */
    const char name[1];     /**< Name of hex file.  */
};

#define PARSE_INVALID_ADDRESS   ((uint32_t)(-1))
/**
 *
 */
struct parse_state {
    uint32_t addr;          /* FIXME: this field isn't being used, but should be. */
    uint32_t addr_hi;
    uint16_t addr_lo;
    uint32_t line;
    const char *line_start;
    const char *line_end;
};

enum hex_file_passes {
    PASS_VALIDATE,
    PASS_WRITE,
    PASS_VERIFY,

    PASS_COUNT
};

/* Functions defined in hex.c */
struct hex_file *hex_file_open(const char *const name);
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
struct usb_hid_bootloader *bl_open(void);
void bl_set_simulation_mode(struct usb_hid_bootloader *bl, bool enabled);
void bl_protect_config(struct usb_hid_bootloader *bl);
int bl_lock_unlock_config(struct usb_hid_bootloader *bl, bool locked);
int bl_erase(struct usb_hid_bootloader *bl);
int bl_write_data(struct usb_hid_bootloader *bl, struct parse_state *state,
                  const struct hex_record *r);
int bl_program_complete(struct usb_hid_bootloader *bl);
const void *bl_get_data(struct usb_hid_bootloader *bl, uint32_t addr,
                        uint8_t size);
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
