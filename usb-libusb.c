/****************************************************************************
 File        : usb-libusb.c
 Description : Encapsulates all nonportable, libusb USB I/O code
               within the mphidflash program.

 History     : 2009-02-19  Phillip Burgess
                 * Initial implementation of usb-linux with libhid
               2009-12-28  Thomas Fischl, Dominik Fisch (www.FundF.net)
                 * Support for libusb without dependencies to libhid
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
#include <stdio.h>
#include <string.h>
#include <usb.h>
#include <errno.h>
#include <assert.h>
 #include <stddef.h>

#include "mphidflash.h"

/* Values derived from Microchip HID Bootloader source */

/* Bootloader commands */

enum bl_commands {
    /**
     * Query device information and store in struct pic_usb_hid_packet::info.
     */
    CMD_QUERY_DEVICE        = 0x02,
    /**
     * Lock or unlock configuration bits.
     */
    CMD_UNLOCK_CONFIG       = 0x03,
    /**
     * Start an erase operation.  The firmware controls which pages will be
     * erased.  This command takes a while to complete and the firmware will
     * not respond to other commands until it's finished (which is why we need
     * a larger than usual timeout value).
     */
    CMD_ERASE_DEVICE        = 0x04,
    /**
     * If host is going to send a full RequestDataBlockSize to be programmed,
     * it uses this command.
     */
    CMD_PROGRAM_DEVICE      = 0x05,
    /* If host send less than a RequestDataBlockSize to be programmed, or if
     * it wished to program whatever was left in the buffer, it uses this
     * command.
     */
    CMD_PROGRAM_COMPLETE    = 0x06,
    /**
     * The host sends this command in order to read out memory from the device.
     * Used during verify (and read/export hex operations)
     */
    CMD_GET_DATA            = 0x07,
    /**
     * Resets the microcontroller, so it can update the config bits (if they
     * were programmed, and so as to leave the bootloader (and potentially go
     * back into the main application)
     */
    CMD_RESET_DEVICE        = 0x08,
    /**The host PC application should send this command after the verify
     * operation has completed successfully.  If checksums are used instead of
     * a true verify (due to ALLOW_GET_DATA_COMMAND being commented), then the
     * host PC application should send SIGN_FLASH command after is has verified
     * the checksums are as exected. The firmware will then program the
     * SIGNATURE_WORD into flash at the SIGNATURE_ADDRESS.
     */
    CMD_SIGN_FLASH          = 0x09,
    /**
     * Used by host PC app to get additional info about the device, beyond the
     * basic NVM layout provided by the query device command
     */
    CMD_QUERY_EXTENDED_INFO = 0x0C
};

/* Sub-commands for the ERASE_DEVICE command */
#define UNLOCKCONFIG      0x00
#define LOCKCONFIG        0x01

/* Response types for QUERY_DEVICE command */
#define	TypeProgramMemory 0x01
#define TypeEEPROM        0x02
#define TypeConfigWords   0x03
#define	TypeEndOfTypeList 0xFF


static void packet_to_host_endianness(struct pic_usb_hid_packet *p) {
    if (p->is_host_endianness)
        return;

    switch (p->cmd) {
        unsigned i;
        struct pic_ext_info *ext;

    case CMD_GET_DATA:
        p->data.Address = le32_to_cpu(p->data.Address);
        break;

    case CMD_QUERY_DEVICE:
        for (i = 0; i < ARRAY_SIZE(p->info.mem); ++i) {
            struct pic_info_mem *mem = &p->info.mem[i];
            mem->Address = le32_to_cpu(mem->Address);
            mem->Length  = le32_to_cpu(mem->Length);
        }
        break;

    case CMD_QUERY_EXTENDED_INFO:
        ext = &p->ext_info;

        ext->BootloaderVersion  = le16_to_cpu(ext->BootloaderVersion);
        ext->ApplicationVersion = le16_to_cpu(ext->ApplicationVersion);
        ext->SignatureAddress   = le32_to_cpu(ext->SignatureAddress);
        ext->SignatureValue     = le16_to_cpu(ext->SignatureValue);
        ext->ErasePageSize      = le32_to_cpu(ext->ErasePageSize);
        break;

    default:
        break;
    }
    p->is_host_endianness = true;
}

static void packet_to_remote_endianness(struct pic_usb_hid_packet *p) {
    if (!p->is_host_endianness)
        return;

    switch (p->cmd) {
    case CMD_GET_DATA:
        p->data.Address = cpu_to_le32(p->data.Address);
        break;

    default:
        break;
    }
    p->is_host_endianness = false;
}

#if 0
    switch (p->cmd) {
    case CMD_QUERY_DEVICE:
    case CMD_UNLOCK_CONFIG:
    case CMD_ERASE_DEVICE:
    case CMD_PROGRAM_DEVICE:
    case CMD_PROGRAM_COMPLETE:
    case CMD_GET_DATA:
    case CMD_RESET_DEVICE:
    case CMD_SIGN_FLASH:
    case CMD_QUERY_EXTENDED_INFO:
    }
#endif

static inline void pic_usb_hid_packet_dump(const struct pic_usb_hid_packet *p, bool is_out) {
    unsigned i;
    switch (p->cmd) {
    case CMD_QUERY_DEVICE:
    case CMD_UNLOCK_CONFIG:
    case CMD_ERASE_DEVICE:
        break;

    case CMD_GET_DATA:
    case CMD_PROGRAM_DEVICE:
        fprintf(stderr, "======== URB %s ========\n", is_out ? "OUT" : "IN");
        fprintf(stderr, "p = {\n"
                "  Command %02x\n"
                "  Address %08x\n"
                "  Size    %02x\n"
                "  Data    = {\n"
                "    %04x:                    ",
                p->cmd,
                p->data.Address,
                p->data.Size,
                0);

        for (i = 0; i < sizeof(p->data.Data); ++i) {
            size_t off = i + offsetof(struct pic_usb_hid_packet, data.Data);
            if (!(off % 16))
                fprintf(stderr, "\n    %04zx:  ", off);
            fprintf(stderr, "%02x ", p->data.Data[i]);
        }
        fprintf(stderr, "\n  }\n}\n");
        break;

    case CMD_PROGRAM_COMPLETE:
    case CMD_RESET_DEVICE:
    case CMD_SIGN_FLASH:
    case CMD_QUERY_EXTENDED_INFO:
        break;
    }
}


/**
 *
 */
struct usb_hid_bootloader *bl_open(const unsigned short vendorID,
                                   const unsigned short productID) {
    struct usb_bus      *bus;
    struct usb_device   *dev;
    struct usb_hid_bootloader *bl;
    int ret = 0;

    bl = malloc(sizeof(*bl));
    if (!bl)
        return ERR_PTR(-ENOMEM);
    memset(bl, 0, sizeof(*bl));
    bl->ignore_config = true;

    usb_init();
    if ((ret = usb_find_busses()) < 0) {
        errno = -ret;
        perror("usb_find_busses");
        return ERR_PTR(ret);
    }
    if ((ret = usb_find_devices()) < 0) {
        errno = -ret;
        perror("usb_find_devices");
        return ERR_PTR(ret);
    }

    for (bus = usb_get_busses(); bus; bus = bus->next) {
        for (dev = bus->devices; dev; dev = dev->next) {
            if (dev->descriptor.idVendor == vendorID
                    && dev->descriptor.idProduct == productID) {

                if (!(bl->h = usb_open(dev))) {
                    ret = -errno;
                    perror("usb_open");
                    fprintf(stderr, "Warning: matching device found, but "
                            "cannot open usb device: %s\n", usb_strerror());
                    continue;
                }

                if (usb_claim_interface(bl->h, 0)) {
#ifdef LIBUSB_HAS_DETACH_KERNEL_DRIVER_NP
                    usb_detach_kernel_driver_np(bl->h, 0);
#endif
                    if ((ret = usb_claim_interface(bl->h, 0))) {
                        errno = -ret;
                        perror("usb_claim_interface");
                        usb_close(bl->h);
                        bl->h = NULL;
                        fprintf(stderr, "Warning: cannot claim interface: %s\n",
                                usb_strerror());
                        /* FIXME: UGLY AS SIN.  We should specify a device and
                         * either claim it or fail, not keep trying other devices. */
                        continue;
                    }
                }

                return bl;
            }
        }
    }

    err("USB HID Bootloader device with vid:pid %04hx:%04hx not found.\n",
        vendorID, productID);

    return ERR_PTR(-ENODEV);
}

static int bl_submit(struct usb_hid_bootloader *bl, const unsigned char len,
                     bool do_read)
{
    int ret;

#ifdef DEBUG
    if (0)
        pic_usb_hid_packet_dump(&bl->buf, true);
#endif
    packet_to_remote_endianness(&bl->buf);
    ret = usb_interrupt_write(bl->h, USB_ENDPOINT_OUT | 1, bl->buf.char_arr,
                              len, 5000);
    if (ret < 0) {
        errno = ret = -ret;
        perror("usb_interrupt_write");
        return ret;
    }

    if (do_read) {
        ret = usb_interrupt_read(bl->h, USB_ENDPOINT_IN | 1, bl->buf.char_arr,
                                 64, 5000);
        if (ret < 0) {
            errno = ret = -ret;
            perror("usb_interrupt_read");
            return ret;
        }
        packet_to_host_endianness(&bl->buf);
#ifdef DEBUG
        if (0)
            pic_usb_hid_packet_dump(&bl->buf, false);
#endif
    } else
        /* Else reset the flag for the next outgoing packet */
        bl->buf.is_host_endianness = true;

    return 0;
}

int bl_query(struct usb_hid_bootloader *bl) {
    unsigned i;
    int ret;

    bl->buf.cmd = CMD_QUERY_DEVICE;
    if ((ret = bl_submit(bl, 1, true)))
        return ret;

    /* Initialize the usb_hid_bootloader's copy of the query results. */
    memcpy(&bl->info, &bl->buf.info, sizeof(bl->info));

    /* Count memory regions and init mem map. */
    for (i = 0; bl->info.mem[i].Type != MEMORY_REGION_END; ++i) {
        struct memory_region *mem = bl->mem + i;

        if (bl->info.mem[i].Type == MEMORY_REGION_PROGRAM_MEM)
            bl->free_program_memory = bl->info.mem[i].Length;
        mem->type  = bl->info.mem[i].Type;
        mem->start = bl->info.mem[i].Address;
        mem->end   = bl->info.mem[i].Length + mem->start;
    }
    bl->mem_region_count = i;
    bl->have_info = true;
    return ret;
}

static int get_region_type(struct usb_hid_bootloader *bl, uint32_t addr,
                           uint32_t len) {
    struct memory_region *mem;
    uint32_t end = addr + len;		/* end is one byte beyond */

    /* The original code (by Phillip Burges, Thomas Fischl and Dominik Fisch)
     * allowed a match if the desired addr and len resided partially within
     * a valid region and then modified the addr or len to fit if part of the
     * requested rage resided outside of a valid region.  This seems extremely
     * suspect to me and I have written this function to reject any such
     * blocks. */
    for (mem = bl->mem; mem < &bl->mem[bl->mem_region_count]; ++mem) {
        if (addr < mem->start || end > mem->end)
            continue;
        return mem->type;
    }
    return 0;
}

int bl_lock_unlock_config(struct usb_hid_bootloader *bl, bool locked) {
    bl->buf.cmd = CMD_UNLOCK_CONFIG;
    bl->buf.lock.LockValue = locked ? LOCKCONFIG : UNLOCKCONFIG;
    return bl_submit(bl, 2, false);
}

int bl_erase(struct usb_hid_bootloader *bl) {
    int ret = 0;

    bl->buf.cmd = CMD_ERASE_DEVICE;
    if ((ret = bl_submit(bl, 1, false))) {
        err("Erase command failed\n");
        return ret;
    }

    /* The query here isn't needed for any technical reason, just makes the
     * presentation better. The ERASE_DEVICE command above returns immediately.
     * Thus, subsequent commands can be made but will pause until the erase
     * cycle completes.  So this query just keeps the "Writing" message or
     * others from being displayed prematurely.  */
    bl->buf.cmd = CMD_QUERY_DEVICE;
    if ((ret = bl_submit(bl, 1, true)))
        err("Query command failed\n");

    return ret;
}

static int bl_flush(struct usb_hid_bootloader *bl, bool simulate_only) {
    int ret;
    int offset = (int)bl->info.PacketDataFieldSize - (int)bl->buf.data.Size;
    //uint32_t addr_next;

    if (!bl->dirty)
        return 0;

    assert(offset >= 0);

    /* Regardless of actual byte count, data packet is always 64 bytes.
     * Following the header, the bootloader wants the data portion 'right
     * justified' within packet.  Odd.
     *
     * It's simpler to do it here than while accumulating data.  */
    if (offset) {
        unsigned i;
        for (i = bl->buf.data.Size; i;) {
            --i;
            bl->buf.data.Data[i + offset] = bl->buf.data.Data[i];
        }
        /* or...
        memmove(bl->buf.data.Data + offset, bl->buf.data.Data,
        		bl->buf.data.Size);
        */
    }

    /* Stupid crap:
     *
     * For some dumb reason they want even numbers of bytes only.  This will
     * force us to write a Stupid Byte(TM)(patent pending), which will force
     * a PROGRAM_COMPLETE command prior to any other writes.
     */
    if (bl->buf.data.Size & 1) {
        warn("Writing Stupid Byte(TM) at address 0x%08x because record "
             "contained uneven number\nof bytes (%u), of which the PIC USB HID "
             "is not fond.\n", bl->buf.data.Address, bl->buf.data.Size);
        bl->buf.data.Data[bl->buf.data.Size++] = PIC_ERASE_VALUE;
        bl->stupid_byte_written = true;
        bl->next_addr = (uint32_t) - 1;
    } else
        bl->next_addr = bl->buf.data.Address + bl->buf.data.Size;

    if (bl->info.BytesPerAddress > 1)
        bl->buf.data.Address /= bl->info.BytesPerAddress;

    //if (!simulate_only)
    debug("addr=0x%08x, size=%u\n", bl->buf.data.Address, bl->buf.data.Size);
    if (!simulate_only && (ret = bl_submit(bl, 64, false))) {
        err("PROGRAM_DEVICE command failed and it's probably your fault.  "
            "What did you do!?\n");
        /* OK, not really, but there should be more than enough blame to
        * spread around.  */
        return ret;
    }

    bl->dirty = false;
    bl->writing = true;

    return 0;
}

/** Flush write buffer and submit CMD_PROGRAM_COMPLETE if neccesary.  */
int bl_program_complete(struct usb_hid_bootloader *bl, bool simulate_only) {
    int ret;
    if (bl->dirty && (ret = bl_flush(bl, simulate_only))) {
        err("Flushing write buffer failed.\n");
        return ret;
    }

    if (bl->writing) {
        bl->buf.cmd = CMD_PROGRAM_COMPLETE;
        //if (!simulate_only)
        debug("\n");
        if (!simulate_only && (ret = bl_submit(bl, 1, false))) {
            err("PROGRAM_COMPLETE command failed.\n");
            return ret;
        }
        bl->writing = false;
        bl->next_addr = (uint32_t) - 1;
        /* Stupid Byte situation is resolved once we have performed a
         * program complete */
        bl->stupid_byte_written = false;
    }

    return 0;
}

/* Write program data to our output buffer until full or we need to flush to
 * the device. */
int bl_write_data(struct usb_hid_bootloader *bl, struct parse_state *state,
                  const struct hex_record *r, bool simulate_only) {
    int ret, type;
    uint32_t room;
    uint32_t in_offset;
    uint32_t addr = state->addr_hi + r->addr;

    struct pic_usb_hid_packet *buf = &bl->buf;

    if (!(type = get_region_type(bl, addr, r->size))) {
        err("Data record attempts to program invalid memory region at address "
            "0x%08x, length = %u\n", addr, r->size);
        return EINVAL;
    }
    if (type == MEMORY_REGION_CONFIG) {
        if (bl->ignore_config) {
            warn("skipping config...\n");
            return 0;
        }

        if (bl->protect_config) {
            err("Cannot write to config region without --unlock\n");
            return EPERM;
        }
    }

    /* If a write is in progress and the data record does not start at the next
     * address then we must flush and issue a completion.  The same is true if
     * we've had to write a Stupid Byte.  */
    if (((bl->writing || bl->dirty) && bl->next_addr != addr) || bl->stupid_byte_written)
        bl_program_complete(bl, simulate_only);

    for (in_offset = 0; in_offset < r->size;) {
        uint32_t bytes_this_write = r->size - in_offset;

        if (!bl->dirty) {
#ifdef DEBUG
            memset(&buf->data, 0, sizeof(buf->data));
#endif
            buf->data.Command = CMD_PROGRAM_DEVICE;
            buf->data.Address = addr;
            buf->data.Size = 0;
        }

        /* Detect address wrap */
        if (addr + bytes_this_write < addr)
            bytes_this_write = (uint32_t)0 - addr;

        room = bl->info.PacketDataFieldSize - buf->data.Size;
        if (bytes_this_write > room)
            bytes_this_write = room;

        memcpy(buf->data.Data + buf->data.Size, r->data + in_offset,
               bytes_this_write);
        buf->data.Size += bytes_this_write;
        bl->dirty = true;

        assert(buf->data.Size <= bl->info.PacketDataFieldSize);
        if (buf->data.Size == bl->info.PacketDataFieldSize)
            if ((ret = bl_flush(bl, simulate_only)))
                return ret;

        in_offset += bytes_this_write;
        bl->next_addr = (addr += bytes_this_write);
    }
    assert(in_offset == r->size);

    return 0;
}

/**
 * Execute a GET_DATA command.
 *
 * @return A pointer to the actual data (not right-justified) or a negative
 *         error code.
 */
const void *bl_get_data(struct usb_hid_bootloader *bl, uint32_t addr,
                        uint8_t size) {
    int ret = 0, type;

    bl->buf.cmd = CMD_GET_DATA;
    bl->buf.data.Address = addr;
    bl->buf.data.Size = size;
    bl->buf.is_host_endianness = true;

    /* FIXME: cleanup */
    if (!(type = get_region_type(bl, addr, size))) {
        err("Memory region invalid. addr = 0x%08x, size = %u\n", addr, size);
        return ERR_PTR(-EINVAL);
    }
    if (type == MEMORY_REGION_CONFIG) {
        if (bl->ignore_config) {
            return ERR_PTR(-EAGAIN);
        }

        if (bl->protect_config) {
            err("Config data protected\n");
            return ERR_PTR(-EAGAIN);
        }
    }

    if (bl->info.BytesPerAddress > 1)
        bl->buf.data.Address /= bl->info.BytesPerAddress;

    if ((ret = bl_submit(bl, 6, true))) {
        err("GET_DATA command failed for addr = 0x%08x, size = %hhu\n",
            addr, size);
        return ERR_PTR(-ret);
    }

    return bl->buf.data.Data + (bl->info.PacketDataFieldSize - size);
}

int bl_reset(struct usb_hid_bootloader *bl) {
    bl->buf.cmd = CMD_RESET_DEVICE;
    return bl_submit(bl, 1, false);
}

int bl_sign(struct usb_hid_bootloader *bl) {
    bl->buf.cmd = CMD_SIGN_FLASH;
    return bl_submit(bl, 1, false);
}

void bl_protect_config(struct usb_hid_bootloader *bl) {
    bl->protect_config = true;
}

void bl_close(struct usb_hid_bootloader *bl) {
    if (bl->h) {
        usb_release_interface(bl->h, 0);
        usb_close(bl->h);
    }
}
