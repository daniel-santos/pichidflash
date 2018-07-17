AUTOMAKE_OPTIONS = foreign

CFLAGS ?= -O2 -g3
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Werror
LIBUSB_LIBS ?= -lusb

bin_PROGRAMS = picus_behid
mphidflash_SOURCES = main.c hex.c usb-libusb.c
mphidflash_include_HEADERS = mphidflash.h
mphidflash_includedir = .
mphidflash_CFLAGS = $(LIBUSB_CFLAGS)
mphidflash_LDADD = $(LIBUSB_LIBS)
