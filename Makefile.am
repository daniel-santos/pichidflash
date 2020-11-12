AUTOMAKE_OPTIONS = foreign

CFLAGS ?= -O2 -g3
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Werror
LIBUSB_LIBS ?= -lusb

bin_PROGRAMS = pichidflash
pichidflash_SOURCES = main.c hex.c usb-libusb.c port.c log.c
pichidflash_include_HEADERS = mphidflash.h log.h
pichidflash_includedir = .
pichidflash_CFLAGS = $(LIBUSB_CFLAGS)
pichidflash_LDADD = $(LIBUSB_LIBS)
