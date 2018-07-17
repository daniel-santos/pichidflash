AUTOMAKE_OPTIONS = foreign

CFLAGS ?= -O2 -g3
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Werror
LIBUSB_LIBS ?= -lusb

bin_PROGRAMS = picus_behid
picus_behid_SOURCES = main.c hex.c usb-libusb.c
picus_behid_include_HEADERS = mphidflash.h
picus_behid_includedir = .
picus_behid_CFLAGS = $(LIBUSB_CFLAGS)
picus_behid_LDADD = $(LIBUSB_LIBS)
