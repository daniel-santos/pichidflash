AUTOMAKE_OPTIONS = foreign

CFLAGS ?= -O2 -g3
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Werror
LIBUSB_LIBS ?= -lusb

bin_PROGRAMS = pic_usb_hid_tool
pic_usb_hid_tool_SOURCES = main.c hex.c usb-libusb.c
pic_usb_hid_tool_include_HEADERS = mphidflash.h
pic_usb_hid_tool_includedir = .
pic_usb_hid_tool_CFLAGS = $(LIBUSB_CFLAGS)
pic_usb_hid_tool_LDADD = $(LIBUSB_LIBS)
