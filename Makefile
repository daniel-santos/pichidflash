VERSION_MAIN = 1
VERSION_SUB  = 6

CC       = gcc
OBJS     = main.o hex.o

ifeq ($(shell uname -s),Darwin)
# Rules for Mac OS X
  OBJS    += usb-osx.o
  CFLAGS   = -fast
  LDFLAGS  = -Wl,-framework,IOKit,-framework,CoreFoundation
  SYSTEM = osx
else
# Rules for Linux, etc.
  OBJS    += usb-libusb.o
  CFLAGS   = -O2
  LDFLAGS  = -lusb
  SYSTEM = linux
endif

CFLAGS += -DVERSION_MAIN=$(VERSION_MAIN) -DVERSION_SUB=$(VERSION_SUB) -g -Wall -Wextra -Werror
EXEC = mphidflash

all: $(EXEC)

*.o: mphidflash.h

.c.o:
	$(CC) $(CFLAGS) -c $*.c


mphidflash: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(EXEC)

clean:
	rm -f *.o core $(EXEC)
