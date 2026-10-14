CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wformat=2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now

all: dnsq

dnsq: dnsq.c
	$(CC) $(CFLAGS) -o $@ dnsq.c $(LDFLAGS)

clean:
	rm -f dnsq

.PHONY: all clean
