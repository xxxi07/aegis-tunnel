# AEGIS-Tunnel Makefile
# Quick build without CMake:  make [target]
# Full CMake build:           make cmake

CC       ?= gcc
CFLAGS   ?= -O2
CFLAGS   += -std=c99 -D_GNU_SOURCE -Wall -Wextra -Wpedantic
CFLAGS   += -Wshadow -Wconversion -Wstrict-prototypes -Wmissing-prototypes
CFLAGS   += -Wno-declaration-after-statement
# Uncomment to use thread pool instead of fork():
# CFLAGS   += -DWITH_THREADPOOL
LDFLAGS  += -lssl -lcrypto -lpthread

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
LIBDIR   ?= $(PREFIX)/lib

SRC_DIR  := src
INC      := -I$(SRC_DIR)

# ── Architecture detection ──
ARCH := $(shell uname -m)
IS_ARM := $(filter aarch64 arm64 armv8%,$(ARCH))

ifneq ($(IS_ARM),)
    # ARMv8 Crypto extensions (all ARMv8+ chips support this)
    CFLAGS += -march=armv8-a+crypto
endif

# ── Source files by module ──
CRYPTO   := $(SRC_DIR)/crypto/aegis.c
ifneq ($(IS_ARM),)
CRYPTO   += $(SRC_DIR)/crypto/neon/aegis128-plain.c \
             $(SRC_DIR)/crypto/neon/aegis128-armcrypto.c
endif
UTIL     := $(SRC_DIR)/util/util.c $(SRC_DIR)/util/log.c $(SRC_DIR)/util/config.c $(SRC_DIR)/util/iniconfig.c
PROTOCOL := $(SRC_DIR)/protocol/handshake.c $(SRC_DIR)/protocol/ecdh.c $(SRC_DIR)/protocol/frame_reader.c $(SRC_DIR)/protocol/keyfile.c
TUNNEL   := $(SRC_DIR)/tunnel/tunnel.c $(SRC_DIR)/tunnel/threadpool.c $(SRC_DIR)/tunnel/tun.c
PROXY    := $(SRC_DIR)/proxy/socks5.c

LIB_SRCS := $(CRYPTO) $(UTIL) $(PROTOCOL) $(TUNNEL) $(PROXY)
LIB_OBJS := $(LIB_SRCS:.c=.o)

MODE_SRCS := $(SRC_DIR)/main.c $(SRC_DIR)/mode_psk.c $(SRC_DIR)/mode_tun.c
MAIN_SRCS  := $(MODE_SRCS) $(LIB_SRCS)
MAIN_OBJS  := $(MAIN_SRCS:.c=.o)

TEST_SRCS := tests/test_aegis.c tests/test_tunnel.c tests/e2e_test.c tests/bench_aegis.c

# ═══════════════════════════════════════════════════════════════

.PHONY: all clean install uninstall cmake debug release test

all: aegis-tunnel aegis-tunnel-keygen test-aegis test-tunnel e2e-test bench-aegis

# ── Main executable ──
aegis-tunnel: $(MAIN_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "  → $@ built"

# ── Libraries ──
libaegis-tunnel.so: $(LIB_OBJS)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $^ $(LDFLAGS)
	@echo "  → $@ built"

libaegis-tunnel.a: $(LIB_OBJS)
	$(AR) rcs $@ $^
	@echo "  → $@ built"

# ── Key generation tool ──
KEYGEN_SRCS := src/keygen.c src/protocol/ecdh.c src/protocol/keyfile.c src/util/util.c
KEYGER_OBJS := $(KEYGEN_SRCS:.c=.o)

aegis-tunnel-keygen: $(KEYGEN_SRCS)
	$(CC) $(CFLAGS) $(INC) -o $@ $(KEYGEN_SRCS) $(LDFLAGS)
	@echo "  → $@ built"

# ── Object files ──
%.o: %.c
	$(CC) $(CFLAGS) $(INC) -c $< -o $@

# ── Tests ──
test-aegis: $(CRYPTO) $(SRC_DIR)/util/util.c tests/test_aegis.c
	$(CC) $(CFLAGS) $(INC) -o $@ tests/test_aegis.c $(CRYPTO) $(SRC_DIR)/util/util.c -lssl -lcrypto
	@echo "  → $@ built"

test-tunnel: $(CRYPTO) $(SRC_DIR)/util/util.c $(PROTOCOL) $(TUNNEL) tests/test_tunnel.c
	$(CC) $(CFLAGS) $(INC) -o $@ tests/test_tunnel.c $(CRYPTO) $(SRC_DIR)/util/util.c $(PROTOCOL) $(TUNNEL) $(LDFLAGS)
	@echo "  → $@ built"

e2e-test: $(CRYPTO) $(SRC_DIR)/util/util.c $(PROTOCOL) $(TUNNEL) tests/e2e_test.c
	$(CC) $(CFLAGS) $(INC) -o $@ tests/e2e_test.c $(CRYPTO) $(SRC_DIR)/util/util.c $(PROTOCOL) $(TUNNEL) $(LDFLAGS)
	@echo "  → $@ built"

bench-aegis: $(CRYPTO) $(SRC_DIR)/util/util.c tests/bench_aegis.c
	$(CC) $(CFLAGS) $(INC) -o $@ tests/bench_aegis.c $(CRYPTO) $(SRC_DIR)/util/util.c -lssl -lcrypto
	@echo "  → $@ built"

test: test-aegis test-tunnel e2e-test
	@echo "=== test-aegis ===" && ./test-aegis
	@echo "=== test-tunnel ===" && timeout 10 ./test-tunnel
	@echo "=== e2e-test ===" && timeout 10 ./e2e-test
	@echo "=== ALL TESTS PASSED ==="

# ── Build variants ──
debug: CFLAGS = -std=c99 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -g -O0 \
               -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer
debug: LDFLAGS += -fsanitize=address -fsanitize=undefined
debug: all

release: CFLAGS = -std=c99 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -O3 -march=native -flto
release: LDFLAGS += -flto
release: all

# ── CMake wrapper ──
cmake:
	cmake -B build -DCMAKE_BUILD_TYPE=Release
	cmake --build build -j$$(nproc)

# ── Install ──
install: all
	install -D -m 755 aegis-tunnel $(DESTDIR)$(BINDIR)/aegis-tunnel
	@if [ -f libaegis-tunnel.so ]; then \
	    install -D -m 755 libaegis-tunnel.so $(DESTDIR)$(LIBDIR)/libaegis-tunnel.so; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/aegis-tunnel
	rm -f $(DESTDIR)$(LIBDIR)/libaegis-tunnel.so

# ── Clean ──
clean:
	rm -f aegis-tunnel libaegis-tunnel.so libaegis-tunnel.a
	rm -f aegis-tunnel-keygen test-aegis test-tunnel e2e-test bench-aegis
	find $(SRC_DIR) tests -name '*.o' -delete
