# Host simulator + unit-test build. Requires gcc + OpenSSL dev headers.
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c11
COMMON   = ../src/common
INCLUDES = -I$(COMMON)
LDLIBS   = -lcrypto

COMMON_SRC = $(COMMON)/he_detector.c $(COMMON)/he_payload.c

BINDIR = bin

.PHONY: all clean
all: $(BINDIR)/he-attest-sim $(BINDIR)/he-detect $(BINDIR)/test_detector $(BINDIR)/test_payload

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/he-attest-sim: he_sim_sign.c $(COMMON_SRC) | $(BINDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDLIBS)

$(BINDIR)/he-detect: he_detect_cli.c $(COMMON_SRC) | $(BINDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

$(BINDIR)/test_detector: ../test/test_detector.c $(COMMON_SRC) | $(BINDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ -lm

$(BINDIR)/test_payload: ../test/test_payload.c $(COMMON_SRC) | $(BINDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^

.PHONY: test
test: all
	./$(BINDIR)/test_payload
	./$(BINDIR)/test_detector

clean:
	rm -rf $(BINDIR)
