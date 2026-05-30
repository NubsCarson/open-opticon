# Tamper watcher — builds on the target (Linux normal world on Pi / i.MX).
CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
BINDIR  = bin

.PHONY: all clean test
all: $(BINDIR)/he-tamper

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/he-tamper: he_tamper.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $<

# Exercise the breach action without hardware.
test: all
	@echo "secret-key-blob" > /tmp/he-tamper-test.key
	./$(BINDIR)/he-tamper --simulate \
		--key-file /tmp/he-tamper-test.key \
		--flag-file /tmp/he-tamper-test.flag
	@test ! -f /tmp/he-tamper-test.key && echo "PASS: key erased" || (echo "FAIL: key survived"; exit 1)
	@test -f /tmp/he-tamper-test.flag && echo "PASS: flag written" || (echo "FAIL: no flag"; exit 1)

clean:
	rm -rf $(BINDIR)
