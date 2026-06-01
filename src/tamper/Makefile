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
	@echo "=== happy path: key erased, flag written, exit 0 ==="
	@echo "secret-key-blob" > /tmp/he-tamper-test.key
	./$(BINDIR)/he-tamper --simulate \
		--key-file /tmp/he-tamper-test.key \
		--flag-file /tmp/he-tamper-test.flag
	@test ! -f /tmp/he-tamper-test.key && echo "PASS: key erased" || (echo "FAIL: key survived"; exit 1)
	@test -f /tmp/he-tamper-test.flag && echo "PASS: flag written" || (echo "FAIL: no flag"; exit 1)
	@echo "=== erase FAILURE must exit nonzero and never falsely claim 'dead' ==="
	@mkdir -p /tmp/he-tamper-test.dir; \
	out=$$(./$(BINDIR)/he-tamper --simulate --key-file /tmp/he-tamper-test.dir --flag-file /tmp/he-tamper-test.flag 2>&1); rc=$$?; \
	rm -rf /tmp/he-tamper-test.dir; \
	if [ $$rc -eq 0 ]; then echo "FAIL: exited 0 despite erase failure"; exit 1; fi; \
	echo "PASS: nonzero exit on erase failure ($$rc)"; \
	if ! echo "$$out" | grep -q "NOT confirmed"; then echo "FAIL: missing NOT-confirmed warning"; exit 1; fi; \
	echo "PASS: reports device NOT confirmed dead"; \
	if echo "$$out" | grep -q "cryptographically dead"; then echo "FAIL: falsely claimed dead on erase failure"; exit 1; fi; \
	echo "PASS: does not falsely claim cryptographically dead"

clean:
	rm -rf $(BINDIR)
