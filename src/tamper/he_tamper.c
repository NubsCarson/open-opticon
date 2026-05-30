/*
 * Honest Ear — tamper-loop watcher (normal-world daemon, Linux).
 *
 * Watches a GPIO line wired to the enclosure's tamper loop (a normally-closed
 * conductive foil/wire path around the clear case, optionally OR'd with an LDR
 * for light-on-open). When the loop breaks (lid opened / case drilled), it
 * makes the device's signing key cryptographically unavailable:
 *
 *   1. securely erases the device key material (overwrite + unlink),
 *   2. writes a persistent tamper marker,
 *
 * so the next live challenge FAILS even though the firmware is unmodified —
 * "an opened device is cryptographically dead."
 *
 * SCOPE: this is the hackathon, theatre-grade mechanism. On a production build
 * the tamper line is wired directly to a secure element (ATECC608 / Zymkey) or
 * the i.MX CAAM so the *private key inside the chip* is zeroized in hardware,
 * with battery-backed detection that works while powered off. See THREAT_MODEL.
 *
 * Uses the Linux GPIO character-device v2 ABI (<linux/gpio.h>); no libgpiod
 * dependency. `--simulate` exercises the breach action without hardware.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<linux/gpio.h>)
#include <linux/gpio.h>
#include <sys/ioctl.h>
#define HE_HAVE_GPIO 1
#endif
#endif

static const char *key_file = NULL;
static const char *flag_file = "/var/lib/honest-ear/tamper.tripped";
static const char *exec_cmd = NULL; /* e.g. "he_host --trip" to latch the TA flag */

/* Best-effort secure erase: overwrite with random, fsync, then unlink. */
static int secure_erase(const char *path)
{
    FILE *f = fopen(path, "r+b");
    if (!f) {
        /* nothing to erase is not a failure */
        return (errno == ENOENT) ? 0 : -1;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    FILE *r = fopen("/dev/urandom", "rb");
    for (long i = 0; i < n; i++) {
        int c = r ? fgetc(r) : (int)(i * 1103515245u);
        fputc(c & 0xff, f);
    }
    fflush(f);
    fsync(fileno(f));
    if (r)
        fclose(r);
    fclose(f);
    return unlink(path);
}

static void write_flag(void)
{
    FILE *f = fopen(flag_file, "w");
    if (!f) {
        fprintf(stderr, "[tamper] WARNING: cannot write flag %s: %s\n",
                flag_file, strerror(errno));
        return;
    }
    time_t t = time(NULL);
    fprintf(f, "tamper tripped at %ld\n", (long)t);
    fclose(f);
}

static void breach_action(const char *why)
{
    fprintf(stderr,
            "\n================ TAMPER DETECTED ================\n"
            "  cause: %s\n"
            "  destroying device key material and tripping flag.\n"
            "=================================================\n\n",
            why);
    if (key_file) {
        if (secure_erase(key_file) == 0)
            fprintf(stderr, "[tamper] key material erased: %s\n", key_file);
        else
            fprintf(stderr, "[tamper] key erase issue (%s): %s\n", key_file,
                    strerror(errno));
    }
    write_flag();
    if (exec_cmd) {
        fprintf(stderr, "[tamper] running breach hook: %s\n", exec_cmd);
        int rc = system(exec_cmd);
        if (rc != 0)
            fprintf(stderr, "[tamper] breach hook exit code %d\n", rc);
    }
    fprintf(stderr, "[tamper] device is now cryptographically dead until "
                    "re-provisioned.\n");
}

#ifdef HE_HAVE_GPIO
/* Returns 0 on clean exit after a breach, non-zero on setup error. */
static int watch_gpio(const char *chip, unsigned int line, int active_low,
                      int loop)
{
    int cfd = open(chip, O_RDONLY | O_CLOEXEC);
    if (cfd < 0) {
        fprintf(stderr, "[tamper] open %s: %s\n", chip, strerror(errno));
        return 2;
    }

    struct gpio_v2_line_request req;
    memset(&req, 0, sizeof(req));
    req.offsets[0] = line;
    req.num_lines = 1;
    snprintf(req.consumer, sizeof(req.consumer), "honest-ear-tamper");
    req.config.flags = GPIO_V2_LINE_FLAG_INPUT |
                       GPIO_V2_LINE_FLAG_EDGE_RISING |
                       GPIO_V2_LINE_FLAG_EDGE_FALLING |
                       GPIO_V2_LINE_FLAG_BIAS_PULL_UP;
    if (active_low)
        req.config.flags |= GPIO_V2_LINE_FLAG_ACTIVE_LOW;

    if (ioctl(cfd, GPIO_V2_GET_LINE_IOCTL, &req) < 0) {
        fprintf(stderr, "[tamper] GPIO_V2_GET_LINE: %s\n", strerror(errno));
        close(cfd);
        return 2;
    }
    close(cfd);

    /* Read the current level; the loop should be CLOSED (logical 1) at start. */
    struct gpio_v2_line_values vals;
    memset(&vals, 0, sizeof(vals));
    vals.mask = 1;
    if (ioctl(req.fd, GPIO_V2_LINE_GET_VALUES_IOCTL, &vals) == 0) {
        if ((vals.bits & 1) == 0) {
            breach_action("tamper loop already OPEN at startup");
            if (!loop) {
                close(req.fd);
                return 0;
            }
        } else {
            fprintf(stderr, "[tamper] armed: loop closed, watching line %u\n",
                    line);
        }
    }

    struct pollfd pfd = {.fd = req.fd, .events = POLLIN};
    for (;;) {
        int pr = poll(&pfd, 1, -1);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        struct gpio_v2_line_event ev;
        ssize_t rd = read(req.fd, &ev, sizeof(ev));
        if (rd != sizeof(ev))
            continue;
        /* Any edge -> re-read level; logical 0 means the loop is broken. */
        memset(&vals, 0, sizeof(vals));
        vals.mask = 1;
        if (ioctl(req.fd, GPIO_V2_LINE_GET_VALUES_IOCTL, &vals) == 0 &&
            (vals.bits & 1) == 0) {
            breach_action("tamper loop OPENED");
            if (!loop) {
                close(req.fd);
                return 0;
            }
        }
    }
    close(req.fd);
    return 0;
}
#endif /* HE_HAVE_GPIO */

static void usage(const char *p)
{
    fprintf(stderr,
            "usage: %s --key-file <path> [--flag-file <path>]\n"
            "          [--chip /dev/gpiochip0] [--line N] [--active-low] [--loop]\n"
            "          [--simulate]\n\n"
            "  --simulate   run the breach action immediately (no GPIO), for testing\n",
            p);
}

int main(int argc, char **argv)
{
    const char *chip = "/dev/gpiochip0";
    unsigned int line = 17;
    int active_low = 0, loop = 0, simulate = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--key-file") && i + 1 < argc)
            key_file = argv[++i];
        else if (!strcmp(argv[i], "--flag-file") && i + 1 < argc)
            flag_file = argv[++i];
        else if (!strcmp(argv[i], "--exec") && i + 1 < argc)
            exec_cmd = argv[++i];
        else if (!strcmp(argv[i], "--chip") && i + 1 < argc)
            chip = argv[++i];
        else if (!strcmp(argv[i], "--line") && i + 1 < argc)
            line = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "--active-low"))
            active_low = 1;
        else if (!strcmp(argv[i], "--loop"))
            loop = 1;
        else if (!strcmp(argv[i], "--simulate"))
            simulate = 1;
        else {
            usage(argv[0]);
            return 2;
        }
    }

    if (simulate) {
        breach_action("--simulate");
        return 0;
    }

#ifdef HE_HAVE_GPIO
    fprintf(stderr, "[tamper] watching %s line %u (active_low=%d)\n", chip,
            line, active_low);
    return watch_gpio(chip, line, active_low, loop);
#else
    (void)chip;
    (void)line;
    (void)active_low;
    (void)loop;
    fprintf(stderr, "[tamper] <linux/gpio.h> not available; build on the "
                    "target or use --simulate.\n");
    return 3;
#endif
}
