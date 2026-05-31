#include "he_pcm.h"

#include <stdio.h>
#include <stdlib.h>

int he_read_pcm(const char *path, int16_t **out, size_t *n_samples)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || (sz % 2) != 0) {
        fclose(f);
        return -1;
    }
    int16_t *buf = malloc((size_t)sz ? (size_t)sz : 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return -1;
    }
    fclose(f);
    *out = buf;
    *n_samples = (size_t)sz / 2;
    return 0;
}
