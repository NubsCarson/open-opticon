#ifndef HE_PCM_H
#define HE_PCM_H

#include <stddef.h>
#include <stdint.h>

/*
 * Read a little-endian signed-16 mono PCM file into a freshly malloc'd buffer.
 * On success returns 0, sets *out (caller frees) and *n_samples; on open,
 * odd-size, allocation, or short-read error returns -1 and touches nothing.
 * Shared by the host-side sim tools so there is one PCM reader.
 */
int he_read_pcm(const char *path, int16_t **out, size_t *n_samples);

#endif /* HE_PCM_H */
