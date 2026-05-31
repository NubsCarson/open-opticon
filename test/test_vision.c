/*
 * Honest Ear — vision occupancy detector unit test.
 *
 * Builds grayscale frames in memory and asserts the predicate: a flat scene is
 * EMPTY, a textured subject is OCCUPIED, and a single textured tile stays below
 * the occupancy threshold. Also locks the config-blob length. No I/O, no float.
 */
#include "he_vision.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;

static void check(int cond, const char *msg)
{
    if (!cond) {
        printf("  FAIL: %s\n", msg);
        fails++;
    } else {
        printf("  ok:   %s\n", msg);
    }
}

/* Paint a w x h block of vertical 0/255 stripes at (bx,by) into a W-wide frame. */
static void paint_stripes(uint8_t *frame, uint32_t W, uint32_t bx, uint32_t by,
                          uint32_t w, uint32_t h)
{
    for (uint32_t y = 0; y < h; y++)
        for (uint32_t x = 0; x < w; x++)
            frame[(size_t)(by + y) * W + (bx + x)] = (x & 1u) ? 255 : 0;
}

int main(void)
{
    printf("test_vision:\n");

    he_vision_config_t cfg;
    he_vision_default_config(&cfg);
    const size_t n = (size_t)cfg.width * cfg.height;
    uint8_t *frame = malloc(n);
    if (!frame) {
        printf("  FAIL: alloc\n");
        return 1;
    }

    he_vision_result_t res;

    /* 1) Flat scene -> EMPTY, no active tiles. */
    memset(frame, 128, n);
    he_vision_run(&cfg, frame, n, &res);
    check(res.tiles == 16, "flat: 16 tiles examined (4x4 grid)");
    check(res.active_tiles == 0, "flat: no active tiles");
    check(res.presence == 0 && res.scene == HE_SCENE_EMPTY, "flat -> empty");

    /* 2) A 32x32 textured subject (4 tiles) -> OCCUPIED. */
    memset(frame, 128, n);
    paint_stripes(frame, cfg.width, 0, 0, 32, 32);
    he_vision_run(&cfg, frame, n, &res);
    check(res.active_tiles == 4, "subject: 4 tiles active");
    check(res.presence == 1 && res.scene == HE_SCENE_OCCUPIED, "subject -> occupied");

    /* 3) A single 16x16 textured tile stays below the occupancy threshold. */
    memset(frame, 128, n);
    paint_stripes(frame, cfg.width, 0, 0, 16, 16);
    he_vision_run(&cfg, frame, n, &res);
    check(res.active_tiles == 1, "one textured tile: 1 active");
    check(res.presence == 0 && res.scene == HE_SCENE_EMPTY,
          "one tile below min_active_tiles -> empty");

    /* 4) Config blob length is the documented constant. */
    uint8_t blob[HE_VISION_BLOB_LEN];
    check(he_vision_config_blob(&cfg, blob, sizeof(blob)) == HE_VISION_BLOB_LEN,
          "config blob length == HE_VISION_BLOB_LEN");

    /* 5) Scene names are stable. */
    check(strcmp(he_scene_name(HE_SCENE_OCCUPIED), "occupied") == 0 &&
              strcmp(he_scene_name(HE_SCENE_EMPTY), "empty") == 0,
          "scene names stable");

    free(frame);

    if (fails) {
        printf("test_vision: %d FAILURE(S)\n", fails);
        return 1;
    }
    printf("test_vision: all passed\n");
    return 0;
}
