/*
 * Honest Ear — in-enclave vision occupancy detector implementation.
 * Integer-only, no float, no allocation. See he_vision.h.
 */
#include "he_vision.h"

#include "he_serialize.h"

#include <string.h>

void he_vision_default_config(he_vision_config_t *cfg)
{
    if (!cfg)
        return;
    cfg->width = 64;
    cfg->height = 64;
    cfg->tile = 16;            /* -> a 4x4 grid of 16 tiles */
    cfg->activity_floor = 800; /* per-tile sum of |dx|+|dy| (8-bit pixels) */
    cfg->min_active_tiles = 2; /* OCCUPIED once >= 2 tiles show structure */
}

size_t he_vision_config_blob(const he_vision_config_t *cfg, uint8_t *out,
                             size_t cap)
{
    if (!cfg || !out || cap < HE_VISION_BLOB_LEN)
        return 0;
    he_be64(out + 0, cfg->width);
    he_be64(out + 8, cfg->height);
    he_be64(out + 16, cfg->tile);
    he_be64(out + 24, cfg->activity_floor);
    he_be64(out + 32, cfg->min_active_tiles);
    return HE_VISION_BLOB_LEN;
}

const char *he_scene_name(he_scene_t s)
{
    return (s == HE_SCENE_OCCUPIED) ? "occupied" : "empty";
}

void he_vision_run(const he_vision_config_t *cfg, const uint8_t *frame,
                   size_t n_pixels, he_vision_result_t *res)
{
    if (!res)
        return;
    memset(res, 0, sizeof(*res));
    if (!cfg || !frame || cfg->tile == 0 || cfg->width == 0 || cfg->height == 0)
        return;
    if (cfg->width < cfg->tile || cfg->height < cfg->tile)
        return; /* frame smaller than one tile: leave res zeroed (tiles==0)
                   rather than silently report a confident EMPTY */
    if (n_pixels < (size_t)cfg->width * cfg->height)
        return; /* buffer too small for the declared geometry */

    const uint32_t W = cfg->width;
    const uint32_t tile = cfg->tile;
    /* Floor division: a width/height not a multiple of tile leaves a right/
       bottom margin (< tile wide) unexamined — geometry is in config_hash. */
    const uint32_t tiles_x = W / tile;
    const uint32_t tiles_y = cfg->height / tile;

    for (uint32_t ty = 0; ty < tiles_y; ty++) {
        for (uint32_t tx = 0; tx < tiles_x; tx++) {
            const uint32_t x0 = tx * tile;
            const uint32_t y0 = ty * tile;
            uint64_t energy = 0;

            /* In-tile gradients only: dx up to tile-2 columns, dy up to
             * tile-2 rows, so a tile never reads its neighbours' pixels (clean
             * per-tile separation, deterministic regardless of grid position). */
            for (uint32_t y = 0; y < tile; y++) {
                const uint8_t *row = frame + (size_t)(y0 + y) * W + x0;
                for (uint32_t x = 0; x < tile; x++) {
                    if (x + 1 < tile) {
                        int d = (int)row[x + 1] - (int)row[x];
                        energy += (uint64_t)(d < 0 ? -d : d);
                    }
                    if (y + 1 < tile) {
                        int d = (int)row[x + (size_t)W] - (int)row[x];
                        energy += (uint64_t)(d < 0 ? -d : d);
                    }
                }
            }

            res->tiles++;
            if (energy >= cfg->activity_floor)
                res->active_tiles++;
        }
    }

    res->presence = (res->active_tiles >= cfg->min_active_tiles) ? 1u : 0u;
    res->scene = res->presence ? HE_SCENE_OCCUPIED : HE_SCENE_EMPTY;
}
