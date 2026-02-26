/*
 * eye4_accel.c — C accelerator for Eye4 RTSP proxy hot paths.
 *
 * Compile: gcc -O2 -shared -fPIC -o eye4_accel.so eye4_accel.c
 *
 * Functions:
 *   p2p_decrypt   — P2P_Proprietary stream cipher decrypt (per-byte XOR table)
 *   p2p_encrypt   — P2P_Proprietary stream cipher encrypt
 *   decode_adpcm  — IMA ADPCM decoder (high nibble first, per-frame reset)
 *   byteswap16    — 16-bit byte swap (LE↔BE)
 */

#include <stdint.h>

/* ── P2P_Proprietary cipher ─────────────────────────────────────────────── */

/*
 * Merged table layout: 256 entries.
 * merged[i] = original_tables[i & 3][i] = PE_TABLE[(key4[i&3] + i) & 0xFF]
 *
 * Decrypt: out[i] = in[i] ^ merged[prev]; prev = in[i]
 * Encrypt: out[i] = in[i] ^ merged[prev]; prev = out[i]
 */

void p2p_decrypt(const uint8_t *table, const uint8_t *in, uint8_t *out, int len) {
    uint8_t prev = 0;
    for (int i = 0; i < len; i++) {
        uint8_t c = in[i];
        out[i] = c ^ table[prev];
        prev = c;
    }
}

void p2p_encrypt(const uint8_t *table, const uint8_t *in, uint8_t *out, int len) {
    uint8_t prev = 0;
    for (int i = 0; i < len; i++) {
        uint8_t c = in[i] ^ table[prev];
        out[i] = c;
        prev = c;
    }
}

/* ── IMA ADPCM decoder ──────────────────────────────────────────────────── */

static const int16_t step_table[89] = {
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31,
    34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143,
    157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544,
    598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707,
    1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871,
    5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635,
    13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767,
};

static const int8_t index_table[16] = {
    -1, -1, -1, -1, 2, 4, 6, 8,
    -1, -1, -1, -1, 2, 4, 6, 8,
};

static inline int16_t decode_nibble(uint8_t nibble, int32_t *pred, int *idx) {
    int step = step_table[*idx];
    int diff = step >> 3;
    if (nibble & 1) diff += step >> 2;
    if (nibble & 2) diff += step >> 1;
    if (nibble & 4) diff += step;
    if (nibble & 8)
        *pred -= diff;
    else
        *pred += diff;
    if (*pred > 32767) *pred = 32767;
    else if (*pred < -32768) *pred = -32768;
    int new_idx = *idx + index_table[nibble];
    if (new_idx < 0) new_idx = 0;
    else if (new_idx > 88) new_idx = 88;
    *idx = new_idx;
    return (int16_t)*pred;
}

/*
 * Decode IMA ADPCM to PCM 16-bit signed little-endian.
 * High nibble first per byte. Predictor=0, index=0 (caller resets per frame).
 * out must have room for len*2 int16_t samples.
 */
void decode_adpcm(const uint8_t *data, int len, int16_t *out) {
    int32_t pred = 0;
    int idx = 0;
    for (int i = 0; i < len; i++) {
        uint8_t byte = data[i];
        *out++ = decode_nibble((byte >> 4) & 0x0F, &pred, &idx);
        *out++ = decode_nibble(byte & 0x0F, &pred, &idx);
    }
}

/* ── 16-bit byte swap ───────────────────────────────────────────────────── */

/*
 * Swap adjacent bytes pairwise (LE↔BE for 16-bit samples).
 * len must be even. In-place OK (in == out).
 */
void byteswap16(const uint8_t *in, uint8_t *out, int len) {
    for (int i = 0; i < len - 1; i += 2) {
        uint8_t a = in[i];
        uint8_t b = in[i + 1];
        out[i] = b;
        out[i + 1] = a;
    }
}
