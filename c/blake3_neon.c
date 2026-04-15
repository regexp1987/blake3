#include "blake3_impl.h"

#include <arm_neon.h>

#ifdef __ARM_BIG_ENDIAN
#error "This implementation only supports little-endian ARM."
#endif

INLINE uint32x4_t loadu_128(const uint8_t uc_src[16]) {
  return vreinterpretq_u32_u8(vld1q_u8(uc_src));
}

INLINE void storeu_128(uint32x4_t ui_src, uint8_t uc_dest[16]) {
  vst1q_u8(uc_dest, vreinterpretq_u8_u32(ui_src));
}

INLINE uint32x4_t add_128(uint32x4_t ui_a, uint32x4_t ui_b) {
  return vaddq_u32(ui_a, ui_b);
}

INLINE uint32x4_t xor_128(uint32x4_t ui_a, uint32x4_t ui_b) {
  return veorq_u32(ui_a, ui_b);
}

INLINE uint32x4_t set1_128(uint32_t ui_x) { return vld1q_dup_u32(&ui_x); }

INLINE uint32x4_t set4(uint32_t ui_a, uint32_t ui_b, uint32_t ui_c, uint32_t ui_d) {
  uint32_t ui_array[4] = {ui_a, ui_b, ui_c, ui_d};
  return vld1q_u32(ui_array);
}

INLINE uint32x4_t rot16_128(uint32x4_t ui_x) {
  return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(ui_x)));
}

INLINE uint32x4_t rot12_128(uint32x4_t ui_x) {
  return vsriq_n_u32(vshlq_n_u32(ui_x, 32-12), ui_x, 12);
}

INLINE uint32x4_t rot8_128(uint32x4_t ui_x) {
#if defined(__clang__)
  return vreinterpretq_u32_u8(__builtin_shufflevector(vreinterpretq_u8_u32(ui_x), vreinterpretq_u8_u32(ui_x), 1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12));
#elif __GNUC__ * 10000 + __GNUC_MINOR__ * 100 >=40700
  static const uint8x16_t uc_r8 = {1,2,3,0,5,6,7,4,9,10,11,8,13,14,15,12};
  return vreinterpretq_u32_u8(__builtin_shuffle(vreinterpretq_u8_u32(ui_x), vreinterpretq_u8_u32(ui_x), uc_r8));
#else
  return vsriq_n_u32(vshlq_n_u32(ui_x, 32-8), ui_x, 8);
#endif
}

INLINE uint32x4_t rot7_128(uint32x4_t ui_x) {
  return vsriq_n_u32(vshlq_n_u32(ui_x, 32-7), ui_x, 7);
}

INLINE void round_fn4(uint32x4_t ui_v[16], uint32x4_t ui_m[16], size_t ul_r) {
  ui_v[0] = add_128(ui_v[0], ui_m[(size_t)MSG_SCHEDULE[ul_r][0]]);
  ui_v[1] = add_128(ui_v[1], ui_m[(size_t)MSG_SCHEDULE[ul_r][2]]);
  ui_v[2] = add_128(ui_v[2], ui_m[(size_t)MSG_SCHEDULE[ul_r][4]]);
  ui_v[3] = add_128(ui_v[3], ui_m[(size_t)MSG_SCHEDULE[ul_r][6]]);
  ui_v[0] = add_128(ui_v[0], ui_v[4]);
  ui_v[1] = add_128(ui_v[1], ui_v[5]);
  ui_v[2] = add_128(ui_v[2], ui_v[6]);
  ui_v[3] = add_128(ui_v[3], ui_v[7]);
  ui_v[12] = xor_128(ui_v[12], ui_v[0]);
  ui_v[13] = xor_128(ui_v[13], ui_v[1]);
  ui_v[14] = xor_128(ui_v[14], ui_v[2]);
  ui_v[15] = xor_128(ui_v[15], ui_v[3]);
  ui_v[12] = rot16_128(ui_v[12]);
  ui_v[13] = rot16_128(ui_v[13]);
  ui_v[14] = rot16_128(ui_v[14]);
  ui_v[15] = rot16_128(ui_v[15]);
  ui_v[8] = add_128(ui_v[8], ui_v[12]);
  ui_v[9] = add_128(ui_v[9], ui_v[13]);
  ui_v[10] = add_128(ui_v[10], ui_v[14]);
  ui_v[11] = add_128(ui_v[11], ui_v[15]);
  ui_v[4] = xor_128(ui_v[4], ui_v[8]);
  ui_v[5] = xor_128(ui_v[5], ui_v[9]);
  ui_v[6] = xor_128(ui_v[6], ui_v[10]);
  ui_v[7] = xor_128(ui_v[7], ui_v[11]);
  ui_v[4] = rot12_128(ui_v[4]);
  ui_v[5] = rot12_128(ui_v[5]);
  ui_v[6] = rot12_128(ui_v[6]);
  ui_v[7] = rot12_128(ui_v[7]);
  ui_v[0] = add_128(ui_v[0], ui_m[(size_t)MSG_SCHEDULE[ul_r][1]]);
  ui_v[1] = add_128(ui_v[1], ui_m[(size_t)MSG_SCHEDULE[ul_r][3]]);
  ui_v[2] = add_128(ui_v[2], ui_m[(size_t)MSG_SCHEDULE[ul_r][5]]);
  ui_v[3] = add_128(ui_v[3], ui_m[(size_t)MSG_SCHEDULE[ul_r][7]]);
  ui_v[0] = add_128(ui_v[0], ui_v[4]);
  ui_v[1] = add_128(ui_v[1], ui_v[5]);
  ui_v[2] = add_128(ui_v[2], ui_v[6]);
  ui_v[3] = add_128(ui_v[3], ui_v[7]);
  ui_v[12] = xor_128(ui_v[12], ui_v[0]);
  ui_v[13] = xor_128(ui_v[13], ui_v[1]);
  ui_v[14] = xor_128(ui_v[14], ui_v[2]);
  ui_v[15] = xor_128(ui_v[15], ui_v[3]);
  ui_v[12] = rot8_128(ui_v[12]);
  ui_v[13] = rot8_128(ui_v[13]);
  ui_v[14] = rot8_128(ui_v[14]);
  ui_v[15] = rot8_128(ui_v[15]);
  ui_v[8] = add_128(ui_v[8], ui_v[12]);
  ui_v[9] = add_128(ui_v[9], ui_v[13]);
  ui_v[10] = add_128(ui_v[10], ui_v[14]);
  ui_v[11] = add_128(ui_v[11], ui_v[15]);
  ui_v[4] = xor_128(ui_v[4], ui_v[8]);
  ui_v[5] = xor_128(ui_v[5], ui_v[9]);
  ui_v[6] = xor_128(ui_v[6], ui_v[10]);
  ui_v[7] = xor_128(ui_v[7], ui_v[11]);
  ui_v[4] = rot7_128(ui_v[4]);
  ui_v[5] = rot7_128(ui_v[5]);
  ui_v[6] = rot7_128(ui_v[6]);
  ui_v[7] = rot7_128(ui_v[7]);

  ui_v[0] = add_128(ui_v[0], ui_m[(size_t)MSG_SCHEDULE[ul_r][8]]);
  ui_v[1] = add_128(ui_v[1], ui_m[(size_t)MSG_SCHEDULE[ul_r][10]]);
  ui_v[2] = add_128(ui_v[2], ui_m[(size_t)MSG_SCHEDULE[ul_r][12]]);
  ui_v[3] = add_128(ui_v[3], ui_m[(size_t)MSG_SCHEDULE[ul_r][14]]);
  ui_v[0] = add_128(ui_v[0], ui_v[5]);
  ui_v[1] = add_128(ui_v[1], ui_v[6]);
  ui_v[2] = add_128(ui_v[2], ui_v[7]);
  ui_v[3] = add_128(ui_v[3], ui_v[4]);
  ui_v[15] = xor_128(ui_v[15], ui_v[0]);
  ui_v[12] = xor_128(ui_v[12], ui_v[1]);
  ui_v[13] = xor_128(ui_v[13], ui_v[2]);
  ui_v[14] = xor_128(ui_v[14], ui_v[3]);
  ui_v[15] = rot16_128(ui_v[15]);
  ui_v[12] = rot16_128(ui_v[12]);
  ui_v[13] = rot16_128(ui_v[13]);
  ui_v[14] = rot16_128(ui_v[14]);
  ui_v[10] = add_128(ui_v[10], ui_v[15]);
  ui_v[11] = add_128(ui_v[11], ui_v[12]);
  ui_v[8] = add_128(ui_v[8], ui_v[13]);
  ui_v[9] = add_128(ui_v[9], ui_v[14]);
  ui_v[5] = xor_128(ui_v[5], ui_v[10]);
  ui_v[6] = xor_128(ui_v[6], ui_v[11]);
  ui_v[7] = xor_128(ui_v[7], ui_v[8]);
  ui_v[4] = xor_128(ui_v[4], ui_v[9]);
  ui_v[5] = rot12_128(ui_v[5]);
  ui_v[6] = rot12_128(ui_v[6]);
  ui_v[7] = rot12_128(ui_v[7]);
  ui_v[4] = rot12_128(ui_v[4]);
  ui_v[0] = add_128(ui_v[0], ui_m[(size_t)MSG_SCHEDULE[ul_r][9]]);
  ui_v[1] = add_128(ui_v[1], ui_m[(size_t)MSG_SCHEDULE[ul_r][11]]);
  ui_v[2] = add_128(ui_v[2], ui_m[(size_t)MSG_SCHEDULE[ul_r][13]]);
  ui_v[3] = add_128(ui_v[3], ui_m[(size_t)MSG_SCHEDULE[ul_r][15]]);
  ui_v[0] = add_128(ui_v[0], ui_v[5]);
  ui_v[1] = add_128(ui_v[1], ui_v[6]);
  ui_v[2] = add_128(ui_v[2], ui_v[7]);
  ui_v[3] = add_128(ui_v[3], ui_v[4]);
  ui_v[15] = xor_128(ui_v[15], ui_v[0]);
  ui_v[12] = xor_128(ui_v[12], ui_v[1]);
  ui_v[13] = xor_128(ui_v[13], ui_v[2]);
  ui_v[14] = xor_128(ui_v[14], ui_v[3]);
  ui_v[15] = rot8_128(ui_v[15]);
  ui_v[12] = rot8_128(ui_v[12]);
  ui_v[13] = rot8_128(ui_v[13]);
  ui_v[14] = rot8_128(ui_v[14]);
  ui_v[10] = add_128(ui_v[10], ui_v[15]);
  ui_v[11] = add_128(ui_v[11], ui_v[12]);
  ui_v[8] = add_128(ui_v[8], ui_v[13]);
  ui_v[9] = add_128(ui_v[9], ui_v[14]);
  ui_v[5] = xor_128(ui_v[5], ui_v[10]);
  ui_v[6] = xor_128(ui_v[6], ui_v[11]);
  ui_v[7] = xor_128(ui_v[7], ui_v[8]);
  ui_v[4] = xor_128(ui_v[4], ui_v[9]);
  ui_v[5] = rot7_128(ui_v[5]);
  ui_v[6] = rot7_128(ui_v[6]);
  ui_v[7] = rot7_128(ui_v[7]);
  ui_v[4] = rot7_128(ui_v[4]);
}

INLINE void transpose_vecs_128(uint32x4_t ui_vecs[4]) {
  uint32x4x2_t ui_rows01 = vtrnq_u32(ui_vecs[0], ui_vecs[1]);
  uint32x4x2_t ui_rows23 = vtrnq_u32(ui_vecs[2], ui_vecs[3]);

  ui_vecs[0] =
    vcombine_u32(vget_low_u32(ui_rows01.val[0]), vget_low_u32(ui_rows23.val[0]));
  ui_vecs[1] =
    vcombine_u32(vget_low_u32(ui_rows01.val[1]), vget_low_u32(ui_rows23.val[1]));
  ui_vecs[2] =
    vcombine_u32(vget_high_u32(ui_rows01.val[0]), vget_high_u32(ui_rows23.val[0]));
  ui_vecs[3] =
    vcombine_u32(vget_high_u32(ui_rows01.val[1]), vget_high_u32(ui_rows23.val[1]));
}

INLINE void transpose_msg_vecs4(const uint8_t *const *p_inputs,
                                size_t ul_block_offset, uint32x4_t ui_out[16]) {
  ui_out[0] = loadu_128(&p_inputs[0][ul_block_offset + 0 * sizeof(uint32x4_t)]);
  ui_out[1] = loadu_128(&p_inputs[1][ul_block_offset + 0 * sizeof(uint32x4_t)]);
  ui_out[2] = loadu_128(&p_inputs[2][ul_block_offset + 0 * sizeof(uint32x4_t)]);
  ui_out[3] = loadu_128(&p_inputs[3][ul_block_offset + 0 * sizeof(uint32x4_t)]);
  ui_out[4] = loadu_128(&p_inputs[0][ul_block_offset + 1 * sizeof(uint32x4_t)]);
  ui_out[5] = loadu_128(&p_inputs[1][ul_block_offset + 1 * sizeof(uint32x4_t)]);
  ui_out[6] = loadu_128(&p_inputs[2][ul_block_offset + 1 * sizeof(uint32x4_t)]);
  ui_out[7] = loadu_128(&p_inputs[3][ul_block_offset + 1 * sizeof(uint32x4_t)]);
  ui_out[8] = loadu_128(&p_inputs[0][ul_block_offset + 2 * sizeof(uint32x4_t)]);
  ui_out[9] = loadu_128(&p_inputs[1][ul_block_offset + 2 * sizeof(uint32x4_t)]);
  ui_out[10] = loadu_128(&p_inputs[2][ul_block_offset + 2 * sizeof(uint32x4_t)]);
  ui_out[11] = loadu_128(&p_inputs[3][ul_block_offset + 2 * sizeof(uint32x4_t)]);
  ui_out[12] = loadu_128(&p_inputs[0][ul_block_offset + 3 * sizeof(uint32x4_t)]);
  ui_out[13] = loadu_128(&p_inputs[1][ul_block_offset + 3 * sizeof(uint32x4_t)]);
  ui_out[14] = loadu_128(&p_inputs[2][ul_block_offset + 3 * sizeof(uint32x4_t)]);
  ui_out[15] = loadu_128(&p_inputs[3][ul_block_offset + 3 * sizeof(uint32x4_t)]);
  transpose_vecs_128(&ui_out[0]);
  transpose_vecs_128(&ui_out[4]);
  transpose_vecs_128(&ui_out[8]);
  transpose_vecs_128(&ui_out[12]);
}

INLINE void load_counters4(uint64_t ul_counter, bool b_increment_counter,
                           uint32x4_t *p_ui_out_low, uint32x4_t *p_ui_out_high) {
  uint64_t ul_mask = (b_increment_counter ? ~0 : 0);
  *p_ui_out_low = set4(
      counter_low(ul_counter + (ul_mask & 0)), counter_low(ul_counter + (ul_mask & 1)),
      counter_low(ul_counter + (ul_mask & 2)), counter_low(ul_counter + (ul_mask & 3)));
  *p_ui_out_high = set4(
      counter_high(ul_counter + (ul_mask & 0)), counter_high(ul_counter + (ul_mask & 1)),
      counter_high(ul_counter + (ul_mask & 2)), counter_high(ul_counter + (ul_mask & 3)));
}

static void blake3_hash4_neon(const uint8_t *const *p_inputs, size_t ul_blocks,
                              const uint32_t ui_key[8], uint64_t ul_counter,
                              bool b_increment_counter, uint8_t uc_flags,
                              uint8_t uc_flags_start, uint8_t uc_flags_end,
                              uint8_t *p_uc_out) {
  uint32x4_t ui_h_vecs[8] = {
    set1_128(ui_key[0]), set1_128(ui_key[1]), set1_128(ui_key[2]), set1_128(ui_key[3]),
    set1_128(ui_key[4]), set1_128(ui_key[5]), set1_128(ui_key[6]), set1_128(ui_key[7]),
  };
  uint32x4_t ui_counter_low_vec, ui_counter_high_vec;
  load_counters4(ul_counter, b_increment_counter, &ui_counter_low_vec,
                 &ui_counter_high_vec);
  uint8_t uc_block_flags = uc_flags | uc_flags_start;

  for (size_t ul_block = 0; ul_block < ul_blocks; ul_block++) {
    if (ul_block + 1 == ul_blocks) {
      uc_block_flags |= uc_flags_end;
    }
    uint32x4_t ui_block_len_vec = set1_128(BLAKE3_BLOCK_LEN);
    uint32x4_t ui_block_flags_vec = set1_128(uc_block_flags);
    uint32x4_t ui_msg_vecs[16];
    transpose_msg_vecs4(p_inputs, ul_block * BLAKE3_BLOCK_LEN, ui_msg_vecs);

    uint32x4_t ui_v[16] = {
      ui_h_vecs[0],       ui_h_vecs[1],        ui_h_vecs[2],       ui_h_vecs[3],
      ui_h_vecs[4],       ui_h_vecs[5],        ui_h_vecs[6],       ui_h_vecs[7],
      set1_128(IV[0]), set1_128(IV[1]),  set1_128(IV[2]), set1_128(IV[3]),
      ui_counter_low_vec, ui_counter_high_vec, ui_block_len_vec,   ui_block_flags_vec,
    };
    round_fn4(ui_v, ui_msg_vecs, 0);
    round_fn4(ui_v, ui_msg_vecs, 1);
    round_fn4(ui_v, ui_msg_vecs, 2);
    round_fn4(ui_v, ui_msg_vecs, 3);
    round_fn4(ui_v, ui_msg_vecs, 4);
    round_fn4(ui_v, ui_msg_vecs, 5);
    round_fn4(ui_v, ui_msg_vecs, 6);
    ui_h_vecs[0] = xor_128(ui_v[0], ui_v[8]);
    ui_h_vecs[1] = xor_128(ui_v[1], ui_v[9]);
    ui_h_vecs[2] = xor_128(ui_v[2], ui_v[10]);
    ui_h_vecs[3] = xor_128(ui_v[3], ui_v[11]);
    ui_h_vecs[4] = xor_128(ui_v[4], ui_v[12]);
    ui_h_vecs[5] = xor_128(ui_v[5], ui_v[13]);
    ui_h_vecs[6] = xor_128(ui_v[6], ui_v[14]);
    ui_h_vecs[7] = xor_128(ui_v[7], ui_v[15]);

    uc_block_flags = uc_flags;
  }

  transpose_vecs_128(&ui_h_vecs[0]);
  transpose_vecs_128(&ui_h_vecs[4]);
  storeu_128(ui_h_vecs[0], &p_uc_out[0 * sizeof(uint32x4_t)]);
  storeu_128(ui_h_vecs[4], &p_uc_out[1 * sizeof(uint32x4_t)]);
  storeu_128(ui_h_vecs[1], &p_uc_out[2 * sizeof(uint32x4_t)]);
  storeu_128(ui_h_vecs[5], &p_uc_out[3 * sizeof(uint32x4_t)]);
  storeu_128(ui_h_vecs[2], &p_uc_out[4 * sizeof(uint32x4_t)]);
  storeu_128(ui_h_vecs[6], &p_uc_out[5 * sizeof(uint32x4_t)]);
  storeu_128(ui_h_vecs[3], &p_uc_out[6 * sizeof(uint32x4_t)]);
  storeu_128(ui_h_vecs[7], &p_uc_out[7 * sizeof(uint32x4_t)]);
}

void blake3_compress_in_place_portable(uint32_t ui_cv[8],
                                       const uint8_t uc_block[BLAKE3_BLOCK_LEN],
                                       uint8_t uc_block_len, uint64_t ul_counter,
                                       uint8_t uc_flags);

INLINE void hash_one_neon(const uint8_t *p_uc_input, size_t ul_blocks,
                          const uint32_t ui_key[8], uint64_t ul_counter,
                          uint8_t uc_flags, uint8_t uc_flags_start, uint8_t uc_flags_end,
                          uint8_t uc_out[BLAKE3_OUT_LEN]) {
  uint32_t ui_cv[8];
  memcpy(ui_cv, ui_key, BLAKE3_KEY_LEN);
  uint8_t uc_block_flags = uc_flags | uc_flags_start;
  while (ul_blocks > 0) {
    if (ul_blocks == 1) {
      uc_block_flags |= uc_flags_end;
    }
    blake3_compress_in_place_portable(ui_cv, p_uc_input, BLAKE3_BLOCK_LEN, ul_counter,
                                      uc_block_flags);
    p_uc_input = &p_uc_input[BLAKE3_BLOCK_LEN];
    ul_blocks -= 1;
    uc_block_flags = uc_flags;
  }
  memcpy(uc_out, ui_cv, BLAKE3_OUT_LEN);
}

void blake3_hash_many_neon(const uint8_t *const *p_inputs, size_t ul_num_inputs,
                           size_t ul_blocks, const uint32_t ui_key[8],
                           uint64_t ul_counter, bool b_increment_counter,
                           uint8_t uc_flags, uint8_t uc_flags_start,
                           uint8_t uc_flags_end, uint8_t *p_uc_out) {
  while (ul_num_inputs >= 4) {
    blake3_hash4_neon(p_inputs, ul_blocks, ui_key, ul_counter, b_increment_counter, uc_flags,
                      uc_flags_start, uc_flags_end, p_uc_out);
    if (b_increment_counter) {
      ul_counter += 4;
    }
    p_inputs += 4;
    ul_num_inputs -= 4;
    p_uc_out = &p_uc_out[4 * BLAKE3_OUT_LEN];
  }
  while (ul_num_inputs > 0) {
    hash_one_neon(p_inputs[0], ul_blocks, ui_key, ul_counter, uc_flags, uc_flags_start,
                  uc_flags_end, p_uc_out);
    if (b_increment_counter) {
      ul_counter += 1;
    }
    p_inputs += 1;
    ul_num_inputs -= 1;
    p_uc_out = &p_uc_out[BLAKE3_OUT_LEN];
  }
}
