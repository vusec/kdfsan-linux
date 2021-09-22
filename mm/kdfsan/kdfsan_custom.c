#include "kdfsan_types.h"

void *__dfsw___memcpy(void *dest, const void *src, size_t n,
                    dfsan_label dest_label, dfsan_label src_label,
                    dfsan_label n_label, dfsan_label *ret_label) {
  void * ret_val = __memcpy(dest, src, n);
  *ret_label = dest_label;
  dfsan_mem_transfer_callback(dest, src, n);
  return ret_val;
}

void *__dfsw_memcpy(void *dest, const void *src, size_t n,
                    dfsan_label dest_label, dfsan_label src_label,
                    dfsan_label n_label, dfsan_label *ret_label) {
  void * ret_val = memcpy(dest, src, n);
  *ret_label = dest_label;
  dfsan_mem_transfer_callback(dest, src, n);
  return ret_val;
}

void *__dfsw___memset(void *ptr, int val, size_t n,
                    dfsan_label ptr_label, dfsan_label val_label,
                    dfsan_label n_label, dfsan_label *ret_label) {
  void * ret_val = __memset(ptr, val, n);
  *ret_label = ptr_label;
  dfsan_set_label(val_label, ptr, n);
  return ret_val;
}

void *__dfsw_memset(void *ptr, int val, size_t n,
                    dfsan_label ptr_label, dfsan_label val_label,
                    dfsan_label n_label, dfsan_label *ret_label) {
  void * ret_val = memset(ptr, val, n);
  *ret_label = ptr_label;
  dfsan_set_label(val_label, ptr, n);
  return ret_val;
}

void *__dfsw_memset32(uint32_t *s, uint32_t v, size_t count,
                    dfsan_label s_label, dfsan_label v_label,
                    dfsan_label count_label, dfsan_label *ret_label) {
  void * ret_val = memset32(s, v, count);
  *ret_label = s_label;
  dfsan_set_label(v_label, s, count * sizeof(uint32_t));
  return ret_val;
}

void *__dfsw___memmove(void *dest, const void *src, size_t n,
                    dfsan_label dest_label, dfsan_label src_label,
                    dfsan_label n_label, dfsan_label *ret_label) {
  void * ret_val = __memmove(dest, src, n);
  *ret_label = dest_label;
  dfsan_mem_transfer_callback(dest, src, n);
  return ret_val;
}
