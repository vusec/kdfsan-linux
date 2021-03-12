// SPDX-License-Identifier: GPL-2.0

#include "kdfsan_types.h"
#include "kdfsan_interface.h"

void *__dfsw___memcpy(void *dest, const void *src, size_t n,
                    dfsan_label dest_label, dfsan_label src_label,
                    dfsan_label n_label, dfsan_label *ret_label) {
  kspecem_hook_memcpy(dest, n);
  void * ret_val = __memcpy(dest, src, n);
  *ret_label = dest_label;
  dfsan_mem_transfer_callback(dest, src, n);
  return ret_val;
}

void *__dfsw___memset(void *ptr, int val, size_t n,
                    dfsan_label ptr_label, dfsan_label val_label,
                    dfsan_label n_label, dfsan_label *ret_label) {
  kspecem_hook_memcpy(ptr, n);
  void * ret_val = __memset(ptr, val, n);
  *ret_label = ptr_label;
  dfsan_set_label(val_label, ptr, n);
  return ret_val;
}

void *__dfsw___memmove(void *dest, const void *src, size_t n,
                    dfsan_label dest_label, dfsan_label src_label,
                    dfsan_label n_label, dfsan_label *ret_label) {
  kspecem_hook_memcpy(dest, n);
  void * ret_val = __memmove(dest, src, n);
  *ret_label = dest_label;
  dfsan_mem_transfer_callback(dest, src, n);
  return ret_val;
}
