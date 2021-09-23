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

void *__dfsw_memset16(uint16_t *s, uint16_t v, size_t count,
                    dfsan_label s_label, dfsan_label v_label,
                    dfsan_label count_label, dfsan_label *ret_label) {
  void * ret_val = memset16(s, v, count);
  *ret_label = s_label;
  dfsan_set_label(v_label, s, count * sizeof(uint16_t));
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

void *__dfsw_memset64(uint64_t *s, uint64_t v, size_t count,
                    dfsan_label s_label, dfsan_label v_label,
                    dfsan_label count_label, dfsan_label *ret_label) {
  void * ret_val = memset64(s, v, count);
  *ret_label = s_label;
  dfsan_set_label(v_label, s, count * sizeof(uint64_t));
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

/* TODO:
char *strcpy(char *dest, const char *src);
size_t strlcat(char *dest, const char *src, size_t count);
size_t strlcpy(char *dest, const char *src, size_t size);
char *strnchr(const char *s, size_t count, int c);
char *strreplace(char *s, char old, char new);
char *strsep(char **s, const char *ct);
char *strstr(const char *s1, const char *s2);
*/