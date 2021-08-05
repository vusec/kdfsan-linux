#ifndef KDFSAN_UTIL_H
#define KDFSAN_UTIL_H

unsigned long kdf_util_syscall_get_nr(void);
int kdf_util_hook_is_whitelist_task(void);

size_t kdf_util_strlcat(char *dest, const char *src, size_t count);
char* kdf_util_itoa(long long num, char* str, int base);

#define CONCAT_STR(SRC,DEST,COUNT) \
  do { kdf_util_strlcat(DEST, SRC, COUNT); } while(0)
#define CONCAT_NUM(NUM,BASE,DEST,COUNT) \
  do { char __tmp_num_str[32]; \
  __memset(__tmp_num_str,0,32); \
  kdf_util_itoa(NUM, __tmp_num_str, BASE); \
  CONCAT_STR(__tmp_num_str,DEST,COUNT); } while(0)

#endif