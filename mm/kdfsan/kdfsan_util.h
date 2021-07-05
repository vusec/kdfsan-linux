#ifndef KDFSAN_UTIL_H
#define KDFSAN_UTIL_H

unsigned long kdf_util_syscall_get_nr(void);
int kdf_util_hook_is_whitelist_task(void);

size_t kdf_util_strlcat(char *dest, const char *src, size_t count);
char* kdf_util_itoa(long long num, char* str, int base);

#endif