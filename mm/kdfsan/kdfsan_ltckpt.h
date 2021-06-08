#ifndef KDFSAN_LTCKPT_H
#define KDFSAN_LTCKPT_H

unsigned long ltckpt_syscall_get_nr(void);
int ltckpt_hook_is_whitelist_task(void);

size_t ltckpt_strlcat(char *dest, const char *src, size_t count);
char* ltckpt_itoa(long long num, char* str, int base);

#endif