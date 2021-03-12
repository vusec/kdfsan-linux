#ifndef KDFSAN_LTCKPT_H
#define KDFSAN_LTCKPT_H

unsigned long ltckpt_syscall_get_nr(void);
int ltckpt_hook_is_whitelist_task(void);

void ltckpt_hook_ridl_report(unsigned long addr, size_t size, bool is_write, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label);
void ltckpt_hook_specv1_report(unsigned long addr, size_t size, bool is_write, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label);

void ltckpt_hook_memcpy(char *addr, size_t size);
void ltckpt_common_late_init(void);

size_t ltckpt_strlcat(char *dest, const char *src, size_t count);
char* ltckpt_itoa(long long num, char* str, int base);

void ltckpt_assert_print(char *file, char *line, char *condition);

#endif