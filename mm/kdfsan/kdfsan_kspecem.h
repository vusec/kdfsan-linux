// SPDX-License-Identifier: GPL-2.0

#ifndef KDFSAN_KSPECEM_H
#define KDFSAN_KSPECEM_H

extern int volatile kspecem_in_speculative_emulation;

unsigned long kspecem_syscall_get_nr(void);
int kspecem_hook_is_whitelist_task(void);

void kspecem_hook_ridl_report(unsigned long addr, size_t size, bool is_write, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label);
void kspecem_hook_specv1_report(unsigned long addr, size_t size, bool is_write, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label);
void kspecem_hook_smotherspectre_report(unsigned long ip, dfsan_label label);

void kspecem_hook_memcpy(char *addr, size_t size);
void kspecem_common_late_init(void);

size_t kspecem_strlcat(char *dest, const char *src, size_t count);
char* kspecem_itoa(long long num, char* str, int base);

void kspecem_assert_print(char *file, char *line, char *condition);

#endif
