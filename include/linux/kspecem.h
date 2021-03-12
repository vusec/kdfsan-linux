// SPDX-License-Identifier: GPL-2.0

#ifndef LINUX_KSPECEM_H
#define LINUX_KSPECEM_H

#include <linux/types.h>

#ifdef CONFIG_KSPECEM
#define KSPECEM_NO_RESTART "\n#KSPECEM_NO_RESTART\n"
// weak definitions in mm/kspecem/kspecem.c; real definitions out-of-tree
void kspecem_hook_store(void *addr);
void kspecem_hook_memcpy(char *addr, size_t size);
void kspecem_hook_panic_info(void);
bool kspecem_hook_kasan_report(unsigned long addr, size_t size,
    bool is_write, unsigned long ip);
void kspecem_hook_check_spec_length(unsigned int bb_inst_count);
int kspecem_init(void);
#else
#define KSPECEM_NO_RESTART ""
static inline void kspecem_hook_store(void *addr) { }
static inline void kspecem_hook_memcpy(char *addr, size_t size) { }
static inline void kspecem_hook_panic_info(void) { }
static inline void  kspecem_hook_kasan_report(unsigned long addr, size_t size,
    bool is_write, unsigned long ip) { }
static inline int kspecem_init(void) { return 0; }
#endif

#endif /* LINUX_KSPECEM_H */
