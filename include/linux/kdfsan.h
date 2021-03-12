// SPDX-License-Identifier: GPL-2.0

#ifndef LINUX_KDFSAN_H
#define LINUX_KDFSAN_H

#include <linux/types.h>
#include <linux/init.h>

typedef enum {
  KDF_SYSCALL_LABEL_DEFAULT = 0,
  KDF_SYSCALL_LABEL_SIMPLIFIED,
  KDF_SYSCALL_LABEL_GENERIC
} kdfsan_syscall_label_type_enum;

struct page;
typedef unsigned long uptr;
typedef u16 dfsan_label;

#ifdef CONFIG_KDFSAN
int kdfsan_alloc_page(struct page *page, unsigned int order, gfp_t flags, int node);
void kdfsan_free_page(struct page *page, unsigned int order);
void kdfsan_split_page(struct page *page, unsigned int order);
void __init kdfsan_init_shadow(void);
void dfsan_mem_transfer_callback(void *dest, const void *src, uptr size);
void dfsan_set_label(dfsan_label label, void *addr, uptr size);
void dfsan_add_label(dfsan_label label_src, void *addr, uptr size);
dfsan_label dfsan_create_label(const char *desc, void *userdata);
int dfsan_has_label(dfsan_label label, dfsan_label elem);
dfsan_label dfsan_has_label_with_desc(dfsan_label label, const char *desc);
dfsan_label dfsan_get_label_count(void);
dfsan_label dfsan_read_label(const void *addr, uptr size);
dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2);
dfsan_label dfsan_get_label(long data);
void kdfinit_taint_syscall_arg(void * arg, size_t s, int arg_num);
void kdfinit_taint_usercopy(void * dst, size_t s, dfsan_label src_ptr_label);
#else
static inline int kdfsan_alloc_page(struct page *page, unsigned int order, gfp_t flags, int node) { return 0; }
static inline void kdfsan_free_page(struct page *page, unsigned int order) { }
static inline void kdfsan_split_page(struct page *page, unsigned int order) { }
static inline void __init kdfsan_init_shadow(void) { }
static inline void dfsan_mem_transfer_callback(void *dest, const void *src, uptr size) { }
static inline void dfsan_set_label(dfsan_label label, void *addr, uptr size) { }
static inline void dfsan_add_label(dfsan_label label_src, void *addr, uptr size) { }
static inline dfsan_label dfsan_create_label(const char *desc, void *userdata) { return 0; }
static inline int dfsan_has_label(dfsan_label label, dfsan_label elem) { return 0; }
static inline dfsan_label dfsan_has_label_with_desc(dfsan_label label, const char *desc) { return 0; }
static inline dfsan_label dfsan_get_label_count(void) { return 0; }
static inline dfsan_label dfsan_read_label(const void *addr, uptr size) { return 0; }
static inline dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2) { return 0; }
static inline dfsan_label dfsan_get_label(long data) { return 0; }
static inline void kdfinit_taint_syscall_arg(void * arg, size_t s, int arg_num) { }
static inline void kdfinit_taint_usercopy(void * dst, size_t s, dfsan_label src_ptr_label) { }
#endif

#endif /* LINUX_KDFSAN_H */
