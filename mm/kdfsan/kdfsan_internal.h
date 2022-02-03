// SPDX-License-Identifier: GPL-2.0

#ifndef KDFSAN_INTERNAL_H
#define KDFSAN_INTERNAL_H

#include "kdfsan_types.h"

void kdf_memtransfer(void *dest, const void *src, uptr count);
void kdf_set_label(dfsan_label label, void *addr, uptr size);
dfsan_label kdf_union(dfsan_label l1, dfsan_label l2);
dfsan_label kdf_union_read_label(const void *addr, uptr n);
void kdf_add_label(dfsan_label label_src, void *addr, uptr size);
dfsan_label kdf_create_label(const char *desc); // userdata decprecated
int kdf_has_label(dfsan_label label, dfsan_label elem);
dfsan_label kdf_has_label_with_desc(dfsan_label label, const char *desc);
dfsan_label kdf_read_label(const void *addr, uptr size);
dfsan_label kdf_union(dfsan_label l1, dfsan_label l2);
void kdf_print_label_info(dfsan_label lbl, const bool line_cont);
void kdf_copy_label_info(dfsan_label label, char * dest, size_t count);
void kdf_init_internal_data(void);

#endif // KDFSAN_INTERNAL_H
