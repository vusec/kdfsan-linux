// SPDX-License-Identifier: GPL-2.0

#ifndef KDFSAN_SHADOW_H
#define KDFSAN_SHADOW_H

#include "kdfsan_types.h"

struct page *kdf_virt_to_page_or_null(void *vaddr);
dfsan_label kdf_get_shadow(const u8 *ptr);
void kdf_set_shadow(const u8 *ptr, dfsan_label label);

#endif // KDFSAN_SHADOW_H
