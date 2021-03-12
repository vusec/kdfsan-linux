// SPDX-License-Identifier: GPL-2.0

#ifndef KDFSAN_SHADOW_H
#define KDFSAN_SHADOW_H

#include "kdfsan_types.h"

static const uptr INTERNAL_LABEL_LOG_BIT_WIDTH = 3; // {0,1,2,3,4} <--- CHANGE THIS TO ADJUST SHADOW MEM SIZE
static const uptr INTERNAL_LABEL_BIT_WIDTH = (1 << INTERNAL_LABEL_LOG_BIT_WIDTH); // {1,2,4,8,16}
static const uptr NUM_LABELS = (1 << INTERNAL_LABEL_BIT_WIDTH); // {0x2,0x4,0x10,0x100,0x10000}
static const uptr INTERNAL_LABEL_ADDR_MASK = (INTERNAL_LABEL_LOG_BIT_WIDTH < 4) ? (1<<(3-INTERNAL_LABEL_LOG_BIT_WIDTH))-1 : 0; // {0x7,0x3,0x1,0x0,0x0}
static const uptr INTERNAL_LABEL_MASK = (NUM_LABELS - 1); // {0x1,0x3,0xf,0xff,0xffff}

dfsan_label kdf_get_shadow(const u8 *ptr);
void kdf_set_shadow(const u8 *ptr, dfsan_label label);
struct page *kdf_virt_to_page_or_null(void *vaddr);

#endif // KDFSAN_SHADOW_H
