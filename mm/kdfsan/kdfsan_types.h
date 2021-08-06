#ifndef KDFSAN_TYPES_H
#define KDFSAN_TYPES_H

#include <linux/kdfsan.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/mm_types.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/slab_def.h>
#include <linux/nmi.h>
#include <linux/irqflags.h>
#include <linux/memblock.h>
#include <linux/uaccess.h>
#include <asm/cpu_entry_area.h>
#include "kdfsan_util.h"

static const uptr INTERNAL_LABEL_LOG_BIT_WIDTH = 3; // {0,1,2,3,4} <--- CHANGE THIS TO ADJUST SHADOW MEM SIZE
static const uptr INTERNAL_LABEL_BIT_WIDTH = (1 << INTERNAL_LABEL_LOG_BIT_WIDTH); // {1,2,4,8,16}
static const uptr NUM_LABELS = (1 << INTERNAL_LABEL_BIT_WIDTH); // {0x2,0x4,0x10,0x100,0x10000}
static const uptr INTERNAL_LABEL_ADDR_MASK = (INTERNAL_LABEL_LOG_BIT_WIDTH < 4) ? (1<<(3-INTERNAL_LABEL_LOG_BIT_WIDTH))-1 : 0; // {0x7,0x3,0x1,0x0,0x0}
static const uptr INTERNAL_LABEL_MASK = (NUM_LABELS - 1); // {0x1,0x3,0xf,0xff,0xffff}

#define KDF_PANIC_ON(cond, ...) \
do { \
  if(cond) { \
    panic(__VA_ARGS__); \
  } \
} while(0)

#define KDF_CHECK_LABEL(lbl) KDF_PANIC_ON(lbl > kdf_get_label_count(), \
    "Found label (%d) greater than max label (%d)", lbl, kdf_get_label_count());

#endif // KDFSAN_TYPES_H
