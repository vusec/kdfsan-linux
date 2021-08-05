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

#define KDF_PANIC_ON(cond, ...) \
do { \
  if(cond) { \
    panic(__VA_ARGS__); \
  } \
} while(0)

#define KDF_CHECK_LABEL(lbl) KDF_PANIC_ON(lbl > kdf_get_label_count(), \
    "Found label (%d) greater than max label (%d)", lbl, kdf_get_label_count());

#endif // KDFSAN_TYPES_H
