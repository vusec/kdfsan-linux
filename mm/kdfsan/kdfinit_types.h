#ifndef KDFINIT_TYPES_H
#define KDFINIT_TYPES_H

#include <linux/kdfsan.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/nmi.h>
#include <linux/kallsyms.h>
#include "kdfsan_ltckpt.h"

// TODO: properly merge kdfinit/kdfsan
dfsan_label kdf_union(dfsan_label l1, dfsan_label l2); // THIS SHOULD ONLY BE CALLED IF WITHIN KDFSAN RT
int kdf_has_label(dfsan_label haver, dfsan_label havee);  // THIS SHOULD ONLY BE CALLED IF WITHIN KDFSAN RT
bool kdf_virt_addr_valid(void *addr);

#ifndef CONFIG_LTCKPT
#define KDF_PANIC_ON(cond, ...) \
do { \
  if(cond) { \
    panic(__VA_ARGS__); \
  } \
} while(0)
#else // CONFIG_LTCKPT
#define STRINGIT2(l) #l
#define STRINGIT(l) STRINGIT2(l)
#define KDF_PANIC_ON(cond, ...) \
do { \
  if(cond) { \
    ltckpt_assert_print(__FILE__, STRINGIT(__LINE__), #cond); \
  } \
} while(0)
#endif // CONFIG_LTCKPT

#endif // KDFINIT_TYPES_H
