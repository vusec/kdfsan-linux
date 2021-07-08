#ifndef KDFINIT_TYPES_H
#define KDFINIT_TYPES_H

#include <linux/kdfsan.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/nmi.h>
#include <linux/kallsyms.h>
#include "kdfsan_util.h"

extern bool kdf_dbgfs_generic_syscall_label;

// TODO: properly merge kdfinit/kdfsan
dfsan_label kdf_union(dfsan_label l1, dfsan_label l2); // THIS SHOULD ONLY BE CALLED IF WITHIN KDFSAN RT
int kdf_has_label(dfsan_label haver, dfsan_label havee);  // THIS SHOULD ONLY BE CALLED IF WITHIN KDFSAN RT
bool kdf_virt_addr_valid(void *addr);

#define KDF_PANIC_ON(cond, ...) \
do { \
  if(cond) { \
    panic(__VA_ARGS__); \
  } \
} while(0)

#endif // KDFINIT_TYPES_H
