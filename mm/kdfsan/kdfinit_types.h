// SPDX-License-Identifier: GPL-2.0

#ifndef KDFINIT_TYPES_H
#define KDFINIT_TYPES_H

#include <linux/kdfsan.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/memory.h>
#include <linux/nmi.h>
#include <linux/kallsyms.h>
#include "kdfsan_kspecem.h"

extern u8 kdf_dbgfs_syscall_label_type;
extern bool kdf_dbgfs_run_specfuzz_policies;
extern bool kdf_dbgfs_run_spectaint_policies;
extern bool kdf_dbgfs_report_only_pht_syscall_cc;
extern bool report_smotherspectre;

// TODO: properly merge kdfinit/kdfsan
dfsan_label kdf_union(dfsan_label l1, dfsan_label l2); // THIS SHOULD ONLY BE CALLED IF WITHIN KDFSAN RT
int kdf_has_label(dfsan_label haver, dfsan_label havee);  // THIS SHOULD ONLY BE CALLED IF WITHIN KDFSAN RT
bool kdf_virt_addr_valid(void *addr);

#ifndef CONFIG_KSPECEM
#define KDF_PANIC_ON(cond, ...) \
do { \
  if(cond) { \
    panic(__VA_ARGS__); \
  } \
} while(0)
#else // CONFIG_KSPECEM
#define STRINGIT2(l) #l
#define STRINGIT(l) STRINGIT2(l)
#define KDF_PANIC_ON(cond, ...) \
do { \
  if(cond) { \
    kspecem_assert_print(__FILE__, STRINGIT(__LINE__), #cond); \
  } \
} while(0)
#endif // CONFIG_KSPECEM

#endif // KDFINIT_TYPES_H
