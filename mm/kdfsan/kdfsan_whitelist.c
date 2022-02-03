// SPDX-License-Identifier: GPL-2.0

#include "kdfsan_types.h"
#include "kdfsan_whitelist.h"
#include "kdfsan_util.h"

extern kdfsan_whitelist_type_t kdf_dbgfs_whitelist_type;

bool kdf_is_whitelist_task(void) {
  if (kdf_dbgfs_whitelist_type == KDFSAN_WHITELIST_DISABLED) {
    return true;
  }
  else if (kdf_dbgfs_whitelist_type == KDFSAN_WHITELIST_TASKNAME) {
    char *task_name = current->comm;
    // taskname should either:
    // (a) be exactly "kdfsan_task" (for kdfsan_tests), or
    // (b) begin with "syz-executor" (for syzkaller)
    if (kdf_util_strncmp(task_name, "kdfsan_task", TASK_COMM_LEN) == 0 ||
        kdf_util_strncmp(task_name, "syz-executor", kdf_util_strlen("syz-executor")) == 0)
      return true;
  }
  else if (kdf_dbgfs_whitelist_type == KDFSAN_WHITELIST_SYSCALLNR) {
    unsigned long syscall_nr = kdf_util_syscall_get_nr();
    // syscall number should be in the range [600, 1200)
    if (syscall_nr >= 600 && syscall_nr < 1200)
      return true;
  }
  return false;
}