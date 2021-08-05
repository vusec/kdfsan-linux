#include "kdfsan_types.h"
#include "kdfsan_util.h"
#include "kdfsan_internal.h"

extern bool kdf_dbgfs_generic_syscall_label;

static u64 cumulative_arg_count = -1;
static dfsan_label attacker_syscall_label = -1;
static dfsan_label attacker_usercopy_label = -1;

// For KDFSan tests
dfsan_label kdfinit_get_usercopy_label(void) { return attacker_usercopy_label; }

// Taint source: syscall args
void kdf_policy_syscall_arg(void * arg, size_t s, int arg_num) {
  if (kdf_dbgfs_generic_syscall_label) {
    kdf_add_label(attacker_syscall_label, arg, s); // Not calling dfsan_add_label because we're in the run-time here
  } else {
    u16 syscall_nr = kdf_util_syscall_get_nr();

    u64 arg_val = 0;
    if(s == 1) { arg_val = (u64)(*(u8*)arg); }
    else if(s == 2) { arg_val = (u64)(*(u16*)arg); }
    else if(s == 4) { arg_val = (u64)(*(u32*)arg); }
    else if(s == 8) { arg_val = (u64)(*(u64*)arg); }
    else { } // TODO: panic?

    char desc[150] = "";
    u64 this_cumulative_arg_count = cumulative_arg_count; cumulative_arg_count++;
    CONCAT_STR("total_arg_nr: ",desc,sizeof(desc)); CONCAT_NUM(this_cumulative_arg_count,10,desc,sizeof(desc));
    CONCAT_STR(", syscall_nr: ",desc,sizeof(desc)); CONCAT_NUM(syscall_nr,10,desc,sizeof(desc));
    CONCAT_STR(", syscall_arg_nr: ",desc,sizeof(desc)); CONCAT_NUM(arg_num,10,desc,sizeof(desc));
    CONCAT_STR(", size: ",desc,sizeof(desc)); CONCAT_NUM(s,10,desc,sizeof(desc));
    CONCAT_STR(", syscall_arg_val: 0x",desc,sizeof(desc)); CONCAT_NUM(arg_val,16,desc,sizeof(desc));

    dfsan_label label = kdf_create_label(desc); // Not calling dfsan_create_label because we're in the run-time here
    kdf_add_label(label, arg, s); // Not calling dfsan_add_label because we're in the run-time here
  }
}

// Taint source: usercopies
void kdf_policy_usercopy(void * dst, size_t s, dfsan_label src_ptr_label) {
  // Propagate both the src_ptr's label and the usercopy label to the dst
  dfsan_label unioned_label = kdf_union(attacker_usercopy_label, src_ptr_label); // Not calling dfsan_union because we're in the run-time here
  kdf_add_label(unioned_label, dst, s); // Not calling dfsan_add_label because we're in the run-time here
}

void kdfinit_init(void) {
  cumulative_arg_count = 0;
  attacker_usercopy_label = dfsan_create_label("attacker-usercopy", 0);
  if (kdf_dbgfs_generic_syscall_label) attacker_syscall_label = dfsan_create_label("attacker-syscall-arg", 0);
}
