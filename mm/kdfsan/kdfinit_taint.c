#include "kdfinit_types.h"
#include "kdfinit_kasan_util.h"

bool kdfinit_is_init_done = -1; // should be false! this is correctly initialized in kdfinit_init!
bool kdfinit_is_in_rt = -1; // should be false! this is correctly initialized in kdfinit_init!
static void set_kdfinit_rt(void) { kdfinit_is_in_rt = true; } static void unset_kdfinit_rt(void) { kdfinit_is_in_rt = false; } // Check for whether kdfinit rt is being called from a function called by kdfinit rt
#define CHECK_WHITELIST(default_ret) do { if(!kdf_util_hook_is_whitelist_task()) { return default_ret; } } while(0)
#define CHECK_KDFINIT_RT(default_ret) do { if(!kdfinit_is_init_done || kdfinit_is_in_rt) { return default_ret; } } while(0)
#define ENTER_KDFINIT_RT(default_ret) \
    unsigned long __irq_flags; \
    do { \
        CHECK_KDFINIT_RT(default_ret); \
        CHECK_WHITELIST(default_ret); \
        set_kdfinit_rt(); \
        preempt_disable(); \
        local_irq_save(__irq_flags); \
        stop_nmi(); \
    } while(0)
#define ENTER_KDFINIT_RT_NO_WHITELISTING(default_ret) \
    unsigned long __irq_flags; \
    do { \
        CHECK_KDFINIT_RT(default_ret); \
        set_kdfinit_rt(); \
        preempt_disable(); \
        local_irq_save(__irq_flags); \
        stop_nmi(); \
    } while(0)
#define LEAVE_KDFINIT_RT() \
    do { \
        KDF_PANIC_ON(!irqs_disabled(), "KDFInit error! IRQs should be disabled within the runtime!"); \
        restart_nmi(); \
        local_irq_restore(__irq_flags); \
        preempt_enable(); \
        unset_kdfinit_rt(); \
    } while(0)

static u64 cumulative_arg_count = -1;
static dfsan_label attacker_syscall_label = -1;
static dfsan_label attacker_usercopy_label = -1;

// For KDFSan tests
dfsan_label kdfinit_get_usercopy_label(void) { return attacker_usercopy_label; }

/********************************************/
/**** Taint sources: syscalls/usercopies ****/

void kdfinit_taint_syscall_arg(void * arg, size_t s, int arg_num) {
  ENTER_KDFINIT_RT();
  if (kdf_dbgfs_generic_syscall_label) {
    dfsan_add_label(attacker_syscall_label, arg, s);
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

    dfsan_label label = dfsan_create_label(desc, 0);
    dfsan_add_label(label, arg, s);
  }
  LEAVE_KDFINIT_RT();
}

// Called from hooks inserted by kernel patch
void kdfinit_taint_usercopy(void * dst, size_t s, dfsan_label src_ptr_label) {
  ENTER_KDFINIT_RT();
  // Propagate both the src_ptr's label and the usercopy label to the dst
  dfsan_label unioned_label = dfsan_union(attacker_usercopy_label, src_ptr_label);
  dfsan_add_label(unioned_label, dst, s);
  LEAVE_KDFINIT_RT();
}

/**************/
/**** Init ****/

void kdfinit_init(void) {
  cumulative_arg_count = 0;

  // Init static labels
  attacker_usercopy_label = dfsan_create_label("attacker-usercopy", 0);

  if (kdf_dbgfs_generic_syscall_label) attacker_syscall_label = dfsan_create_label("attacker-syscall-arg", 0);

  // Done
  kdfinit_is_in_rt = false;
  kdfinit_is_init_done = true;
}
