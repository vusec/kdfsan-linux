#include "kdfinit_types.h"
#include "kdfinit_kasan_util.h"

bool kdfinit_is_init_done = false; // should be false! this is correctly initialized in kdfinit_init!
bool kdfinit_is_in_rt = false; // should be false! this is correctly initialized in kdfinit_init!
static void set_kdfinit_rt(void) { kdfinit_is_in_rt = true; } static void unset_kdfinit_rt(void) { kdfinit_is_in_rt = false; } // Check for whether kdfinit rt is being called from a function called by kdfinit rt
#define CHECK_WHITELIST(default_ret) do { if(!ltckpt_hook_is_whitelist_task()) { return default_ret; } } while(0)
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
static dfsan_label attacker_usercopy_label = -1;
static dfsan_label attacker_slab_massage_label = -1;
static dfsan_label attacker_stack_massage_label = -1;
static dfsan_label attacker_wild_lvi_label = -1;
static dfsan_label attacker_user_lvi_label = -1;
static dfsan_label secret_slab_label = -1;
static dfsan_label secret_stack_label = -1;
static dfsan_label secret_wild_label = -1;
static dfsan_label secret_user_label = -1;
static dfsan_label secret_null_label = -1;
static dfsan_label secret_global_label = -1;
static dfsan_label secret_unknown_label = -1;

// For KDFSan tests
dfsan_label kdfinit_get_usercopy_label(void) { return attacker_usercopy_label; }

// Uses strlcat defined with ltckpt static lib because it doesn't have ltckpt store hooks, and the info string needs to persist after a restart
#define NUM_STR_LEN 30
#define CONCAT_STR(S) do { ltckpt_strlcat(dest, S, count); } while(0)
#define CONCAT_NUM(X,B) do { char _tmp_num_str[NUM_STR_LEN]; __memset(_tmp_num_str,0,NUM_STR_LEN); ltckpt_itoa(X, _tmp_num_str, B); CONCAT_STR(_tmp_num_str); } while(0)
static void init_desc(u16 syscall_nr, u8 syscall_arg_nr, size_t size, u64 syscall_arg_val, char * dest, size_t count) {
  u64 this_cumulative_arg_count = cumulative_arg_count; cumulative_arg_count++;
  CONCAT_STR("total_arg_nr: "); CONCAT_NUM(this_cumulative_arg_count,10);
  CONCAT_STR(", syscall_nr: "); CONCAT_NUM(syscall_nr,10);
  CONCAT_STR(", syscall_arg_nr: "); CONCAT_NUM(syscall_arg_nr,10);
  CONCAT_STR(", size: "); CONCAT_NUM(size,10);
  CONCAT_STR(", syscall_arg_val: 0x"); CONCAT_NUM(syscall_arg_val,16);
}

void kdfinit_taint_syscall_arg(void * arg, size_t s, int arg_num) {
  ENTER_KDFINIT_RT();
  u16 syscall_nr = ltckpt_syscall_get_nr();

  u64 arg_val = 0;
  if(s == 1) { arg_val = (u64)(*(u8*)arg); }
  else if(s == 2) { arg_val = (u64)(*(u16*)arg); }
  else if(s == 4) { arg_val = (u64)(*(u32*)arg); }
  else if(s == 8) { arg_val = (u64)(*(u64*)arg); }
  else { } // TODO: panic?

  char desc[150];
  init_desc(syscall_nr, arg_num, s, arg_val, desc, sizeof(desc));
  dfsan_label label = dfsan_create_label(desc, 0);
  dfsan_add_label(label, arg, s);
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

static __always_inline bool kdfinit_label_also_has_controllable_read_label(dfsan_label label) {
  if(dfsan_has_label(label, secret_slab_label) || dfsan_has_label(label, secret_stack_label) ||
        dfsan_has_label(label, secret_wild_label) || dfsan_has_label(label, secret_user_label) ||
        dfsan_has_label(label, secret_null_label) || dfsan_has_label(label, secret_global_label) ||
        dfsan_has_label(label, secret_unknown_label)) {
    KDF_PANIC_ON(label == secret_slab_label || label == secret_stack_label || label == secret_wild_label ||
          label == secret_user_label || label == secret_null_label || label == secret_global_label || label == secret_unknown_label,
          "KDFInit error: ptr_label contains a secret label but _only_ contains that label; something is wrong (otherwise, what is it controllable by?)\n");
    return true;
  }
  return false;
}

// Called from outside kdfsan runtime lib -- so DO call kdfsan_interface functions from here
void kdfinit_access_taint_sink(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label, bool is_write) {
  ENTER_KDFINIT_RT();
  // SpectreV1 report
  if(kdfinit_label_also_has_controllable_read_label(ptr_label)) {
    ltckpt_hook_specv1_report((unsigned long) addr, size, is_write, ip, data_label, ptr_label);
  }
  // RIDL report
  else if(dfsan_has_label(ptr_label, attacker_slab_massage_label) || dfsan_has_label(ptr_label, attacker_stack_massage_label) ||
            dfsan_has_label(ptr_label, attacker_wild_lvi_label) || dfsan_has_label(ptr_label, attacker_user_lvi_label) ||
            (kdfinit_is_kasan_bug(addr, size) && ptr_label != 0)) {
    ltckpt_hook_ridl_report((unsigned long) addr, size, is_write, ip, data_label, ptr_label);
  }
  LEAVE_KDFINIT_RT();
}

// Called from within kdfsan runtime lib -- so DON'T call kdfsan_interface functions from here
dfsan_label kdfinit_load_taint_source(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label) {
  ENTER_KDFINIT_RT(0);
  dfsan_label load_label = 0;
  kdfinit_access_enum access_type = kdfinit_access_type(addr, size);

  if(kdf_has_label(ptr_label, attacker_slab_massage_label) || kdf_has_label(ptr_label, attacker_stack_massage_label) ||
        kdf_has_label(ptr_label, attacker_wild_lvi_label) || kdf_has_label(ptr_label, attacker_user_lvi_label) ||
        (kdfinit_is_kasan_bug(addr, size) && ptr_label != 0)) {
    switch (access_type) {
      case KDF_KASAN_SLAB_MEM: load_label = kdf_union(load_label, secret_slab_label); break;
      case KDF_KASAN_STACK_MEM: load_label = kdf_union(load_label, secret_stack_label); break;
      case KDF_KASAN_WILD_MEM: load_label = kdf_union(load_label, secret_wild_label); break;
      case KDF_KASAN_USER_MEM: load_label = kdf_union(load_label, secret_user_label); break;
      case KDF_KASAN_NULL_MEM: load_label = kdf_union(load_label, secret_null_label); break;
      case KDF_KASAN_GLOBAL_MEM: load_label = kdf_union(load_label, secret_global_label); break;
      default: load_label = kdf_union(load_label, secret_unknown_label); break;
    }
  }
  else if(kdfinit_is_oob_uaf_bug(addr, size) && ptr_label == 0) {
    switch (access_type) {
      case KDF_KASAN_SLAB_MEM: load_label = kdf_union(load_label, attacker_slab_massage_label); break;
      case KDF_KASAN_STACK_MEM: load_label = kdf_union(load_label, attacker_stack_massage_label); break;
      default: break;
    }
  }
  else if(kdfinit_is_wild_access(addr, size) && ptr_label == 0) {
    switch (access_type) {
      case KDF_KASAN_WILD_MEM: load_label = kdf_union(load_label, attacker_wild_lvi_label); break;
      case KDF_KASAN_USER_MEM: load_label = kdf_union(load_label, attacker_user_lvi_label); break;
      default: break;
    }
  }

  LEAVE_KDFINIT_RT();
  return load_label;
}

void kdfinit_init(void) {
  cumulative_arg_count = 0;

  // Init static labels
  attacker_usercopy_label = dfsan_create_label("attacker-usercopy", 0);
  attacker_slab_massage_label = dfsan_create_label("attacker-slab-massage", 0);
  attacker_stack_massage_label = dfsan_create_label("attacker-stack-massage", 0);
  attacker_wild_lvi_label = dfsan_create_label("attacker-wild-mem-lvi", 0);
  attacker_user_lvi_label = dfsan_create_label("attacker-user-mem-lvi", 0);
  secret_slab_label = dfsan_create_label("secret-slab-mem", 0);
  secret_stack_label = dfsan_create_label("secret-stack-mem", 0);
  secret_wild_label = dfsan_create_label("secret-wild-mem", 0);
  secret_user_label = dfsan_create_label("secret-user-mem", 0);
  secret_null_label = dfsan_create_label("secret-null-mem", 0);
  secret_global_label = dfsan_create_label("secret-global-mem", 0);
  secret_unknown_label = dfsan_create_label("secret-unknown-mem", 0);

  // Done
  kdfinit_is_in_rt = false;
  kdfinit_is_init_done = true;
}
