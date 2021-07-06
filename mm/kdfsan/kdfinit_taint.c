// SPDX-License-Identifier: GPL-2.0

#include "kdfinit_types.h"
#include "kdfinit_kasan_util.h"

bool kdfinit_is_init_done = -1; // should be false! this is correctly initialized in kdfinit_init!
bool kdfinit_is_in_rt = -1; // should be false! this is correctly initialized in kdfinit_init!
static void set_kdfinit_rt(void) { kdfinit_is_in_rt = true; } static void unset_kdfinit_rt(void) { kdfinit_is_in_rt = false; } // Check for whether kdfinit rt is being called from a function called by kdfinit rt
#define CHECK_WHITELIST(default_ret) do { if(!kspecem_hook_is_whitelist_task()) { return default_ret; } } while(0)
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
static dfsan_label attacker_slab_massage_label = -1;
static dfsan_label attacker_stack_massage_label = -1;
static dfsan_label attacker_wild_lvi_label = -1;
static dfsan_label attacker_user_lvi_label = -1;
static dfsan_label attacker_unknown_lvi_label = -1;
static dfsan_label secret_slab_label = -1;
static dfsan_label secret_stack_label = -1;
static dfsan_label secret_wild_label = -1;
static dfsan_label secret_user_label = -1;
static dfsan_label secret_null_label = -1;
static dfsan_label secret_global_label = -1;
static dfsan_label secret_unknown_label = -1;
static dfsan_label secret_safe_label = -1;

/***************/
/**** Utils ****/

static dfsan_label kdfinit_util_get_secret_type(kdfinit_access_enum access_type) {
  switch (access_type) {
    case KDF_KASAN_SLAB_MEM: return secret_slab_label;
    case KDF_KASAN_STACK_MEM: return secret_stack_label;
    case KDF_KASAN_WILD_MEM: return secret_wild_label;
    case KDF_KASAN_USER_MEM: return secret_user_label;
    case KDF_KASAN_NULL_MEM: return secret_null_label;
    case KDF_KASAN_GLOBAL_MEM: return secret_global_label;
    default: break;
  }
  return secret_unknown_label;
}

static dfsan_label kdfinit_util_get_massage_type(kdfinit_access_enum access_type) {
  switch (access_type) {
    case KDF_KASAN_SLAB_MEM: return attacker_slab_massage_label;
    case KDF_KASAN_STACK_MEM: return attacker_stack_massage_label;
    default: break;
  }
  return 0; // TODO! Add an attacker_unknown_massage_label???
}


static dfsan_label kdfinit_util_get_lvi_type(kdfinit_access_enum access_type) {
  switch (access_type) {
    case KDF_KASAN_WILD_MEM: return attacker_wild_lvi_label;
    case KDF_KASAN_USER_MEM: return attacker_user_lvi_label;
    default: break;
  }
  return attacker_unknown_lvi_label;
}

static bool kdfinit_util_has_secret_label(dfsan_label label) {
  if(dfsan_has_label(label, secret_slab_label) || dfsan_has_label(label, secret_stack_label) ||
        dfsan_has_label(label, secret_wild_label) || dfsan_has_label(label, secret_user_label) ||
        dfsan_has_label(label, secret_null_label) || dfsan_has_label(label, secret_global_label) ||
        dfsan_has_label(label, secret_unknown_label)) {
    KDF_PANIC_ON(label == secret_slab_label || label == secret_stack_label || label == secret_wild_label ||
          label == secret_user_label || label == secret_null_label || label == secret_global_label || label == secret_unknown_label,
          "KDFInit error: ptr_label contains a secret label but _only_ contains that label; something is wrong (it should at least contain another attacker label)\n");
    return true;
  }
  return false;
}

static bool kdfinit_util_has_attacker_massage_label(dfsan_label label) {
  return dfsan_has_label(label, attacker_slab_massage_label) || dfsan_has_label(label, attacker_stack_massage_label);
}

static bool kdfinit_util_has_attacker_lvi_label(dfsan_label label) {
 return dfsan_has_label(label, attacker_wild_lvi_label) || dfsan_has_label(label, attacker_user_lvi_label) || dfsan_has_label(label, attacker_unknown_lvi_label);
}

// For KDFSan tests
dfsan_label kdfinit_get_usercopy_label(void) { return attacker_usercopy_label; }

// Uses strlcat defined with kspecem static lib because it doesn't have kspecem store hooks, and the info string needs to persist after a restart
#define NUM_STR_LEN 30
#define CONCAT_STR(S) do { kspecem_strlcat(dest, S, count); } while(0)
#define CONCAT_NUM(X,B) do { char _tmp_num_str[NUM_STR_LEN]; __memset(_tmp_num_str,0,NUM_STR_LEN); kspecem_itoa(X, _tmp_num_str, B); CONCAT_STR(_tmp_num_str); } while(0)
static void init_desc(u16 syscall_nr, u8 syscall_arg_nr, size_t size, u64 syscall_arg_val, char * dest, size_t count) {
  u64 this_cumulative_arg_count = cumulative_arg_count; cumulative_arg_count++;
  CONCAT_STR("total_arg_nr: "); CONCAT_NUM(this_cumulative_arg_count,10);
  CONCAT_STR(", syscall_nr: "); CONCAT_NUM(syscall_nr,10);
  CONCAT_STR(", syscall_arg_nr: "); CONCAT_NUM(syscall_arg_nr,10);
  CONCAT_STR(", size: "); CONCAT_NUM(size,10);
  CONCAT_STR(", syscall_arg_val: 0x"); CONCAT_NUM(syscall_arg_val,16);
}

/********************************************/
/**** Taint sources: syscalls/usercopies ****/

// 1000 (syscall_nr) and 10 (arg_nr) are chosen large enough to be safe
dfsan_label syscall_labels[1000][10];

void kdfinit_taint_syscall_arg(void * arg, size_t s, int arg_num) {
  ENTER_KDFINIT_RT();
  if (kdf_dbgfs_syscall_label_type == KDF_SYSCALL_LABEL_GENERIC) {
    dfsan_add_label(attacker_syscall_label, arg, s);
  } else if (kdf_dbgfs_syscall_label_type == KDF_SYSCALL_LABEL_SIMPLIFIED) {
    u16 syscall_nr = kspecem_syscall_get_nr();

    if (syscall_labels[syscall_nr][arg_num] == 0) {
      char desc[150] = "";
      /* total_arg_nr and syscall_arg_val will be invalid */
      init_desc(syscall_nr, arg_num, s, 0, desc, sizeof(desc));
      syscall_labels[syscall_nr][arg_num] = dfsan_create_label(desc, 0);
    }
    dfsan_add_label(syscall_labels[syscall_nr][arg_num], arg, s);
  } else if (kdf_dbgfs_syscall_label_type == KDF_SYSCALL_LABEL_DEFAULT) {
    u16 syscall_nr = kspecem_syscall_get_nr();

    u64 arg_val = 0;
    if(s == 1) { arg_val = (u64)(*(u8*)arg); }
    else if(s == 2) { arg_val = (u64)(*(u16*)arg); }
    else if(s == 4) { arg_val = (u64)(*(u32*)arg); }
    else if(s == 8) { arg_val = (u64)(*(u64*)arg); }
    else { } // TODO: panic?

    char desc[150] = "";
    init_desc(syscall_nr, arg_num, s, arg_val, desc, sizeof(desc));
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

/******************************/
/* Taint policies:
(1) Kasper (default)
  - Sources: SYSCALL, LVI, MASSAGING, "attacker-->secret" policies
  - Sinks: MDS, CC
(2) Kasper restricted to PHT-SYSCALL-CC (kdf_dbgfs_report_only_pht_syscall_cc)
  - Sources: only SYSCALL and "attacker-->secret" policies
  - Sinks: MDS (no LVI/MASSAGING), CC
(3) SpecTaint (kdf_dbgfs_run_spectaint_policies)
  - Sources: only SYSCALL policy and modified "attacker-->secret" policy (so that label is promoted for _every_ access within spec exec)
  - Sinks: MDS (for *all* attacker-tainted accesses *in spec exec*), CC
(4) SpecFuzz (kdf_dbgfs_run_specfuzz_policies)
  - Sources: none
  - Sinks: MDS (if OOB)
** TODO: When calculating FPs for SpecFuzz's 'accesses', compare against Kasper-PHT-SYSCALL-CC's 'accesses' PLUS 'leaks' because all
'leaks' which Kasper reports could be counted as 'accesses' (but Kasper conservatively only reports them as 'leaks').
*/

/******************************/
/**** Taint sources: loads ****/

static dfsan_label kdfinit_load_source_default(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label) {
  kdfinit_access_enum access_type = kdfinit_access_type(addr, size);
  // 'Attacker' label --> 'secret' label
  if(kdfinit_util_has_attacker_massage_label(ptr_label) || kdfinit_util_has_attacker_lvi_label(ptr_label) ||
        (kdfinit_is_kasan_bug(addr, size) && ptr_label != 0 && !kdfinit_is_nullmem_access(addr))) {
    return kdfinit_util_get_secret_type(access_type);
  }
  // Memory-massaging
  else if(kdfinit_is_oob_uaf_bug(addr, size) && ptr_label == 0) {
    return kdfinit_util_get_massage_type(access_type);
  }
  // LVI
  else if(kdfinit_is_wild_bug(addr, size) && ptr_label == 0 && !kdfinit_is_nullmem_access(addr)) {
    return kdfinit_util_get_lvi_type(access_type);
  }
  return 0;
}

static dfsan_label kdfinit_load_source_kaspersyscallcc(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label) {
  kdfinit_access_enum access_type = kdfinit_access_type(addr, size);
  // 'Attacker' label --> 'secret' label
  if(kdfinit_is_kasan_bug(addr, size) && ptr_label != 0 && !kdfinit_is_nullmem_access(addr)) {
    return kdfinit_util_get_secret_type(access_type);
  }
  return 0;
}

static dfsan_label kdfinit_load_source_spectaint(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label) {
  kdfinit_access_enum access_type = kdfinit_access_type(addr, size);
  // 'Attacker' label --> 'secret' label
  if(ptr_label != 0 && kspecem_in_speculative_emulation) {
    if(kdfinit_is_kasan_bug(addr, size) && !kdfinit_is_nullmem_access(addr)) return kdfinit_util_get_secret_type(access_type); // If _unsafe_ access, apply correct 'secret-*' label
    else return secret_safe_label;// If _safe_ (i.e., in-bounds) access, apply 'secret-safe' label
  }
  return 0;
}

// Use same taint sources as Kasper so that we can evaluate how many of its FPs are due to the "leak" instruction not dereferencing a 'secret'
static dfsan_label kdfinit_load_source_specfuzz(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label) {
  kdfinit_access_enum access_type = kdfinit_access_type(addr, size);
  // 'Attacker' label --> 'secret' label
  if(kdfinit_is_kasan_bug(addr, size) && ptr_label != 0 && !kdfinit_is_nullmem_access(addr)) {
    return kdfinit_util_get_secret_type(access_type);
  }
  return 0;
}

// Called from within kdfsan runtime lib -- so DON'T call kdfsan_interface functions from here
dfsan_label kdfinit_load_taint_source(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label) {
  ENTER_KDFINIT_RT(0);
  dfsan_label policy_label = 0;
  if (kdf_dbgfs_report_only_pht_syscall_cc) policy_label = kdfinit_load_source_kaspersyscallcc(addr, size, ip, data_label, ptr_label);
  else if (kdf_dbgfs_run_spectaint_policies) policy_label = kdfinit_load_source_spectaint(addr, size, ip, data_label, ptr_label);
  else if (kdf_dbgfs_run_specfuzz_policies) policy_label = kdfinit_load_source_specfuzz(addr, size, ip, data_label, ptr_label);
  else policy_label = kdfinit_load_source_default(addr, size, ip, data_label, ptr_label);
  LEAVE_KDFINIT_RT();
  return policy_label;
}

/*******************************/
/**** Taint sinks: accesses ****/

static void kdfinit_access_sink_default(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label, bool is_write) {
  // CC report
  if(kdfinit_util_has_secret_label(ptr_label)) {
    kspecem_hook_specv1_report((unsigned long) addr, size, is_write, ip, data_label, ptr_label);
  }
  // MDS report
  else if(kdfinit_util_has_attacker_massage_label(ptr_label) || kdfinit_util_has_attacker_lvi_label(ptr_label) ||
            (kdfinit_is_kasan_bug(addr, size) && ptr_label != 0 && !kdfinit_is_nullmem_access(addr))) {
    kspecem_hook_ridl_report((unsigned long) addr, size, is_write, ip, data_label, ptr_label);
  }
}

static void kdfinit_access_sink_kaspersyscallcc(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label, bool is_write) {
  // CC report
  if(kdfinit_util_has_secret_label(ptr_label)) {
    kspecem_hook_specv1_report((unsigned long) addr, size, is_write, ip, data_label, ptr_label);
  }
  // MDS report (no LVI/MASSAGING)
  else if(kdfinit_is_kasan_bug(addr, size) && ptr_label != 0 && !kdfinit_is_nullmem_access(addr)) {
    kspecem_hook_ridl_report((unsigned long) addr, size, is_write, ip, data_label, ptr_label);
  }
}

static void kdfinit_access_sink_spectaint(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label, bool is_write) {
  // CC report
  if(kdfinit_util_has_secret_label(ptr_label) || dfsan_has_label(ptr_label, secret_safe_label)) {
    kspecem_hook_specv1_report((unsigned long) addr, size, is_write, ip, data_label, ptr_label);
  }
}

static void kdfinit_access_sink_specfuzz(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label, bool is_write) {
  // CC report (if OOB)
  if(kdfinit_is_kasan_bug(addr, size)) {
    kspecem_hook_specv1_report((unsigned long) addr, size, is_write, ip, data_label, ptr_label);
  }
}

// Called from outside kdfsan runtime lib -- so DO call kdfsan_interface functions from here
void kdfinit_access_taint_sink(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label, bool is_write) {
  ENTER_KDFINIT_RT();
  if (kdf_dbgfs_report_only_pht_syscall_cc) kdfinit_access_sink_kaspersyscallcc(addr, size, ip, data_label, ptr_label, is_write);
  else if (kdf_dbgfs_run_spectaint_policies) kdfinit_access_sink_spectaint(addr, size, ip, data_label, ptr_label, is_write);
  else if (kdf_dbgfs_run_specfuzz_policies) kdfinit_access_sink_specfuzz(addr, size, ip, data_label, ptr_label, is_write);
  else kdfinit_access_sink_default(addr, size, ip, data_label, ptr_label, is_write);
  LEAVE_KDFINIT_RT();
}

/*******************************/
/**** Taint sinks: branches ****/

// Called from outside kdfsan runtime lib -- so DO call kdfsan_interface functions from here
void kdfinit_branch_sink(unsigned long ip, dfsan_label label) {
  if(label == 0 || !report_smotherspectre) return;
  ENTER_KDFINIT_RT();
  if(kdfinit_util_has_secret_label(label)) {
    kspecem_hook_smotherspectre_report(ip, label);
  }
  LEAVE_KDFINIT_RT();
}

/**************/
/**** Init ****/

void kdfinit_init(void) {
  cumulative_arg_count = 0;

  for (int i = 0; i < 1000; i++)
    __memset(syscall_labels[i], 0, 10*sizeof(dfsan_label));

  // Init static labels
  attacker_usercopy_label = dfsan_create_label("attacker-usercopy", 0);
  attacker_slab_massage_label = dfsan_create_label("attacker-slab-massage", 0);
  attacker_stack_massage_label = dfsan_create_label("attacker-stack-massage", 0);
  attacker_wild_lvi_label = dfsan_create_label("attacker-wild-mem-lvi", 0);
  attacker_user_lvi_label = dfsan_create_label("attacker-user-mem-lvi", 0);
  attacker_unknown_lvi_label = dfsan_create_label("attacker-unknown-mem-lvi", 0);
  secret_slab_label = dfsan_create_label("secret-slab-mem", 0);
  secret_stack_label = dfsan_create_label("secret-stack-mem", 0);
  secret_wild_label = dfsan_create_label("secret-wild-mem", 0);
  secret_user_label = dfsan_create_label("secret-user-mem", 0);
  secret_null_label = dfsan_create_label("secret-null-mem", 0);
  secret_global_label = dfsan_create_label("secret-global-mem", 0);
  secret_unknown_label = dfsan_create_label("secret-unknown-mem", 0);
  secret_safe_label = dfsan_create_label("secret-safe", 0); // Only used by SpecTaint policies to check its FPs

  if (kdf_dbgfs_syscall_label_type == KDF_SYSCALL_LABEL_GENERIC)
    attacker_syscall_label = dfsan_create_label("attacker-syscall-arg", 0);

  // Done
  kdfinit_is_in_rt = false;
  kdfinit_is_init_done = true;
}
