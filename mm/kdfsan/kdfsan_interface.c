#include "kdfsan_types.h"
#include "kdfsan_internal.h"
#include "kdfsan_mm.h"
#include "kdfsan_policies.h"

/************************************************************/
/********************** Interface data **********************/

dfsan_label __dfsan_arg_tls[64] = { -1 }; // should be { 0 }! this is correctly initialized elsewhere!
dfsan_label __dfsan_retval_tls = -1; // should be 0! this is correctly initialized elsewhere!
static bool kdf_is_init_done = -1; // should be false! this is correctly initialized elsewhere!
static bool kdf_is_in_rt = -1; // should be false! this is correctly initialized elsewhere!

void __init kdfsan_interface_preinit(void) {
  // Global variables are statically initialized to a non-zero value to keep them in the data section
  // This function sets them to the initial values they are actually supposed to be
  // This is a hack; there's probably a better way of zero-initializing kernel data
  kdf_is_init_done = false;
  kdf_is_in_rt = false;
  __memset(__dfsan_arg_tls, 0, 64*sizeof(__dfsan_arg_tls[0]));
  __dfsan_retval_tls = 0;
}

/***********************************************************/
/********* Enter/leave guards for run-time library *********/

// Set after init routine
void kdf_init_finished(void) { kdf_is_init_done = true; }

// Check for whether dfsan rt is being called from a function called by dfsan rt
static void set_rt(void) { kdf_is_in_rt = true; }
static void unset_rt(void) { kdf_is_in_rt = false; }

#if defined(CONFIG_X86)
#define kdf_stop_nmi() stop_nmi()
#define kdf_restart_nmi() restart_nmi()
#elif defined(CONFIG_ARM64)
#define kdf_stop_nmi()
#define kdf_restart_nmi()
#endif

// TODO: Probably should put set_rt after preempt_disable/local_irq_save/stop_nmi and
// unset_rt before restart_nmi/local_irq_restore/preempt_enable. This would probably require
// disabling instrumentation for arch/x86/kernel/nmi.c (at least). For now, we'll set/unset_rt
// from outside of the non-pre-emptable state, at the risk of losing KDFSan coverage, i.e.,
// because KDFSan would be disabled during an interrupt e.g., between set_rt() and preempt_disable()

#define CHECK_RT(default_ret) do { if(!kdf_is_init_done || kdf_is_in_rt) { return default_ret; } } while(0)
#define ENTER_RT(default_ret) \
    unsigned long __irq_flags; \
    do { \
        CHECK_RT(default_ret); \
        set_rt(); \
        preempt_disable(); \
        local_irq_save(__irq_flags); \
        kdf_stop_nmi(); \
    } while(0)
#define LEAVE_RT() \
    do { \
        KDF_PANIC_ON(!irqs_disabled(), "KDFSan error! IRQs should be disabled within the runtime!"); \
        kdf_restart_nmi(); \
        local_irq_restore(__irq_flags); \
        preempt_enable(); \
        unset_rt(); \
    } while(0)

#define CHECK_ONLY_IN_RT(default_ret) do { if(kdf_is_in_rt) { return default_ret; } } while(0)
#define ENTER_NOINIT_RT(default_ret) \
  unsigned long __irq_flags; \
	do { \
        CHECK_ONLY_IN_RT(default_ret); \
        set_rt(); \
        preempt_disable(); \
        local_irq_save(__irq_flags); \
        kdf_stop_nmi(); \
	} while(0)
#define LEAVE_NOINIT_RT() LEAVE_RT()

#define CHECK_WHITELIST(default_ret) do { if(!kdf_util_hook_is_whitelist_task()) { return default_ret; } } while(0)
#define ENTER_WHITELIST_RT(default_ret) \
    unsigned long __irq_flags; \
    do { \
        CHECK_RT(default_ret); \
	CHECK_WHITELIST(default_ret); \
        set_rt(); \
        preempt_disable(); \
        local_irq_save(__irq_flags); \
        kdf_stop_nmi(); \
    } while(0)
#define LEAVE_WHITELIST_RT() LEAVE_RT()

/***********************************************************/
/*************** Interfaces inserted by pass ***************/

dfsan_label noinline __dfsan_read_label(const void *addr, uptr size) {
  if (size == 0) return 0;
  ENTER_RT(0);
  dfsan_label ret = kdf_read_label(addr,size);
  KDF_CHECK_LABEL(ret);
  LEAVE_RT();
  return ret;
}

void noinline __dfsan_set_label(dfsan_label label, void *addr, uptr size) {
  if(size == 0) return;
  ENTER_RT();
  KDF_CHECK_LABEL(label);
  kdf_set_label(label,addr,size);
  LEAVE_RT();
}

dfsan_label noinline __dfsan_union(dfsan_label l1, dfsan_label l2) {
  if (l1 == 0) return l2;
  if (l2 == 0) return l1;
  if (l1 == l2) return l1;
  ENTER_RT(0);
  KDF_CHECK_LABEL(l1); KDF_CHECK_LABEL(l2);
  dfsan_label ret = kdf_union(l1,l2);
  KDF_CHECK_LABEL(ret);
  LEAVE_RT();
  return ret;
}

void noinline __dfsan_vararg_wrapper(const char *fname) {
  ENTER_RT();
  printk("KDFSan ERROR: unsupported indirect call to vararg\n");
  LEAVE_RT();
}

/********************************************************************/
/*************** Callback interfaces inserted by pass ***************/

/* TODO: The KDFSAN pass _might_ need to be picky about which loads/stores to
 * check, similar to how KASAN only instruments "interesting" loads/stores. At
 * least for Kasper (where the KDFSAN pass runs after the KASAN pass), we only
 * inserted load/store callbacks for the accesses which were hooked by KASAN.
 * Otherwise, KDFSAN would instrument too many accesses, and result in a crash.
 */

/* Add noinline function attribute if/when this callback does something interesting */
dfsan_label __dfsan_load_callback(void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label) { return data_label; }

/* Add noinline function attribute if/when this callback does something interesting */
void __dfsan_store_callback(void *addr, uptr size, dfsan_label data_label, dfsan_label ptr_label) { }

void noinline __dfsan_mem_transfer_callback(void *dest, const void *src, uptr size) {
  if(size == 0) return;
  ENTER_RT();
  kdf_memtransfer(dest, src, size);
  LEAVE_RT();
}

/* Add noinline function attribute if/when this callback does something interesting */
void __dfsan_cmp_callback(dfsan_label combined_label) { }

/***************************************************************/
/*************** Interfaces not inserted by pass ***************/

void noinline dfsan_add_label(dfsan_label label_src, void *addr, uptr size) {
  if(size == 0 || label_src == 0) return;
  ENTER_RT();
  KDF_CHECK_LABEL(label_src);
  kdf_add_label(label_src,addr,size);
  LEAVE_RT();
}

// TODO: userdata unused; remove
dfsan_label noinline dfsan_create_label(const char *desc, void *userdata) {
  ENTER_RT(0);
  dfsan_label ret = kdf_create_label(desc);
  KDF_CHECK_LABEL(ret);
  LEAVE_RT();
  return ret;
}

int noinline dfsan_has_label(dfsan_label label, dfsan_label elem) {
  if (label == elem) return true;
  ENTER_RT(false);
  KDF_CHECK_LABEL(label); KDF_CHECK_LABEL(elem);
  int ret = kdf_has_label(label,elem);
  LEAVE_RT();
  return ret;
}

dfsan_label noinline dfsan_has_label_with_desc(dfsan_label label, const char *desc) {
  ENTER_RT(0);
  KDF_CHECK_LABEL(label);
  dfsan_label ret = kdf_has_label_with_desc(label,desc);
  KDF_CHECK_LABEL(ret);
  LEAVE_RT();
  return ret;
}

dfsan_label noinline dfsan_get_label_count(void) {
  ENTER_RT(0);
  dfsan_label ret = kdf_get_label_count();
  LEAVE_RT();
  return ret;
}

dfsan_label noinline dfsan_read_label(const void *addr, uptr size) {
  return __dfsan_read_label(addr, size);
}

void noinline dfsan_set_label(dfsan_label label, void *addr, uptr size) {
  __dfsan_set_label(label, addr, size);
}

dfsan_label noinline dfsan_union(dfsan_label l1, dfsan_label l2) {
  return __dfsan_union(l1,l2);
}

dfsan_label noinline __dfsw_dfsan_get_label(long data, dfsan_label data_label, dfsan_label *ret_label) {
  *ret_label = 0;
  return data_label;
}

// TODO: Improve KDFSAN instrumentation coverage so that this can be removed.
dfsan_label noinline dfsan_get_label(long data) { return 0; }

void noinline dfsan_mem_transfer_callback(void *dest, const void *src, uptr size) {
  __dfsan_mem_transfer_callback(dest, src, size);
}

/************************************************************/
/*************** Memory management interfaces ***************/

int noinline kdfsan_alloc_page(struct page *page, unsigned int order, gfp_t orig_flags, int node) {
  ENTER_NOINIT_RT(0);
  int ret = kdf_alloc_page(page, order, orig_flags, node);
  LEAVE_NOINIT_RT();
  return ret;
}

void noinline kdfsan_free_page(struct page *page, unsigned int order) {
  ENTER_NOINIT_RT();
  kdf_free_page(page, order);
  LEAVE_NOINIT_RT();
}

void noinline kdfsan_split_page(struct page *page, unsigned int order) {
  ENTER_NOINIT_RT();
  kdf_split_page(page, order);
  LEAVE_NOINIT_RT();
}

/********************************************************/
/*************** Miscellaneous interfaces ***************/

void noinline dfsan_copy_label_info(dfsan_label label, char * dest, size_t count) {
  ENTER_RT();
  KDF_CHECK_LABEL(label);
  kdf_copy_label_info(label, dest, count);
  LEAVE_RT();
}

void noinline kdfsan_policy_syscall_arg(void * arg, size_t s, int arg_num) {
  ENTER_WHITELIST_RT();
  kdf_policy_syscall_arg(arg, s, arg_num);
  LEAVE_WHITELIST_RT();
}

void noinline kdfsan_policy_usercopy(void * dst, size_t s, dfsan_label src_ptr_label) {
  ENTER_WHITELIST_RT();
  kdf_policy_usercopy(dst, s, src_ptr_label);
  LEAVE_WHITELIST_RT();
}