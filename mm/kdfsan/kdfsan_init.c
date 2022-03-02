// SPDX-License-Identifier: GPL-2.0
// Shadow memory initialization based on KMSAN's

#include "kdfsan_types.h"
#include "kdfsan_internal.h"
#include "kdfsan_shadow.h"
#include "kdfsan_init.h"

#include <asm/cpu_entry_area.h>
#include <asm/sections.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/debugfs.h>

#define NUM_FUTURE_RANGES 128
struct start_end_pair {
  void *start, *end;
};

static struct start_end_pair start_end_pairs[NUM_FUTURE_RANGES] __initdata;
static int future_index __initdata;

/*
 * Record a range of memory for which the metadata pages will be created once
 * the page allocator becomes available.
 */
static void __init kdf_record_future_shadow_range(void *start, void *end) {
  printk("%s: recording region %px-%px\n",__func__,start,end);
  KDF_PANIC_ON(future_index == NUM_FUTURE_RANGES, "KDFSan init error: check 1 in kdf_record_future_shadow_range failed");
  KDF_PANIC_ON((start >= end) || !start || !end, "KDFSan init error: check 2 in kdf_record_future_shadow_range failed");
  start_end_pairs[future_index].start = start;
  start_end_pairs[future_index].end = end;
  future_index++;
}

/* Allocate metadata for pages allocated at boot time. */
static void __init kdf_init_alloc_meta_for_range(void *start, void *end) {
  u64 addr, size;
  struct page *page;
  void *shadow;
  struct page *shadow_p;

  // FIXME: Potential bug -- If a range is in the same region as another range, then it will have >1 shadow page allocated for it
  start = (void *)ALIGN_DOWN((u64)start, PAGE_SIZE);
  size = ALIGN((u64)end - (u64)start, PAGE_SIZE);
  shadow = memblock_alloc(size, PAGE_SIZE);
  for (addr = 0; addr < size; addr += PAGE_SIZE) {
    page = kdf_virt_to_page_or_null((char *)start + addr);
    shadow_p = kdf_virt_to_page_or_null((char *)shadow + addr);
    shadow_p->shadow = NULL;
    page->shadow = shadow_p;
  }
}

/*
 * Initialize the shadow for existing mappings during kernel initialization.
 * These include kernel text/data sections, NODE_DATA and future ranges
 * registered while creating other data (e.g. percpu).
 *
 * Allocations via memblock can be only done before slab is initialized.
 */
static void __init kdf_initialize_shadow(void) {
  int nid;
  u64 i;
  struct memblock_region *mb_region;
  const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);

  printk("KDFSan: Initializing shadow...\n");
  printk("%s: recording all reserved memblock regions...\n",__func__);
  for_each_reserved_mem_region(mb_region) kdf_record_future_shadow_range(phys_to_virt(mb_region->base),
      phys_to_virt(mb_region->base + mb_region->size));

  printk("%s: recording .data region...\n",__func__);
  kdf_record_future_shadow_range(_sdata, _edata);

  printk("%s: recording all online nodes regions...\n",__func__);
  for_each_online_node (nid) kdf_record_future_shadow_range(NODE_DATA(nid), (char *)NODE_DATA(nid) + nd_size);

  printk("%s: allocating %d ranges...\n",__func__,future_index);
  for (i = 0; i < future_index; i++) kdf_init_alloc_meta_for_range(start_end_pairs[i].start, start_end_pairs[i].end);

  printk("KDFSan: Shadow initialized.\n");
}

/********/

extern bool kdf_is_init_done; // should be false;
extern bool kdf_is_in_rt; // should be false;
extern dfsan_label __dfsan_arg_tls[64]; // should be { 0 }
extern dfsan_label __dfsan_retval_tls; // should be 0
static void __init kdf_preinit_data(void) {
  // Global variables are statically initialized to a non-zero value to keep them in the data section
  // This function sets them to the initial values they are actually supposed to be
  // This is a hack; there's probably a better way of zero-initializing kernel data
  kdf_is_init_done = false;
  kdf_is_in_rt = false;
  __memset(__dfsan_arg_tls, 0, 64*sizeof(__dfsan_arg_tls[0]));
  __dfsan_retval_tls = 0;
}

void __init kdfsan_init_shadow(void) {
  kdf_initialize_shadow();
  kdf_preinit_data();
}
EXPORT_SYMBOL(kdfsan_init_shadow);

/********/

// Warning: SUPER janky code to get the tests to work with task whitelisting

static char *my_strcpy(char *dst, const char* src) {
  u32 i;
  for (i=0; src[i] != '\0'; ++i) { dst[i] = src[i]; }
  dst[i]= '\0';
  return dst;
}

#define SET_WHITELIST_TASK() \
  char _saved_str[TASK_COMM_LEN]; \
  my_strcpy(_saved_str, current->comm); \
  my_strcpy(current->comm, "kasper_task");

#define RESET_TASK() \
  my_strcpy(current->comm, _saved_str);

/********/

static bool kdf_dbgfs_disable_tainting = false;
static bool kdf_dbgfs_run_tests = false;
static bool kdf_dbgfs_run_kocher_tests = false;
u8 kdf_dbgfs_syscall_label_type = KDF_SYSCALL_LABEL_DEFAULT;
bool kdf_dbgfs_run_specfuzz_policies = false;
bool kdf_dbgfs_run_spectaint_policies = false;
bool kdf_dbgfs_report_only_pht_syscall_cc = false;
bool report_smotherspectre = true;

static void kdf_check_policies(void) {
  int i = 0;
  if (kdf_dbgfs_run_specfuzz_policies) i++;
  if (kdf_dbgfs_run_spectaint_policies) i++;
  if (kdf_dbgfs_report_only_pht_syscall_cc) i++;
  if (i >= 1) report_smotherspectre = false; // only report smotherspectre gadget with default policies
  if (i > 1) panic("KDFSan ERROR: Only one policy should be set at most!\n");
}

/********/

void kdf_run_base_tests(bool is_first_run);
void kdf_run_policies_tests(void);
void kdf_run_kasper_tests(void);
void kdf_run_kocher_tests(void);
void kdfinit_init(void);

int kdfsan_enable(void *data, u64 *val) {
  unsigned long ini = 0, end = 0;
  if (kdf_dbgfs_disable_tainting) {
    printk("KDFSan: Enabling kspecem...\n");
    kspecem_common_late_init();
    printk("KDFSan: Enabling kspecem: done.\n");
    return 0;
  }
  printk("KDFSan: Checking policies...\n");
  kdf_check_policies();
  printk("KDFSan: Enabling...\n");
  kdf_init_finished();
  printk("KDFSan: Initializing custom tainting policies...\n");
  kdfinit_init();
  if (kdf_dbgfs_run_tests) {
    printk("KDFSan: Running KDFSan base tests...\n");
    ini=get_cycles(); kdf_run_base_tests(true); end=get_cycles();
    printk("KDFSan: KDFSan base tests complete (%liM cycles elapsed)", (end-ini)/1000000);
  }
  printk("KDFSan: Enabling kspecem...\n");
  kspecem_common_late_init();
  printk("KDFSan: Enabling kspecem: done.\n");
  if (kdf_dbgfs_run_tests) {
    SET_WHITELIST_TASK();
    printk("KDFSan: Re-running KDFSan base tests...\n");
    ini=get_cycles(); kdf_run_base_tests(false); end=get_cycles();
    printk("KDFSan: KDFSan base tests complete (%liM cycles elapsed).\n", (end-ini)/1000000);
    printk("KDFSan: Running KDFSan policies tests...\n");
    ini=get_cycles(); kdf_run_policies_tests(); end=get_cycles();
    printk("KDFSan: KDFSan policies tests complete (%liM cycles elapsed)", (end-ini)/1000000);
    printk("Running Kasper tests...\n");
    ini=get_cycles(); kdf_run_kasper_tests(); end=get_cycles();
    printk("KDFSan: Kasper tests complete (%liM cycles elapsed).\n", (end-ini)/1000000);
    RESET_TASK();
  }
  if (kdf_dbgfs_run_kocher_tests) {
    SET_WHITELIST_TASK();
    printk("Running Kocher tests...\n");
    ini=get_cycles(); kdf_run_kocher_tests(); end=get_cycles();
    printk("KDFSan: Kocher tests complete (%liM cycles elapsed).\n", (end-ini)/1000000);
    RESET_TASK();
  }
  printk("KDFSan: Done.\n");
  return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(kdfsan_enable_fops, kdfsan_enable, NULL, "%lld\n");

int __init kdfsan_init(void) {
  struct dentry *kdfsan_dir;

  printk("KDFSan: Initializing internal data...\n");
  kdf_init_internal_data();

  printk("KDFSan: Initializing debugfs...\n");
  kdfsan_dir  = debugfs_create_dir("kdfsan", NULL);
  debugfs_create_file("enable", 0444, kdfsan_dir, NULL, &kdfsan_enable_fops);
  debugfs_create_u8("syscall_label_type", 0666, kdfsan_dir,
      &kdf_dbgfs_syscall_label_type);
  debugfs_create_bool("disable_tainting", 0666, kdfsan_dir, &kdf_dbgfs_disable_tainting);
  debugfs_create_bool("run_tests", 0666, kdfsan_dir, &kdf_dbgfs_run_tests);
  debugfs_create_bool("run_kocher_tests", 0666, kdfsan_dir, &kdf_dbgfs_run_kocher_tests);
  debugfs_create_bool("run_specfuzz_policies", 0666, kdfsan_dir, &kdf_dbgfs_run_specfuzz_policies);
  debugfs_create_bool("run_spectaint_policies", 0666, kdfsan_dir, &kdf_dbgfs_run_spectaint_policies);
  debugfs_create_bool("report_only_pht_syscall_cc", 0666, kdfsan_dir, &kdf_dbgfs_report_only_pht_syscall_cc);
  printk("KDFSan: Initialization done.\n");
  return 0;
}
postcore_initcall(kdfsan_init);
