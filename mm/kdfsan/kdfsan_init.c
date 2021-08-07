#include "kdfsan_types.h"
#include "kdfsan_internal.h"
#include "kdfsan_shadow.h"
#include "kdfsan_policies.h"
#include "kdfsan_interface.h"

#include <asm/cpu_entry_area.h>
#include <asm/sections.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/debugfs.h>

/*********************************************************************/
/************************** Early-boot init **************************/

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

void __init kdfsan_init_shadow(void) {
  kdf_initialize_shadow();
  kdfsan_interface_preinit();
}

/********************************************************************/
/************************** Late-boot init **************************/

bool kdf_dbgfs_run_tests = false;
bool kdf_dbgfs_generic_syscall_label = false;

static int kdfsan_enable(void *data, u64 *val);
DEFINE_DEBUGFS_ATTRIBUTE(kdfsan_enable_fops, kdfsan_enable, NULL, "%lld\n");

int __init kdfsan_init(void) {
  struct dentry *kdfsan_dir;

  printk("KDFSan: Initializing internal data...\n");
  kdf_init_internal_data();

  printk("KDFSan: Initializing debugfs...\n");
  kdfsan_dir  = debugfs_create_dir("kdfsan", NULL);
  debugfs_create_file("enable", 0444, kdfsan_dir, NULL, &kdfsan_enable_fops);
  debugfs_create_bool("generic_syscall_label", 0666, kdfsan_dir,
      &kdf_dbgfs_generic_syscall_label);
  debugfs_create_bool("run_tests", 0666, kdfsan_dir, &kdf_dbgfs_run_tests);
  printk("KDFSan: Initialization done.\n");
  return 0;
}
postcore_initcall(kdfsan_init);

/**********************************************************************/
/************************** Post-boot enable **************************/

void kdf_run_base_tests(bool is_first_run);
void kdf_run_policies_tests(void);

// Warning: SUPER janky code to get the tests to work with task whitelisting
#define SET_WHITELIST_TASK() \
  char _saved_str[TASK_COMM_LEN]; \
  kdf_util_strlcpy(_saved_str, current->comm, TASK_COMM_LEN); \
  kdf_util_strlcpy(current->comm, "kdfsan_task", TASK_COMM_LEN);
#define RESET_TASK() \
  kdf_util_strlcpy(current->comm, _saved_str, TASK_COMM_LEN);

static int kdfsan_enable(void *data, u64 *val) {
  unsigned long ini = 0, end = 0;
  printk("KDFSan: Enabling...\n");
  kdf_init_finished();
  printk("KDFSan: Initializing custom tainting policies...\n");
  kdf_policies_init();
  if (kdf_dbgfs_run_tests) {
    printk("KDFSan: Running KDFSan base tests...\n");
    ini=get_cycles(); kdf_run_base_tests(true); end=get_cycles();
    printk("KDFSan: KDFSan base tests complete (%liM cycles elapsed)", (end-ini)/1000000);
    printk("KDFSan: Running KDFSan policies tests...\n");
    SET_WHITELIST_TASK();
    ini=get_cycles(); kdf_run_policies_tests(); end=get_cycles();
    RESET_TASK();
    printk("KDFSan: KDFSan policies tests complete (%liM cycles elapsed)", (end-ini)/1000000);
  }
  printk("KDFSan: Done.\n");
  return 0;
}