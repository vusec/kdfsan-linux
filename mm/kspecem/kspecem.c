// SPDX-License-Identifier: GPL-2.0

#include <linux/kspecem.h>
#include <linux/kernel.h>
#include <linux/sched.h>

#ifdef CONFIG_KSPECEM
#define KSPECEM_ERR do { panic("The kspecem pass needs to run and the kspecem runtime need to be linked in when CONFIG_KSPECEM is enabled!"); } while(0)
void __weak kspecem_hook_store(void *addr) { KSPECEM_ERR; }
void __weak kspecem_hook_memcpy(char *addr, size_t size) { KSPECEM_ERR; }
void __weak kspecem_hook_panic_info(void) { KSPECEM_ERR; }
bool __weak kspecem_hook_kasan_report(unsigned long addr, size_t size,
    bool is_write, unsigned long ip) { KSPECEM_ERR; }
void __weak kspecem_hook_check_spec_length(unsigned int bb_inst_count) { KSPECEM_ERR; }
int __init __weak kspecem_init(void) { KSPECEM_ERR; }

postcore_initcall(kspecem_init);

noinline __attribute__((no_sanitize("address"))) unsigned long kspecem_syscall_get_nr(void) {
  unsigned long __ptr = (unsigned long)(current->stack);
  __ptr += THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
  return (((struct pt_regs *)__ptr) - 1)->orig_ax;
}
#endif
