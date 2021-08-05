#include <linux/kdfsan.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include "../mm/kdfsan/kdfsan_policies.h"

static bool kdf_tests_fail = false;

#define TEST_PANIC_ON(cond, ...) \
do { \
  if(cond) { \
    panic(__VA_ARGS__); \
  } \
} while(0)

#define ASSERT(x) \
do {    if (x) break; \
        printk(KERN_EMERG "### ASSERTION FAILED %s: %s: %d: %s\n", \
               __FILE__, __func__, __LINE__, #x); \
        kdf_tests_fail = true;  \
} while (0)

static bool check_mem(char * arr, size_t size, char x) {
  for(int i = 0; i < size; i++) {
    if(arr[i] != x)
      return false;
  }
  return true;
}

static void clear_mem(char * arr, size_t size) {
  memset(arr, 0, size);
  dfsan_set_label(0, arr, size);
  ASSERT(check_mem(arr, size, 0));
  ASSERT(dfsan_read_label(arr, size) == 0);
}

/****************/

static bool check_labels(char * arr, size_t size, dfsan_label expected_label) {
  dfsan_label this_label;
  for(int i = 0; i < size; i++) {
    this_label = dfsan_get_label(arr[i]);
    if(this_label != expected_label) {
      printk("    KDFSan test ERROR: label of arr[%d] is %d but expected %d; quitting test...\n", i, this_label, expected_label);
      return false;
    }
  }
  return true;
}

static void testpolicies_usercopy_run(char *kmem, char __user *usermem, size_t size, char data, dfsan_label expected_label) {
  // Test copy_from_user
  clear_mem(kmem, size);
  TEST_PANIC_ON(copy_from_user(kmem, usermem, size), "KDFSan test error: copy_from_user failed");
  ASSERT(check_labels(kmem, size, expected_label));
  ASSERT(check_mem(kmem, size, data));

  // Test get_user
  clear_mem(kmem, size);
  TEST_PANIC_ON(get_user(kmem[0], usermem), "KDFSan test error: get_user failed");
  ASSERT(check_labels(kmem, 1, expected_label) && dfsan_read_label(&kmem[1], size - 1) == 0);
  ASSERT(check_mem(kmem, 1, data) && check_mem(&kmem[1], size - 1, 0));

  // Test strncpy_from_user
  clear_mem(kmem, size);
  put_user(0, &usermem[size - 1]); // NULL-terminates string
  TEST_PANIC_ON(strncpy_from_user(kmem, usermem, size) != size - 1, "KDFSan test error: strncpy_from_user failed"); // returns length of string on success
  ASSERT(check_labels(kmem, size - 1, expected_label) && dfsan_read_label(&kmem[size - 1], 1) == 0);
  ASSERT(check_mem(kmem, size - 1, data) && check_mem(&kmem[size - 1], 1, 0));

  // Test strnlen_user
  clear_mem(kmem, size);
  put_user(0, &usermem[size - 2]); // NULL-terminates string 1 byte early
  size_t user_len = strnlen_user(usermem, size); // returns the string length *including* the NULL terminator
  ASSERT(dfsan_get_label(user_len) == expected_label);
  ASSERT(user_len == size - 1);
}

static void testpolicies_usercopy(void) {
  printk("    KDFSan: Setting up user copy tests... (This should only run once task whitelisting is enabled, otherwise usercopy taint will not be applied)\n");

  char *kmem;
  char __user *usermem;
  unsigned long user_addr;
  size_t size = 10;
  char data = 34;
  dfsan_label attacker_label = dfsan_create_label("test-a11", 0);
  dfsan_label usercopy_label = kdf_policy_get_usercopy_label();
  dfsan_label unioned_label = dfsan_union(attacker_label, usercopy_label);
  //printk("    KDFSan usercopy test: attacker_label = %d, usercopy_label = %d, unioned_label = %d\n", attacker_label, usercopy_label, unioned_label);

  // Allocate mem
  kmem = kmalloc(size, GFP_KERNEL);
	TEST_PANIC_ON(!kmem, "KDFSan test error: Failed to allocate kernel memory");
	user_addr = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0);
  TEST_PANIC_ON(user_addr >= (unsigned long)(TASK_SIZE), "KDFSan test error: Failed to allocate user memory");
	usermem = (char __user *)user_addr;

  // Initialize usermem and check that parameters are untainted
  printk("    KDFSan: Running user copy tests with untainted user pointer...\n");
  memset(kmem, data, size);
  TEST_PANIC_ON(copy_to_user(usermem, kmem, size), "KDFSan test error: copy_to_user failed");
  ASSERT(dfsan_read_label(&kmem, sizeof(kmem)) == 0);
  ASSERT(dfsan_read_label(&usermem, sizeof(usermem)) == 0);
  ASSERT(dfsan_get_label(size) == 0 && dfsan_get_label(data) == 0);
  testpolicies_usercopy_run(kmem, usermem, size, data, usercopy_label); // usercopy output should only have the usercopy label

  // Re-initialize usermem and taint user pointer (tests should function the same regardless of taint)
  printk("    KDFSan: Running user copy tests with tainted user pointer...\n");
  memset(kmem, data, size);
  TEST_PANIC_ON(copy_to_user(usermem, kmem, size), "KDFSan test error: copy_to_user failed");
  dfsan_set_label(attacker_label, &usermem, sizeof(usermem));
  ASSERT(dfsan_read_label(&kmem, sizeof(kmem)) == 0);
  ASSERT(dfsan_read_label(&usermem, sizeof(usermem)) != 0); // usermem pointer is tainted
  ASSERT(dfsan_get_label(size) == 0 && dfsan_get_label(data) == 0);
  testpolicies_usercopy_run(kmem, usermem, size, data, unioned_label); // usercopy output should have both the usercopy label and the attacker label

  // Cleanup
  printk("    KDFSan: Cleaning up user copy tests...\n");
  vm_munmap(user_addr, size);
  kfree(kmem);
}

/****************/

void kdf_run_policies_tests(void) {
  testpolicies_usercopy();
  TEST_PANIC_ON(kdf_tests_fail, "KDFSan error: one or more tests failed");
}
