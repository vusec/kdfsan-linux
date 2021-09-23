#include <linux/kdfsan.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/mman.h>
#include <linux/slab.h>

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

static void testbase_init(void) {
  printk("    KDFSan: Running init test...\n");
  int a;

  int a_read_label = dfsan_read_label(&a, sizeof(a));
  //printk("read_uninit_label (%d) == 0?\n",a_read_label);
  ASSERT(a_read_label == 0);

  a = -1; // gets rid of uninit usage warning

  int a_this_label = dfsan_get_label(a);
  //printk("this_uninit_label (%d) == 0?\n",a_this_label);
  ASSERT(a_this_label == 0);
}

/****************/

static void testbase_shadow_at(int* ptr) {
  //printk("ptr = %px\n",ptr);

  dfsan_label this_label = dfsan_create_label("a1", 0);
  ASSERT(this_label != 0);
  dfsan_set_label(this_label, ptr, sizeof(*ptr));

  dfsan_label new_this_label = dfsan_get_label(*ptr);
  //printk("this_label (%d) == new_this_label (%d)?\n",this_label,new_this_label);
  ASSERT(this_label == new_this_label);

  dfsan_label read_this_label = dfsan_read_label(ptr, sizeof(*ptr));
  //printk("this_label (%d) == read_this_label (%d)?\n",this_label,read_this_label);
  ASSERT(this_label == read_this_label);
}

int b = 1;
static void testbase_shadow(void) {
  printk("    KDFSan: Running shadow test for stack...\n");
  int i = 1;
  testbase_shadow_at(&i);

  printk("    KDFSan: Running shadow test for heap...\n");
  int* a_p = kzalloc(sizeof(int),GFP_KERNEL);
  *a_p = 1;
  testbase_shadow_at(a_p);
  kfree(a_p);

  printk("    KDFSan: Running shadow test for .data section...\n");
  testbase_shadow_at(&b);
}

/****************/

static void testbase_basic(void) {
  printk("    KDFSan: Running basic test...\n");

  int i = 1;
  dfsan_label i_label = dfsan_create_label("i2", 0);
  ASSERT(i_label != 0);
  dfsan_set_label(i_label, &i, sizeof(i));

  dfsan_label new_label = dfsan_get_label(i);
  //printk("i_label (%d) == new_label (%d)?\n",i_label,new_label);
  ASSERT(i_label == new_label);

  dfsan_label read_label = dfsan_read_label(&i, sizeof(i));
  //printk("i_label (%d) == read_label (%d)?\n",i_label,read_label);
  ASSERT(i_label == read_label);

  // Union tests
  dfsan_label j_label = dfsan_create_label("j2", 0);
  ASSERT(j_label != 0);
  dfsan_add_label(j_label, &i, sizeof(i));

  read_label = dfsan_read_label(&i, sizeof(i));
  //printk("read_label (%d) has i_label (%d)?\n",read_label,i_label);
  ASSERT(dfsan_has_label(read_label, i_label));
  //printk("read_label (%d) has j_label (%d)?\n",read_label,j_label);
  ASSERT(dfsan_has_label(read_label, j_label));
}

/****************/

static int testbase_fn_callee(int x) {
  int j = 2;
  dfsan_label j_label = dfsan_create_label("j3", 0);
  ASSERT(j_label != 0);
  dfsan_set_label(j_label, &j, sizeof(j));
  int ret = x + j;
  return ret;
}

static void testbase_fn_caller(void) {
  printk("    KDFSan: Running function call test...\n");
  int i = 1;
  dfsan_label i_label = dfsan_create_label("i3", 0);
  ASSERT(i_label != 0);
  dfsan_set_label(i_label, &i, sizeof(i));

  dfsan_label ij_label = dfsan_get_label(testbase_fn_callee(i));
  ASSERT(dfsan_has_label(ij_label, i_label));
  ASSERT(dfsan_has_label_with_desc(ij_label, "j3"));
  ASSERT(dfsan_has_label_with_desc(ij_label, "i3"));
  ASSERT(!dfsan_has_label_with_desc(ij_label, "foo3"));
}

/****************/

static void testbase_ref_callee(int * pi, int j) {
  *pi = j;
}

static void testbase_ref_caller(void) {
  printk("    KDFSan: Running pass by reference test...\n");
  int i = 1, j = 2;
  dfsan_label i_label = dfsan_create_label("i4", 0);
  ASSERT(i_label != 0);
  dfsan_label j_label = dfsan_create_label("j4", 0);
  ASSERT(j_label != 0);
  dfsan_set_label(i_label, &i, sizeof(i));
  dfsan_set_label(j_label, &j, sizeof(j));

  testbase_ref_callee(&i,j);

  ASSERT(dfsan_get_label(i) == j_label);
  ASSERT(dfsan_read_label(&i, sizeof(i)) == j_label);
}

/****************/

static void testbase_load(void) {
  printk("    KDFSan: Running load test...\n");
  int x[4] = {1,2,3,4}, i = 3, j;
  dfsan_label x_label = dfsan_create_label("x5", 0);
  ASSERT(x_label != 0);
  dfsan_label i_label = dfsan_create_label("i5", 0);
  ASSERT(i_label != 0);
  dfsan_set_label(x_label, x, sizeof(x));
  dfsan_set_label(i_label, &i, sizeof(i));

  j = x[i];

  // Checking loads combine the label of the pointer and the data
  dfsan_label j_label = dfsan_read_label(&j, sizeof(j));
  ASSERT(j_label != 0);
  ASSERT(j_label != i_label);
  ASSERT(j_label != x_label);
  ASSERT(dfsan_has_label(j_label, i_label));
  ASSERT(dfsan_has_label(j_label, x_label));
}

/****************/

static int add(int a, int b) {
  return a + b;
}

static int mul(int a, int b) {
  return a * b;
}

static void testbase_label_count(void) {
  printk("    KDFSan: Running label count test...\n");
  size_t old_label_count, current_label_count;

  // No labels allocated yet.
  old_label_count = dfsan_get_label_count();

  int i = 1;
  dfsan_label i_label = dfsan_create_label("i6", 0);
  dfsan_set_label(i_label, &i, sizeof(i));

  // One label allocated for i.
  current_label_count = dfsan_get_label_count();
  ASSERT(current_label_count == old_label_count + 1);

  int j = 2;
  dfsan_label j_label = dfsan_create_label("j6", 0);
  dfsan_set_label(j_label, &j, sizeof(j));

  // Check that a new label was allocated for j.
  current_label_count = dfsan_get_label_count();
  ASSERT(current_label_count == old_label_count + 2);

  // Create a value that combines i and j.
  int i_plus_j = add(i, j);

  // Check that a label was created for the union of i and j.
  current_label_count = dfsan_get_label_count();
  ASSERT(current_label_count == old_label_count + 3);

  // Combine i and j in a different way.  Check that the existing label is
  // reused, and a new label is not created.
  int j_times_i = mul(j, i);
  current_label_count = dfsan_get_label_count();
  ASSERT(current_label_count == old_label_count + 3);
  ASSERT(dfsan_get_label(i_plus_j) == dfsan_get_label(j_times_i));
}

/****************/

static void testbase_propagate(void) {
  printk("    KDFSan: Running propagate test...\n");
  ASSERT(dfsan_union(0, 0) == 0);

  int i = 1;
  dfsan_label i_label = dfsan_create_label("i7", 0);
  dfsan_set_label(i_label, &i, sizeof(i));

  int j = 2;
  dfsan_label j_label = dfsan_create_label("j7", 0);
  dfsan_set_label(j_label, &j, sizeof(j));

  int k = 3;
  dfsan_label k_label = dfsan_create_label("k7", 0);
  dfsan_set_label(k_label, &k, sizeof(k));

  int k2 = 4;
  dfsan_set_label(k_label, &k2, sizeof(k2));

  dfsan_label ij_label = dfsan_get_label(i + j);
  ASSERT(dfsan_has_label(ij_label, i_label));
  ASSERT(dfsan_has_label(ij_label, j_label));
  ASSERT(!dfsan_has_label(ij_label, k_label));
  // Test uniquing.
  ASSERT(dfsan_union(i_label, j_label) == ij_label);
  ASSERT(dfsan_union(j_label, i_label) == ij_label);

  dfsan_label ijk_label = dfsan_get_label(i + j + k);
  ASSERT(dfsan_has_label(ijk_label, i_label));
  ASSERT(dfsan_has_label(ijk_label, j_label));
  ASSERT(dfsan_has_label(ijk_label, k_label));

  ASSERT(dfsan_get_label(k + k2) == k_label);

  struct { int i, j; } s = { i, j };
  ASSERT(dfsan_read_label(&s, sizeof(s)) == ij_label);

  ASSERT(dfsan_get_label(((i + j) + k) + i) == ijk_label);
  ASSERT(dfsan_get_label((((i + j) + k) + i) + j) == ijk_label);
  ASSERT(dfsan_get_label(((((i + j) + k) + i) + j) + k) == ijk_label);
}

/****************/

static void testbase_memtransfer(void) {
  printk("    KDFSan: Running shadow memtransfer test... (TODO: get reliable compilation into llvm instrinsics)\n");

  char test_str[16] = "aaaabbbbcccc";
  dfsan_label a_label = dfsan_create_label("a", 0);
  dfsan_set_label(a_label, &test_str[0], 4);
  dfsan_label b_label = dfsan_create_label("b", 0);
  dfsan_set_label(b_label, &test_str[4], 4);
  dfsan_label c_label = dfsan_create_label("c", 0);
  dfsan_set_label(c_label, &test_str[8], 4);

  // Sanity checks
  ASSERT(a_label != 0 && b_label != 0 && c_label != 0); // every label is initialized
  ASSERT(a_label != b_label && b_label != c_label && a_label != c_label); // labels are unique

  // KDFSAN's memmove and memcpy handlers are the same, because the LLVM instructions seem to have the same semantics
  char memmove_str[16];

  // Test forward overlapping
  strcpy(memmove_str, test_str);
  ASSERT(memmove_str[0] == 'a');
  ASSERT(memmove_str[4] == 'b');
  ASSERT(memmove_str[8] == 'c');
  ASSERT(dfsan_read_label(&memmove_str[0], 4) == a_label);
  ASSERT(dfsan_read_label(&memmove_str[4], 4) == b_label);
  ASSERT(dfsan_read_label(&memmove_str[8], 4) == c_label);
  // After this, memmove_str should be "aaaaaaaabbbb"
  __builtin_memmove((memmove_str+4), memmove_str, 8);
  ASSERT(dfsan_read_label(&memmove_str[0], 4) == a_label);
  ASSERT(dfsan_read_label(&memmove_str[4], 4) == a_label);
  ASSERT(dfsan_read_label(&memmove_str[8], 4) == b_label);
  ASSERT(memmove_str[0] == 'a');
  ASSERT(memmove_str[4] == 'a');
  ASSERT(memmove_str[8] == 'b');

  // Test backward overlapping
  strcpy(memmove_str, test_str);
  ASSERT(memmove_str[0] == 'a');
  ASSERT(memmove_str[4] == 'b');
  ASSERT(memmove_str[8] == 'c');
  ASSERT(dfsan_read_label(&memmove_str[0], 4) == a_label);
  ASSERT(dfsan_read_label(&memmove_str[4], 4) == b_label);
  ASSERT(dfsan_read_label(&memmove_str[8], 4) == c_label);
  // After this, memmove_str should be "bbbbcccccccc"
  __builtin_memmove(memmove_str, (memmove_str+4), 8);
  ASSERT(dfsan_read_label(&memmove_str[0], 4) == b_label);
  ASSERT(dfsan_read_label(&memmove_str[4], 4) == c_label);
  ASSERT(dfsan_read_label(&memmove_str[8], 4) == c_label);
  ASSERT(memmove_str[0] == 'b');
  ASSERT(memmove_str[4] == 'c');
  ASSERT(memmove_str[8] == 'c');
}

/****************/

static void testbase_pointers(void) {
  printk("    KDFSan: Running pointer test...\n");

  int i = 3;
  int arr[10] = {0,1,2,3,4,5,6,7,8,9};

  dfsan_label i_label = dfsan_create_label("i8", 0);
  dfsan_set_label(i_label, &i, sizeof(i));
  ASSERT(dfsan_get_label(i) != 0 && dfsan_get_label(i) == i_label); // sanity check

  // A value read via a tainted pointer should be tainted (however, this is configurable from the KDFSan pass)
  ASSERT(dfsan_get_label(arr[i]) == dfsan_get_label(i) && dfsan_get_label(arr[i]) != 0);

  // However, the data itself shouldn't be tainted
  ASSERT(dfsan_get_label(arr[3]) == 0);

  // A value written via a tainted pointer should not be tainted (however, this is configurable from the KDFSan pass)
  arr[i] = 34;
  ASSERT(dfsan_get_label(arr[3]) == 0);
}

/****************/

static void testbase_custom(void) {
  printk("    KDFSan: Running custom ABI test... (TODO: add more custom wrappers)\n");
  // Some custom-wrapped functions are tested within test_string
}

/****************/

#ifdef CONFIG_X86

static void testbase_asminline(void) {
  printk("    KDFSan: Running inline asm test...\n");

  int src_a = 34, src_b = 35, tmp = 0, dst = 0;
  dfsan_label a_label, b_label, ab_label;
  a_label = dfsan_create_label("a9", 0);
  b_label = dfsan_create_label("b9", 0);
  ab_label = dfsan_union(a_label, b_label);
  dfsan_set_label(a_label, &src_a, sizeof(src_a));
  dfsan_set_label(b_label, &src_b, sizeof(src_b));

  // Sanity checks
  ASSERT(a_label != 0 && b_label != 0 && ab_label != 0 && a_label != b_label);
  ASSERT(dfsan_get_label(src_a) == a_label && dfsan_get_label(src_b) == b_label);
  ASSERT(dfsan_has_label(ab_label, a_label) && dfsan_has_label(ab_label, b_label));

  // 1 input, 1 output
  // dst = src_a; dst++
  tmp = dst = 0;
  asm ("mov %1, %0\n\t"
       "add $1, %0"
       : "+r" (dst)
       : "r" (src_a));
  ASSERT(dst == src_a + 1 && src_a == 34 && src_b == 35); // just to make sure asm is correct
  ASSERT(dfsan_get_label(src_a) == a_label); // input label should remain the same
  ASSERT(dfsan_get_label(dst) == 0); // output should be untainted

  // 1 input, 2 outputs
  // tmp = src_a; tmp++; dst = tmp;
  tmp = dst = 0;
  asm ("mov %2, %1\n\t"
       "add $1, %1\n\t"
       "mov %1, %0"
       : "=r" (dst), "+r" (tmp)
       : "r" (src_a));
  ASSERT(tmp == src_a + 1 && dst == tmp && src_a == 34 && src_b == 35);
  ASSERT(dfsan_get_label(src_a) == a_label);
  ASSERT(dfsan_get_label(tmp) == 0 && dfsan_get_label(dst) == 0);

  // 2 inputs, 1 output
  // dst = src_a; dst += src_b;
  tmp = dst = 0;
  asm ("mov %1, %0\n\t"
       "add %2, %0"
       : "+r" (dst)
       : "r" (src_a), "r" (src_b));
  ASSERT(dst == src_a + src_b && src_a == 34 && src_b == 35);
  ASSERT(dfsan_get_label(dst) == 0);

  // 2 inputs, 2 outputs
  // tmp = src_a; tmp += src_b; dst = tmp;
  tmp = dst = 0;
  asm volatile("mov %2, %1\n\t"
       "add %3, %1\n\t"
       "mov %1, %0"
       : "=r" (dst), "+r" (tmp)
       : "r" (src_a), "r" (src_b));
  ASSERT(tmp == src_a + src_b && dst == tmp && src_a == 34 && src_b == 35);
  ASSERT(dfsan_get_label(dst) == 0 && dfsan_get_label(tmp) == 0);

  // 1 input, 1 output
  // even tmp is both the input and output, its taint is washed
  tmp = src_a; // taint tmp
  ASSERT(dfsan_get_label(tmp) == a_label);
  asm ("inc %0" : "+r" (tmp));
  ASSERT(tmp == src_a + 1 && src_a == 34 && src_b == 35);
  ASSERT(dfsan_get_label(tmp) == 0);
}

#else

static void testbase_asminline(void) {
  printk("    KDFSan: No inline asm test for this architecture. Skipping...\n");
}

#endif

/****************/

static void testbase_string(void) {
  printk("    KDFSan: Running string tests...\n");

  uint32_t src = 3, dst;
  dfsan_label taint = dfsan_create_label("x10", 0);
  ASSERT(taint != 0);
  dfsan_set_label(taint, &src, sizeof(src));

  // Clear
  dst = 4;
  ASSERT(src != dst);
  ASSERT(dfsan_get_label(src) == taint);
  ASSERT(dfsan_get_label(dst) == 0);

  // memcpy test
  memcpy(&dst, &src, sizeof(dst));
  ASSERT(dfsan_get_label(src) == taint);
  ASSERT(dfsan_get_label(dst) == taint);
  ASSERT(src == dst);

  // Clear
  dst = 4;
  ASSERT(src != dst);
  ASSERT(dfsan_get_label(src) == taint);
  ASSERT(dfsan_get_label(dst) == 0);

  // __memcpy test
  __memcpy(&dst, &src, sizeof(dst));
  ASSERT(dfsan_get_label(src) == taint);
  ASSERT(dfsan_get_label(dst) == taint);
  ASSERT(src == dst);

  // Clear
  dst = 4;
  ASSERT(src != dst);
  ASSERT(dfsan_get_label(src) == taint);
  ASSERT(dfsan_get_label(dst) == 0);

  // memset32 test
  memset32(&dst, src, 1);
  ASSERT(dfsan_get_label(src) == taint);
  ASSERT(dfsan_get_label(dst) == taint);
  ASSERT(src == (char) dst);

  // Clear
  dst = 4;
  ASSERT(src != dst);
  ASSERT(dfsan_get_label(src) == taint);
  ASSERT(dfsan_get_label(dst) == 0);

  // memset test
  memset(&dst, src, sizeof(dst));
  ASSERT(dfsan_get_label(src) == taint);
  ASSERT(dfsan_get_label(dst) == taint);
  ASSERT(src == (char) dst); // dst actually equals ((src) | (src << 8) | (src << 16) | (src << 24)) because memset does 1-byte copies

  // TODO: memmove, strcpy, strncpy, strlen
}

/****************/

static void testbase_asmfxns_clear_page(void) {
  printk("    KDFSan: Running asm function test -- clear_page...\n");

  // Init buffer
  char * kmem = kzalloc(PAGE_SIZE, GFP_KERNEL);
  clear_mem(kmem, PAGE_SIZE);

  // Init taint
  char val = 34;
  dfsan_label taint = dfsan_create_label("x11", 0);
  dfsan_set_label(taint, &val, sizeof(val));

  // Taint one byte of buffer
  kmem[77] = val;
  ASSERT(kmem[77] == val);
  ASSERT(dfsan_get_label(kmem[76]) == 0);
  ASSERT(dfsan_get_label(kmem[77]) == taint);
  ASSERT(dfsan_get_label(kmem[78]) == 0);
  ASSERT(dfsan_read_label(kmem, PAGE_SIZE) == taint);

  // Clear page
  clear_page(kmem);
  ASSERT(kmem[77] == 0); // clear_page works as expected
  ASSERT(dfsan_get_label(kmem[76]) == 0);
  ASSERT(dfsan_get_label(kmem[77]) == 0); // now untainted
  ASSERT(dfsan_get_label(kmem[78]) == 0);
  ASSERT(dfsan_read_label(kmem, PAGE_SIZE) == 0); // now untainted

  kfree(kmem);
}

static void testbase_asmfxns(void) {
  printk("    KDFSan: Running asm function calls test... (TODO: add more functions)\n");

  testbase_asmfxns_clear_page();
  // TODO: check labels of functions with custom taint handlers for asm
}

/****************/

static int testbase_stack_shadow_overwrite_stack(int i) {
  if(i == 0) return 0;
  return testbase_stack_shadow_overwrite_stack(i-1);
}

static void testbase_stack_shadow_get_tainted_ptr_from_old_frame(int ** ret) {
  // array on the stack where element 34 is tainted
  int arr[64] = {0};
  int * tainted_i = &arr[34];

  dfsan_label lbl = dfsan_create_label("x12", 0);
  dfsan_set_label(lbl, tainted_i, sizeof(*tainted_i));

  *ret = tainted_i;
}

static void testbase_stack_shadow(void) {
  printk("    KDFSan: Running stack shadow test...\n");
  int * ptr = NULL;

  testbase_stack_shadow_get_tainted_ptr_from_old_frame(&ptr);
  ASSERT(ptr != NULL);
  dfsan_label lbl_before = dfsan_read_label(ptr, sizeof(*ptr));
  ASSERT(lbl_before != 0);
  ASSERT(dfsan_has_label_with_desc(lbl_before, "x12"));

  testbase_stack_shadow_overwrite_stack(50);
  dfsan_label label_after = dfsan_read_label(ptr, sizeof(*ptr));
  //ASSERT(label_after == 0);
  printk("  ** NOTE: This seems to be a fundamental problem with DFSan: not _all_ writes to the stack (e.g., calls/rets) hit shadow memory -- ASSERT(label_after %d == 0)? **\n", label_after);
}

/****************/

void kdf_run_base_tests(void) {
  testbase_init(); // Test only works if run first
  testbase_shadow();
  testbase_basic();
  testbase_label_count();
  testbase_fn_caller();
  testbase_ref_caller();
  testbase_load();
  testbase_propagate();
  testbase_memtransfer();
  testbase_string();
  testbase_pointers();
  testbase_custom();
  testbase_asminline();
  testbase_asmfxns();
  testbase_stack_shadow();
  TEST_PANIC_ON(kdf_tests_fail, "KDFSan error: one or more tests failed");
}
