// SPDX-License-Identifier: GPL-2.0

#include <linux/kdfsan.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/slab.h>

bool false_cond = -1;

/****************/

int testkasper_load(int * arr, int x) {
  return arr[x];
}

/****************/

void testkasper_store(int * arr, int i, int val) {
  arr[i] = val;
}

/****************/

int testkasper_spec_load(int * arr, int arr_size, int x) {
  int y = 0;
  if(x < arr_size) {
    y = arr[x];
  }
  return y;
}

/****************/

int testkasper_independent_accesses(int * arr, int arr_size, int x1, int x2) {
  int y = 0;
  bool cond = x1 < arr_size && x2 < arr_size;
  if(cond) {
    int a = arr[x1];
    int b = arr[x2];
    y = a + b;
  }
  return y;
}

/****************/

int testkasper_two_dependent_accesses_arr(int * arr1, int * arr2, int arr1_size, int x) {
  int y = 0;
  if(x < arr1_size) {
    y = arr2[arr1[x] & 0]; // "& 0" hack to prevent subsequent access from going OOB
  }
  return y;
}

/****************/

int testkasper_two_dependent_accesses_ptr(int ** ptr1) {
  int y = 0;
  if(false_cond) {
    int * ptr2;
    ptr2 = *ptr1;
    y = *ptr2;
  }
  return y;
}

/****************/

int testkasper_three_dependent_accesses_ptr(int *** ptr1) {
  int ret = 0;
  int **ptr2, *ptr3;
  if(false_cond) {
    ptr2 = *ptr1;
    ptr3 = *ptr2;
    ret = *ptr3;
  }
  return ret;
}

/****************/

int testkasper_three_dependent_accesses(int * arr1, int * arr2, int arr1_size, int x) {
  int y = 0;
  if(x < arr1_size) {
    y = arr1[arr2[arr1[x] & 0] & 0]; // "& 0" hack to prevent subsequent access from going OOB
  }
  return y;
}

/****************/

int testkasper_newlabel_inspec(int * arr, int arr_size, int x) {
  int y = 0;
  dfsan_label tmp_label = dfsan_create_label("tmp-label", 0);
  dfsan_set_label(tmp_label, &y, sizeof(y));
  if(x < arr_size) {
    y = arr[x + y]; // a new label is created within speculation from the union
  }
  return y;
}

/****************/

// Should print 2 MDS reports
int testkasper_faulty_accesses(int * tainted_oob_ptr, int * wild_ptr) {
  // This should "speculatively" execute
  if(false_cond) {
    int a = *tainted_oob_ptr; // MDS report #1
    int x = *wild_ptr; // Faulty read
    *wild_ptr = 34; // Faulty write
    int b = *tainted_oob_ptr; // MDS report #2
    return a + b + x;
  }
  return 0;
}

/****************/

#define ARR_SIZE 64
#define BUF_ALLOC(buf) buf = kmalloc(sizeof(int)*ARR_SIZE,GFP_KERNEL)
#define BUF_FREE(buf) kfree(buf)

int glob_arr[ARR_SIZE] = { -1 };

void kdf_run_kasper_tests(void) {
  // Initialize data
  int arr1[ARR_SIZE], arr2[ARR_SIZE], attck_inbounds=4, attck_outofbounds=ARR_SIZE, clean_inbounds=7, clean_outofbounds=ARR_SIZE+1;
  int *tmp_buf, *tmp_buf2, attck_val = 34, clean_val = 45;
  for(int i = 0; i < ARR_SIZE; i++) { arr1[i] = arr2[i] = i; }
  false_cond = false;

  // Initialize labels
  dfsan_label attacker_label = dfsan_create_label("attacker-controlled", 0);
  printk("    KDFSan: Test attacker label = %d\n",attacker_label);
  dfsan_set_label(attacker_label, &attck_inbounds, sizeof(attck_inbounds));
  dfsan_set_label(attacker_label, &attck_outofbounds, sizeof(attck_outofbounds));
  dfsan_set_label(attacker_label, &attck_val, sizeof(attck_val));

  // Normal load tests
  printk("    KDFSan: Running load test with tainted in-bounds index...\n");
  BUF_ALLOC(tmp_buf); testkasper_load(tmp_buf,attck_inbounds); BUF_FREE(tmp_buf);
  printk("    KDFSan: Running load test with tainted out-of-bounds index... (SHOULD PRINT 1 MDS REPORT)\n");
  BUF_ALLOC(tmp_buf); testkasper_load(tmp_buf,attck_outofbounds); BUF_FREE(tmp_buf);
  printk("    KDFSan: Running load test with untainted in-bounds index...\n");
  BUF_ALLOC(tmp_buf); testkasper_load(tmp_buf,clean_inbounds); BUF_FREE(tmp_buf);
  printk("    KDFSan: Running load test with untainted out-of-bounds index... (xxx)\n");
  BUF_ALLOC(tmp_buf); testkasper_load(tmp_buf,clean_outofbounds); BUF_FREE(tmp_buf);

  // Normal store tests
  printk("    KDFSan: Running store test with untainted in-bounds index and untainted value...\n");
  BUF_ALLOC(tmp_buf); testkasper_store(tmp_buf,clean_inbounds,clean_val); BUF_FREE(tmp_buf);
  printk("    KDFSan: Running store test with untainted in-bounds index and tainted value...\n");
  BUF_ALLOC(tmp_buf); testkasper_store(tmp_buf,clean_inbounds,attck_val); BUF_FREE(tmp_buf);
  printk("    KDFSan: Running store test with untainted out-of-bounds index and tainted value... (xxx)\n");
  BUF_ALLOC(tmp_buf); testkasper_store(tmp_buf,clean_outofbounds,attck_val); BUF_FREE(tmp_buf);
  printk("    KDFSan: Running store test with tainted out-of-bounds index and untainted value... (SHOULD PRINT 1 MDS REPORT)\n");
  BUF_ALLOC(tmp_buf); testkasper_store(tmp_buf,attck_outofbounds,clean_val); BUF_FREE(tmp_buf);
  printk("    KDFSan: Running store test with tainted out-of-bounds index and tainted value... (SHOULD PRINT 1 MDS REPORT)\n");
  BUF_ALLOC(tmp_buf); testkasper_store(tmp_buf,attck_outofbounds,attck_val); BUF_FREE(tmp_buf);
  printk("    KDFSan: Running store test with untainted out-of-bounds index and untainted value... (xxx)\n");
  BUF_ALLOC(tmp_buf); testkasper_store(tmp_buf,clean_outofbounds,clean_val); BUF_FREE(tmp_buf);

  // Speculative load tests
  printk("    KDFSan: Running speculative load test with tainted in-bounds index...\n");
  testkasper_spec_load(arr1, ARR_SIZE, attck_inbounds);
  printk("    KDFSan: Running speculative load test with tainted out-of-bounds index... (SHOULD PRINT 1 MDS REPORT)\n");
  testkasper_spec_load(arr1, ARR_SIZE, attck_outofbounds);
  printk("    KDFSan: Running speculative load test with untainted in-bounds index...\n");
  testkasper_spec_load(arr1, ARR_SIZE, clean_inbounds);
  printk("    KDFSan: Running speculative load test with untainted out-of-bounds index... (xxx)\n");
  testkasper_spec_load(arr1, ARR_SIZE, clean_outofbounds);
  printk("    KDFSan: Running speculative load test with untainted *global* in-bounds index...\n");
  testkasper_spec_load(glob_arr, ARR_SIZE, clean_inbounds);
  printk("    KDFSan: Running speculative load test with tainted *global* out-of-bounds index... (SHOULD PRINT 1 MDS REPORT)\n");
  testkasper_spec_load(glob_arr, ARR_SIZE, attck_outofbounds);

  // Multiple-independent-accesses tests
  printk("    KDFSan: Running multiple-independent-accesses test with 1 (first) tainted out-of-bounds index... (SHOULD PRINT 1 MDS REPORT)\n");
  testkasper_independent_accesses(arr1,ARR_SIZE,attck_outofbounds,clean_inbounds);
  printk("    KDFSan: Running multiple-independent-accesses test with 1 (second) tainted out-of-bounds index... (SHOULD PRINT 1 MDS REPORT)\n");
  testkasper_independent_accesses(arr1,ARR_SIZE,clean_inbounds,attck_outofbounds);
  printk("    KDFSan: Running multiple-independent-accesses test with 2 (both) tainted out-of-bounds indices... (SHOULD PRINT 2 MDS REPORTS)\n");
  testkasper_independent_accesses(arr1,ARR_SIZE,attck_outofbounds,attck_outofbounds);

  // Two-dependent-accesses tests
  printk("    KDFSan: Running two-dependent-accesses test with untainted in-bounds index...\n");
  testkasper_two_dependent_accesses_arr(arr1,arr2,ARR_SIZE,clean_inbounds);
  printk("    KDFSan: Running two-dependent-accesses test with untainted out-of-bounds index to slab object... (xxx + 1 SLAB-MASSAGE-READ MDS REPORT)\n");
  BUF_ALLOC(tmp_buf); BUF_ALLOC(tmp_buf2); testkasper_two_dependent_accesses_arr(tmp_buf,tmp_buf2,ARR_SIZE,clean_outofbounds); BUF_FREE(tmp_buf); BUF_FREE(tmp_buf2);
  printk("    KDFSan: Running two-dependent-accesses test with untainted out-of-bounds index to stack object... (xxx + 1 STACK-MASSAGE-READ MDS REPORT)\n");
  testkasper_two_dependent_accesses_arr(arr1,arr2,ARR_SIZE,clean_outofbounds);
  printk("    KDFSan: Running two-dependent-accesses test with tainted in-bounds index...\n");
  testkasper_two_dependent_accesses_arr(arr1,arr2,ARR_SIZE,attck_inbounds);
  printk("    KDFSan: Running two-dependent-accesses test with tainted *stack* out-of-bounds index... (SHOULD PRINT 1 MDS REPORT + 1 CC REPORT)\n");
  testkasper_two_dependent_accesses_arr(arr1,arr2,ARR_SIZE,attck_outofbounds);
  printk("    KDFSan: Running two-dependent-accesses test with tainted *global* out-of-bounds index... (SHOULD PRINT 1 MDS REPORT + 1 CC REPORT)\n");
  testkasper_two_dependent_accesses_arr(glob_arr,arr2,ARR_SIZE,attck_outofbounds);

  // Three-dependent-accesses tests
  printk("    KDFSan: Running three-dependent-accesses test with untainted *slab* out-of-bounds index... (xxx + 1 MDS REPORT + 1 CC REPORT)\n");
  BUF_ALLOC(tmp_buf); BUF_ALLOC(tmp_buf2); testkasper_three_dependent_accesses(tmp_buf,tmp_buf2,ARR_SIZE,clean_outofbounds); BUF_FREE(tmp_buf); BUF_FREE(tmp_buf2);
  printk("    KDFSan: Running three-dependent-accesses test with tainted *slab* out-of-bounds index... (SHOULD PRINT 1 MDS REPORT + 2 CC REPORTS)\n");
  BUF_ALLOC(tmp_buf); BUF_ALLOC(tmp_buf2); testkasper_three_dependent_accesses(tmp_buf,tmp_buf2,ARR_SIZE,attck_outofbounds); BUF_FREE(tmp_buf); BUF_FREE(tmp_buf2);

  // New-label-in-spec test
  printk("    KDFSan: Running new-label-in-spec test... (SHOULD PRINT 1 MDS REPORT)\n");
  testkasper_newlabel_inspec(arr1, ARR_SIZE, attck_outofbounds);

  // Independent-page-faults-in-speculation test
  printk("    KDFSan: Running independent-page-fault test... (SHOULD PRINT 2 MDS REPORTS)\n");
  testkasper_faulty_accesses(&arr1[attck_outofbounds], (int*) 0x9876987698769876);

  // Dependent-page-faults-in-speculation test
  int** tainted_wild1 = (int**) 0xffffffffffffdead; dfsan_set_label(attacker_label, &tainted_wild1, sizeof(tainted_wild1));
  int** tainted_wild2 = (int**) 0x1234123412341234; dfsan_set_label(attacker_label, &tainted_wild2, sizeof(tainted_wild2));
  int** tainted_user = (int**) 0x00007fffdeaddead; dfsan_set_label(attacker_label, &tainted_user, sizeof(tainted_user));
  int** tainted_null = (int**) 0x0000000000000fff; dfsan_set_label(attacker_label, &tainted_null, sizeof(tainted_null));
  printk("    KDFSan: Running *tainted wild-mem* #1 dependent-page-fault test... (SHOULD PRINT 1 MDS REPORT + 1 CC REPORT)\n");
  testkasper_two_dependent_accesses_ptr(tainted_wild1);
  printk("    KDFSan: Running *tainted wild-mem* #2 dependent-page-fault test... (SHOULD PRINT 1 MDS REPORT + 1 CC REPORT)\n");
  testkasper_two_dependent_accesses_ptr(tainted_wild2);
  printk("    KDFSan: Running *tainted user-mem* dependent-page-fault test... (SHOULD PRINT 1 MDS REPORT + 1 CC REPORT)\n");
  testkasper_two_dependent_accesses_ptr(tainted_user);
  printk("    KDFSan: Running *tainted null-mem* dependent-page-fault test...\n");
  testkasper_two_dependent_accesses_ptr(tainted_null);

  // LVI test
  int** untainted_wild1 = (int**) 0xffffffffffffd00d;
  int** untainted_wild2 = (int**) 0x1234123412344321;
  int** untainted_user = (int**) 0x00007fffd00dd00d;
  int** untainted_null = (int**) 0x0000000000000bbb;
  // Two access
  printk("    KDFSan: Running *untainted wild-mem* #1 LVI two-access test... (SHOULD PRINT 1 MDS REPORT)\n");
  testkasper_two_dependent_accesses_ptr(untainted_wild1);
  printk("    KDFSan: Running *untainted wild-mem* #2 LVI two-access test... (SHOULD PRINT 1 MDS REPORT)\n");
  testkasper_two_dependent_accesses_ptr(untainted_wild2);
  printk("    KDFSan: Running *untainted user-mem* LVI two-access test... (SHOULD PRINT 1 MDS REPORT)\n");
  testkasper_two_dependent_accesses_ptr(untainted_user);
  printk("    KDFSan: Running *untainted null-mem* LVI two-access test...\n");
  testkasper_two_dependent_accesses_ptr(untainted_null);
  // Three access
  printk("    KDFSan: Running *untainted wild-mem* #1 LVI three-access test... (SHOULD PRINT 1 MDS REPORT + 1 CC REPORT)\n");
  testkasper_three_dependent_accesses_ptr((int***) untainted_wild1);
  printk("    KDFSan: Running *untainted wild-mem* #2 LVI three-access test... (SHOULD PRINT 1 MDS REPORT + 1 CC REPORT)\n");
  testkasper_three_dependent_accesses_ptr((int***) untainted_wild2);
  printk("    KDFSan: Running *untainted user-mem* LVI three-access test... (SHOULD PRINT 1 MDS REPORT + 1 CC REPORT)\n");
  testkasper_three_dependent_accesses_ptr((int***) untainted_user);
  printk("    KDFSan: Running *untainted null-mem* LVI three-access test...\n");
  testkasper_three_dependent_accesses_ptr((int***) untainted_null);

  printk("TODO: Wild-mem #1 ptrs above (%px and %px) are not reported because KASAN doesn't consider them 'wild-mem bugs'\n", tainted_wild1, untainted_wild1);

  // TODO: Add tests for OOB memtrasfers
  // TODO: Add tests running the kasan/specload/specv1 tests with heap and .data mem
}
