// SPDX-License-Identifier: GPL-2.0

// ----------------------------------------------------------------------------------------
// Define the types used, and specify as extern's the arrays, etc. we will access.
// Note that temp is used so that operations aren't optimized away.
//
// Compilation flags:  cl /c /d2guardspecload /O2 /Faout.asm
// Note: Per Microsoft's blog post, /d2guardspecload flag will be renamed /Qspectre
//
// This code is free under the MIT license (https://opensource.org/licenses/MIT), but
// is intentionally insecure so is only intended for testing purposes.

#include <linux/kdfsan.h>
#include <linux/string.h>
#include <linux/printk.h>

unsigned int array1_size = 16;
unsigned int array_size_mask = 15;
uint8_t array1[16];
uint8_t array2[256 * 512];
uint8_t temp = 0;

// ----------------------------------------------------------------------------------------
// EXAMPLE 1:  This is the sample function from the Spectre paper.
//
// Comments:  The generated assembly (below) includes an LFENCE on the vulnerable code
// path, as expected

void testkocher_victim_function_v01(size_t x) {
  // TODO test with this as global
  uint8_t array1[16];

  if (x < array1_size) {
    temp &= array2[array1[x] * 512];
  }
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 2:  Moving the leak to a local function that can be inlined.
//
// Comments:  Produces identical assembly to the example above (i.e. LFENCE is included)
// ----------------------------------------------------------------------------------------

void testkocher_leakByteLocalFunction_v02(uint8_t k) { temp &= array2[(k)* 512]; }
void testkocher_victim_function_v02(size_t x) {
  uint8_t array1[16];
  if (x < array1_size) {
    testkocher_leakByteLocalFunction_v02(array1[x]);
  }
}


// ----------------------------------------------------------------------------------------
// EXAMPLE 3:  Moving the leak to a function that cannot be inlined.
//
// Comments: Output is unsafe.  The same results occur if leakByteNoinlineFunction()
// is in another source module.

void noinline testkocher_leakByteNoinlineFunction(uint8_t k) { temp &= array2[(k)* 512]; }
void testkocher_victim_function_v03(size_t x) {
  uint8_t array1[16];
  if (x < array1_size)
    testkocher_leakByteNoinlineFunction(array1[x]);
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 4:  Add a left shift by one on the index.
//
// Comments: Output is unsafe.

void testkocher_victim_function_v04(size_t x) {
  uint8_t array1[16];
  if (x < array1_size)
    temp &= array2[array1[x << 1] * 512];
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 5:  Use x as the initial value in a for() loop.
//
// Comments: Output is unsafe.

int kdfinit_access_taint_sink1(const void * addr, size_t size, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label, bool is_write);

void testkocher_victim_function_v05(size_t x) {
  size_t i;
  uint8_t array1[16];
  if (x < array1_size) {
    for (i = x - 1; i >= 1; i--) {
      temp &= array2[array1[i] * 512];
    }
  }
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 6:  Check the bounds with an AND mask, rather than "<".
//
// Comments: Output is unsafe.

void testkocher_victim_function_v06(size_t x) {
  uint8_t array1[16];
  if ((x & array_size_mask) == x)
    temp &= array2[array1[x] * 512];
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 7:  Compare against the last known-good value.
//
// Comments: Output is unsafe.

void testkocher_victim_function_v07(size_t x) {
  uint8_t array1[16];
  static size_t last_x = 0;
  if (x == last_x)
    temp &= array2[array1[x] * 512];
  if (x < array1_size)
    last_x = x;
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 8:  Use a ?: operator to check bounds.

void testkocher_victim_function_v08(size_t x) {
  uint8_t array1[16];
  temp &= array2[array1[x < array1_size ? (x + 1) : 0] * 512];
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 9:  Use a separate value to communicate the safety check status.
//
// Comments: Output is unsafe.

void testkocher_victim_function_v09(size_t x, int *x_is_safe) {
  uint8_t array1[16];
  if (*x_is_safe)
    temp &= array2[array1[x] * 512];
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 10:  Leak a comparison result.
//
// Comments: Output is unsafe.  Note that this vulnerability is a little different, namely
// the attacker is assumed to provide both x and k.  The victim code checks whether
// array1[x] == k.  If so, the victim reads from array2[0].  The attacker can try
// values for k until finding the one that causes array2[0] to get brought into the cache.

void testkocher_victim_function_v10(size_t x, uint8_t k) {
  uint8_t array1[16];
  if (x < array1_size) {
    if (array1[x] == k)
      temp &= array2[0];
  }
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 11:  Use memcmp() to read the memory for the leak.
//
// Comments: Output is unsafe.

void testkocher_victim_function_v11(size_t x) {
  uint8_t array1[16];
  if (x < array1_size)
    temp = memcmp(&temp, array2 + (array1[x] * 512), 1);
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 12:  Make the index be the sum of two input parameters.
//
// Comments: Output is unsafe.

void testkocher_victim_function_v12(size_t x, size_t y) {
  uint8_t array1[16];
  if ((x + y) < array1_size)
    temp &= array2[array1[x + y] * 512];
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 13:  Do the safety check into an inline function
//
// Comments: Output is unsafe.

inline static int testkocher_is_x_safe(size_t x) { if (x < array1_size) return 1; return 0; }
void testkocher_victim_function_v13(size_t x) {
  uint8_t array1[16];
  if (testkocher_is_x_safe(x))
    temp &= array2[array1[x] * 512];
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 14:  Invert the low bits of x
//
// Comments: Output is unsafe.

void testkocher_victim_function_v14(size_t x) {
  uint8_t array1[16];
  if (x < array1_size)
    temp &= array2[array1[x ^ 255] * 512];
}

// ----------------------------------------------------------------------------------------
// EXAMPLE 15:  Pass a pointer to the length
//
// Comments: Output is unsafe.

void testkocher_victim_function_v15(size_t *x) {
  uint8_t array1[16];
  if (*x < array1_size)
    temp &= array2[array1[*x] * 512];
}

void kdf_run_kocher_tests(void) {
  printk("********************************************************************************************************************************\n");
  printk("********************************************************************************************************************************\n");
  printk("********************************************************************************************************************************\n");
  printk("********************************************************************************************************************************\n");
  printk("run kocher tests\n");
  memset(array1, 0x0, 16);
  size_t x = 16;

  dfsan_label attacker_label = dfsan_create_label("kocher-attacker-controlled", 0);
  printk("    KDFSan: Test kocher attacker label = %d\n",attacker_label);
  dfsan_set_label(attacker_label, &x, sizeof(x));

  testkocher_victim_function_v01(x);             // RIDL + SPECTRE V1
  testkocher_victim_function_v02(x);             // RIDL + SPECTRE V1
  testkocher_victim_function_v03(x);             // RIDL + SPECTRE V1
  testkocher_victim_function_v04(x + 64);        // RIDL + SPECTRE V1
  testkocher_victim_function_v05(x+2);           // RIDL + SPECTRE V1
  testkocher_victim_function_v06(x);             // RIDL + SPECTRE V1
  testkocher_victim_function_v07(x);             // RIDL + SPECTRE V1
  testkocher_victim_function_v08(x);             // RIDL + SPECTRE V1
  int x_is_safe = 0; testkocher_victim_function_v09(x, &x_is_safe); // RIDL + SPECTRE V1
  testkocher_victim_function_v10(x, 2);          // RIDL (comparison result is leaking)
  testkocher_victim_function_v11(x);             // RIDL + SPECTRE V1
  testkocher_victim_function_v12(x, 0);          // RIDL + SPECTRE V1
  testkocher_victim_function_v13(x);             // RIDL + SPECTRE V1
  testkocher_victim_function_v14(x ^ 255);       // RIDL + SPECTRE V1
  testkocher_victim_function_v15(&x);            // RIDL + SPECTRE V1

  printk("done kocher tests\n");
}
