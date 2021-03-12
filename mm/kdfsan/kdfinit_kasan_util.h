// SPDX-License-Identifier: GPL-2.0

#ifndef KDFINIT_KASAN_UTIL_H
#define KDFINIT_KASAN_UTIL_H

#include "kdfinit_types.h"
#include <linux/kasan.h> // i.e., include/linux/kasan.h
#include "../kasan/kasan.h" // i.e., mm/kasan/kasan.h

// Below copied from mm/kasan/kasan.c and mm/kasan/report.c

static __always_inline const void *kdf_find_first_bad_addr(const void *addr, size_t size)
{
	u8 shadow_val = *(u8 *)kasan_mem_to_shadow(addr);
	const void *first_bad_addr = addr;

	while (!shadow_val && first_bad_addr < addr + size) {
		first_bad_addr += KASAN_GRANULE_SIZE;
		shadow_val = *(u8 *)kasan_mem_to_shadow(first_bad_addr);
	}
	return first_bad_addr;
}

static __always_inline bool kdf_kasan_memory_is_poisoned_1(unsigned long addr)
{
  s8 shadow_value = *(s8 *)kasan_mem_to_shadow((void *)addr);

  if (unlikely(shadow_value)) {
    s8 last_accessible_byte = addr & KASAN_GRANULE_MASK;
    return unlikely(last_accessible_byte >= shadow_value);
  }

  return false;
}

static __always_inline bool kdf_kasan_memory_is_poisoned_2_4_8(unsigned long addr,
            unsigned long size)
{
  u8 *shadow_addr = (u8 *)kasan_mem_to_shadow((void *)addr);

  /*
   * Access crosses 8(shadow size)-byte boundary. Such access maps
   * into 2 shadow bytes, so we need to check them both.
   */
  if (unlikely(((addr + size - 1) & KASAN_GRANULE_MASK) < size - 1))
    return *shadow_addr || kdf_kasan_memory_is_poisoned_1(addr + size - 1);

  return kdf_kasan_memory_is_poisoned_1(addr + size - 1);
}

static __always_inline bool kdf_kasan_memory_is_poisoned_16(unsigned long addr)
{
  u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);

  /* Unaligned 16-bytes access maps into 3 shadow bytes. */
  if (unlikely(!IS_ALIGNED(addr, KASAN_GRANULE_SIZE)))
    return *shadow_addr || kdf_kasan_memory_is_poisoned_1(addr + 15);

  return *shadow_addr;
}

static __always_inline unsigned long kdf_kasan_bytes_is_nonzero(const u8 *start,
          size_t size)
{
  while (size) {
    if (unlikely(*start))
      return (unsigned long)start;
    start++;
    size--;
  }

  return 0;
}

static __always_inline unsigned long kdf_kasan_memory_is_nonzero(const void *start,
            const void *end)
{
  unsigned int words;
  unsigned long ret;
  unsigned int prefix = (unsigned long)start % 8;

  if (end - start <= 16)
    return kdf_kasan_bytes_is_nonzero(start, end - start);

  if (prefix) {
    prefix = 8 - prefix;
    ret = kdf_kasan_bytes_is_nonzero(start, prefix);
    if (unlikely(ret))
      return ret;
    start += prefix;
  }

  words = (end - start) / 8;
  while (words) {
    if (unlikely(*(u64 *)start))
      return kdf_kasan_bytes_is_nonzero(start, 8);
    start += 8;
    words--;
  }

  return kdf_kasan_bytes_is_nonzero(start, (end - start) % 8);
}

static __always_inline bool kdf_kasan_memory_is_poisoned_n(unsigned long addr,
            size_t size)
{
  unsigned long ret;

  ret = kdf_kasan_memory_is_nonzero(kasan_mem_to_shadow((void *)addr),
      kasan_mem_to_shadow((void *)addr + size - 1) + 1);

  if (unlikely(ret)) {
    unsigned long last_byte = addr + size - 1;
    s8 *last_shadow = (s8 *)kasan_mem_to_shadow((void *)last_byte);

    if (unlikely(ret != (unsigned long)last_shadow ||
      ((long)(last_byte & KASAN_GRANULE_MASK) >= *last_shadow)))
      return true;
  }
  return false;
}

static __always_inline bool kdf_kasan_memory_is_poisoned(unsigned long addr, size_t size)
{
  if (__builtin_constant_p(size)) {
    switch (size) {
    case 1:
      return kdf_kasan_memory_is_poisoned_1(addr);
    case 2:
    case 4:
    case 8:
      return kdf_kasan_memory_is_poisoned_2_4_8(addr, size);
    case 16:
      return kdf_kasan_memory_is_poisoned_16(addr);
    default:
      BUILD_BUG();
    }
  }

  return kdf_kasan_memory_is_poisoned_n(addr, size);
}

// "Wild bug" == wild-mem-access or user-mem-access or null-ptr-deref
static __always_inline bool kdfinit_is_wild_bug(const void * addr, size_t size) {
  return size != 0 && (addr < kasan_shadow_to_mem((void *)KASAN_SHADOW_START) || addr + size < addr);
}

static __always_inline bool kdfinit_is_oob_uaf_bug(const void * addr, size_t size) {
  return size != 0 && !kdfinit_is_wild_bug(addr, size) && kdf_kasan_memory_is_poisoned((unsigned long)addr, size);
}

static __always_inline bool kdfinit_is_kasan_bug(const void * addr, size_t size) {
  return kdfinit_is_wild_bug(addr, size) || kdfinit_is_oob_uaf_bug(addr, size);
}

// Copied mostly from get_shadow_bug_type in mm/kasan/report.c
typedef enum {KDF_KASAN_ERR, KDF_KASAN_SLAB_MEM, KDF_KASAN_STACK_MEM, KDF_KASAN_GLOBAL_MEM, KDF_KASAN_USER_MEM, KDF_KASAN_WILD_MEM, KDF_KASAN_NULL_MEM} kdfinit_access_enum;

static __always_inline kdfinit_access_enum kdfinit_kasan_shadow_access_type(const void * addr, size_t size) {
  // Error: this should only be called for oob/uaf bugs
  if(!kdfinit_is_oob_uaf_bug(addr, size)) {
    return KDF_KASAN_ERR;
  }

  u8 *shadow_addr = (u8 *)kasan_mem_to_shadow(kdf_find_first_bad_addr(addr, size));

  // If shadow byte value is in [0, KASAN_KASAN_GRANULE_SIZE) we can look at the next shadow byte to determine the type of the bad access.
  if (*shadow_addr > 0 && *shadow_addr <= KASAN_GRANULE_SIZE - 1) {
    shadow_addr++;
  }

  switch (*shadow_addr) {
    case KASAN_PAGE_REDZONE:
    case KASAN_KMALLOC_REDZONE:
    case KASAN_FREE_PAGE:
    case KASAN_KMALLOC_FREE:
      return KDF_KASAN_SLAB_MEM;
    case KASAN_STACK_LEFT:
    case KASAN_STACK_MID:
    case KASAN_STACK_RIGHT:
    case KASAN_STACK_PARTIAL:
    case KASAN_ALLOCA_LEFT:
    case KASAN_ALLOCA_RIGHT:
      return KDF_KASAN_STACK_MEM;
    case KASAN_GLOBAL_REDZONE:
      return KDF_KASAN_GLOBAL_MEM;
  }

  return KDF_KASAN_ERR;
}

static __always_inline bool kdfinit_is_nullmem_access(const void * addr) {
  return (unsigned long) addr < PAGE_SIZE;
}

static __always_inline bool kdfinit_is_usermem_access(const void * addr) {
  return (unsigned long) addr >= PAGE_SIZE && (unsigned long) addr < TASK_SIZE;
}

static __always_inline bool kdfinit_is_wildmem_access(const void * addr, size_t size) {
  return kdfinit_is_wild_bug(addr, size) && (unsigned long) addr >= TASK_SIZE;
}

static __always_inline bool kdfinit_is_datamem_access(const void * addr, size_t size) {
  return size != 0 && (
      (addr >= (const void *)__start_rodata && addr < (const void *)__end_rodata) ||
      (addr >= (const void *)_sdata         && addr < (const void *)_edata) ||
      (addr >= (const void *)__bss_start    && addr < (const void *)__bss_stop));
}

static __always_inline bool kdfinit_is_stackmem_access(const void * addr, size_t size) {
  // From check_stack_object in mm/usercopy.c
  const void * const stack = current->stack;
  const void * const stackend = stack + THREAD_SIZE;
  if (addr + size <= stack || stackend <= addr) return false;
  return true;
}

static __always_inline bool kdfinit_is_slabmem_access(const void * addr, size_t size) {
  // From check_heap_object in mm/usercopy.c
  if(!kdf_virt_addr_valid((void*)addr)) return false;
  if(PageSlab(compound_head(virt_to_page((void *)addr)))) return true;
  return false;
}

static __always_inline kdfinit_access_enum kdfinit_access_type(const void * addr, size_t size) {
  if(kdfinit_is_nullmem_access(addr)) return KDF_KASAN_NULL_MEM;
  if(kdfinit_is_usermem_access(addr)) return KDF_KASAN_USER_MEM;
  if(kdfinit_is_wildmem_access(addr, size)) return KDF_KASAN_WILD_MEM;
  if(kdfinit_is_datamem_access(addr, size)) return KDF_KASAN_GLOBAL_MEM;
  if(kdfinit_is_stackmem_access(addr, size)) return KDF_KASAN_STACK_MEM;
  if(kdfinit_is_slabmem_access(addr, size)) return KDF_KASAN_SLAB_MEM;
  return kdfinit_kasan_shadow_access_type(addr, size); // If the above checks don't work, we can still use a good old KASAN check
}

#endif // KDFINIT_KASAN_UTIL_H
