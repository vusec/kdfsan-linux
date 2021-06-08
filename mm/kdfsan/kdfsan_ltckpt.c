#ifndef CONFIG_LTCKPT

#include "kdfsan_types.h"

/********/
// Helpers

static size_t ltckpt_strlen(const char *s) {
  const char *sc;
  for (sc = s; *sc != '\0'; ++sc) { ; }
  return sc - s;
}

static int ltckpt_strncmp(const char *cs, const char *ct, int count) {
  unsigned char c1, c2;
  while (count) {
    c1 = *cs++;
    c2 = *ct++;
    if (c1 != c2) {
      return c1 < c2 ? -1 : 1;
    }
    if (!c1) {
      break;
    }
    count--;
  }
  return 0;
}

// Using https://www.geeksforgeeks.org/implement-itoa/
static void ltckpt_reverse_str(char str[], int length) {
  int start = 0;
  int end = length -1;
  while (start < end) {
    char tmp = *(str+end);
    *(str+end) = *(str+start);
    *(str+start) = tmp;
    start++;
    end--;
  }
}

/********/

// TODO: Fix this (right now it assumes syscall-number whitelisting AND task-name whitelisting)
int ltckpt_hook_is_whitelist_task(void) {
  unsigned long syscall_nr = ltckpt_syscall_get_nr();
  char *task_name = current->comm;
  if ((syscall_nr >= 600 && syscall_nr < 1200) ||
      ltckpt_strncmp(task_name, "kasper_task", ltckpt_strlen("kasper_task")) == 0 ||
      ltckpt_strncmp(task_name, "syz-executor", ltckpt_strlen("syz-executor")) == 0) {
    return 1;
  }
  return 0;
}

// TODO: Test this
noinline unsigned long ltckpt_syscall_get_nr(void) {
  unsigned long __ptr = (unsigned long)(current->stack);
  __ptr += THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
  return (((struct pt_regs *)__ptr) - 1)->orig_ax;
}

void ltckpt_hook_ridl_report(unsigned long addr, size_t size, bool is_write, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label) { }
void ltckpt_hook_specv1_report(unsigned long addr, size_t size, bool is_write, unsigned long ip, dfsan_label data_label, dfsan_label ptr_label) { }
void ltckpt_hook_memcpy(char *addr, size_t size) { }
void ltckpt_common_late_init(void) { }


size_t ltckpt_strlcat(char *dest, const char *src, size_t count) {
  size_t dsize = ltckpt_strlen(dest);
  size_t len = ltckpt_strlen(src);
  size_t res = dsize + len;
  BUG_ON(dsize < count); // This would be a bug
  dest += dsize;
  count -= dsize;
  if (len >= count) { len = count-1; }
  __memcpy(dest, src, len);
  dest[len] = 0;
  return res;
}

char* ltckpt_itoa(long long num, char* str, int base) {
  int i = 0;
  bool is_negative = false;
  if (num == 0) {
    str[i++] = '0';
    str[i] = '\0';
    return str;
  }
  if (num < 0 && base == 10) {
    is_negative = true;
    num = -num;
  }
  while (num != 0) {
    int rem = num % base;
    str[i++] = (rem > 9)? (rem-10) + 'a' : rem + '0';
    num = num/base;
  }
  if (is_negative) { str[i++] = '-'; }
  str[i] = '\0';
  ltckpt_reverse_str(str, i);
  return str;
}

#endif
