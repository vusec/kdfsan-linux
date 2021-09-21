#include "kdfsan_types.h"

size_t kdf_util_strlen(const char *s) {
  const char *sc;
  for (sc = s; *sc != '\0'; ++sc) { ; }
  return sc - s;
}

int kdf_util_strncmp(const char *cs, const char *ct, int count) {
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

size_t kdf_util_strlcat(char *dest, const char *src, size_t count) {
  size_t dsize = kdf_util_strlen(dest);
  size_t len = kdf_util_strlen(src);
  size_t res = dsize + len;
  BUG_ON(dsize >= count); // This would be a bug
  dest += dsize;
  count -= dsize;
  if (len >= count) { len = count-1; }
  __memcpy(dest, src, len);
  dest[len] = 0;
  return res;
}

static void kdf_util_reverse_str(char str[], int length) {
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

char* kdf_util_itoa(long long num, char* str, int base) {
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
  kdf_util_reverse_str(str, i);
  return str;
}

size_t kdf_util_strlcpy(char *dest, const char *src, size_t size) {
  size_t ret = kdf_util_strlen(src);
  if (size) {
    size_t len = (ret >= size) ? size - 1 : ret;
    __memcpy(dest, src, len);
    dest[len] = '\0';
  }
  return ret;
}

int kdf_util_memcmp (const void *cs, const void *ct, size_t count) {
  const unsigned char *su1, *su2;
  int res = 0;
  for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
  if ((res = *su1 - *su2) != 0)
    break;
  return res;
}

int kdf_util_strcmp(const char *cs, const char *ct) {
  unsigned char c1, c2;
  while (1) {
    c1 = *cs++;
    c2 = *ct++;
    if (c1 != c2)
      return c1 < c2 ? -1 : 1;
    if (!c1)
      break;
  }
  return 0;
}

// TODO: Fix this (right now it assumes syscall-number whitelisting AND task-name whitelisting)
int kdf_util_hook_is_whitelist_task(void) {
  unsigned long syscall_nr = kdf_util_syscall_get_nr();
  char *task_name = current->comm;
  if ((syscall_nr >= 600 && syscall_nr < 1200) ||
      kdf_util_strncmp(task_name, "kdfsan_task", kdf_util_strlen("kdfsan_task")) == 0 ||
      kdf_util_strncmp(task_name, "syz-executor", kdf_util_strlen("syz-executor")) == 0) {
    return 1;
  }
  return 0;
}

noinline unsigned long kdf_util_syscall_get_nr(void) {
  return syscall_get_nr(current, task_pt_regs(current));
}