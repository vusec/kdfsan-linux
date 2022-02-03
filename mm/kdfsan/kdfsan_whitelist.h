#ifndef KDFSAN_WHITELIST_H
#define KDFSAN_WHITELIST_H

typedef enum {
  KDFSAN_WHITELIST_DISABLED = 0,
  KDFSAN_WHITELIST_TASKNAME,
  KDFSAN_WHITELIST_SYSCALLNR,
  __NUM_KDFSAN_WHITELIST_TYPES,
} kdfsan_whitelist_type_t;

bool kdf_is_whitelist_task(void);

#endif
