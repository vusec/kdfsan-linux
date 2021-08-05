#ifndef KDFSAN_POLICIES_H
#define KDFSAN_POLICIES_H

#include "kdfsan_types.h"

dfsan_label kdf_policy_get_usercopy_label(void);
void kdf_policy_syscall_arg(void * arg, size_t s, int arg_num);
void kdf_policy_usercopy(void * dst, size_t s, dfsan_label src_ptr_label);
void kdf_policies_init(void);


#endif // KDFSAN_POLICIES_H
