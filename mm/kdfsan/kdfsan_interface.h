// SPDX-License-Identifier: GPL-2.0

#ifndef KDFSAN_INTERFACE_H
#define KDFSAN_INTERFACE_H

#include "kdfsan_types.h"

// TODO!!! Probably should put set_rt after preempt_disable/local_irq_save/stop_nmi and
// unset_rt before restart_nmi/local_irq_restore/preempt_enable. This would probably require
// disabling instrumentation for arch/x86/kernel/nmi.c (at least). For now, we'll set/unset_rt
// from outside of the non-pre-emptable state, at the risk of losing KDFSan coverage, i.e.,
// because KDFSan would be disabled during an interrupt e.g., between set_rt() and preempt_disable()

extern bool kdf_is_init_done;
extern bool kdf_is_in_rt;
void set_rt(void);
void unset_rt(void);

#define CHECK_RT(default_ret) do { if(!kdf_is_init_done || kdf_is_in_rt) { return default_ret; } } while(0)

#define CHECK_ONLY_IN_RT(default_ret) do { if(kdf_is_in_rt) { return default_ret; } } while(0)

#define ENTER_RT(default_ret) \
    unsigned long __irq_flags; \
    do { \
        CHECK_RT(default_ret); \
        set_rt(); \
        preempt_disable(); \
        local_irq_save(__irq_flags); \
        stop_nmi(); \
    } while(0)

#define LEAVE_RT() \
    do { \
        KDF_PANIC_ON(!irqs_disabled(), "KDFSan error! IRQs should be disabled within the runtime!"); \
        restart_nmi(); \
        local_irq_restore(__irq_flags); \
        preempt_enable(); \
        unset_rt(); \
    } while(0)

#define ENTER_NOINIT_RT(default_ret) \
  unsigned long __irq_flags; \
	do { \
        CHECK_ONLY_IN_RT(default_ret); \
        set_rt(); \
        preempt_disable(); \
        local_irq_save(__irq_flags); \
        stop_nmi(); \
	} while(0)

#define LEAVE_NOINIT_RT() LEAVE_RT()

#endif // KDFSAN_INTERFACE_H
