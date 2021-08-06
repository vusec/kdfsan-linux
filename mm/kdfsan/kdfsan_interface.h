#ifndef KDFSAN_INTERFACE_H
#define KDFSAN_INTERFACE_H

#include "kdfsan_types.h"
#include "kdfsan_util.h"

// TODO!!! Probably should put set_rt after preempt_disable/local_irq_save/stop_nmi and
// unset_rt before restart_nmi/local_irq_restore/preempt_enable. This would probably require
// disabling instrumentation for arch/x86/kernel/nmi.c (at least). For now, we'll set/unset_rt
// from outside of the non-pre-emptable state, at the risk of losing KDFSan coverage, i.e.,
// because KDFSan would be disabled during an interrupt e.g., between set_rt() and preempt_disable()

void kdfsan_interface_preinit(void);
void kdf_init_finished(void);

#endif // KDFSAN_INTERFACE_H
