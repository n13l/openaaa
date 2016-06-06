#ifndef __ARCH_X86_TRAMP_H__
#define __ARCH_X86_TRAMP_H__

struct arch_tramp;

void
x86_call_intr_vec(unsigned char val);

#define arch_call_intr_vec(val) x86_call_intr_vec(val)

int
arch_tramp(struct arch_tramp *base, void *orig, void *hook);

void
linkmap_init(void);

#endif
