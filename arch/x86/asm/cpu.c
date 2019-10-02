/*
 * The MIT License (MIT)         
 *
 * Copyright (c) 2015 Daniel Kubec <niel@rtfm.cz>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/log.h>
#include <cpuid.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#undef KBUILD_MODNAME
#define KBUILD_MODNAME KBUILD_STR(x86)

/* X86 Vendor %ebx, %edx, %ecx signatures */
#define X86_EBX_AMD               0x68747541
#define X86_EDX_AMD               0x69746e65
#define X86_ECX_AMD               0x444d4163
#define X86_EBX_CENTAUR           0x746e6543
#define X86_EDX_CENTAUR           0x48727561
#define X86_ECX_CENTAUR           0x736c7561
#define X86_EBX_CYRIX             0x69727943
#define X86_EDX_CYRIX             0x736e4978
#define X86_ECX_CYRIX             0x64616574
#define X86_EBX_INTEL             0x756e6547
#define X86_EDX_INTEL             0x49656e69
#define X86_ECX_INTEL             0x6c65746e
#define X86_EBX_TM1               0x6e617254
#define X86_EDX_TM1               0x74656d73
#define X86_ECX_TM1               0x55504361
#define X86_EBX_TM2               0x756e6547
#define X86_EDX_TM2               0x54656e69
#define X86_ECX_TM2               0x3638784d
#define X86_EBX_NSC               0x646f6547
#define X86_EDX_NSC               0x43534e20
#define X86_ECX_NSC               0x79622065
#define X86_EBX_NEXGEN            0x4778654e
#define X86_EDX_NEXGEN            0x72446e65
#define X86_ECX_NEXGEN            0x6e657669
#define X86_EBX_RISE              0x65736952
#define X86_EDX_RISE              0x65736952
#define X86_ECX_RISE              0x65736952
#define X86_EBX_SIS               0x20536953
#define X86_EDX_SIS               0x20536953
#define X86_ECX_SIS               0x20536953
#define X86_EBX_UMC               0x20434d55
#define X86_EDX_UMC               0x20434d55
#define X86_ECX_UMC               0x20434d55
#define X86_EBX_VIA               0x20414956
#define X86_EDX_VIA               0x20414956
#define X86_ECX_VIA               0x20414956
#define X86_EBX_VORTEX            0x74726f56
#define X86_EDX_VORTEX            0x36387865
#define X86_ECX_VORTEX            0x436f5320
           
/* X86 Features in %ecx for level 1 */
#define X86_BIT_SSE3              0x00000001
#define X86_BIT_PCLMULQDQ         0x00000002
#define X86_BIT_DTES64            0x00000004
#define X86_BIT_MONITOR           0x00000008
#define X86_BIT_DSCPL             0x00000010
#define X86_BIT_VMX               0x00000020
#define X86_BIT_SMX               0x00000040
#define X86_BIT_EIST              0x00000080
#define X86_BIT_TM2               0x00000100
#define X86_BIT_SSSE3             0x00000200
#define X86_BIT_CNXTID            0x00000400
#define X86_BIT_FMA               0x00001000
#define X86_BIT_CMPXCHG16B        0x00002000
#define X86_BIT_xTPR              0x00004000
#define X86_BIT_PDCM              0x00008000
#define X86_BIT_PCID              0x00020000
#define X86_BIT_DCA               0x00040000
#define X86_BIT_SSE41             0x00080000
#define X86_BIT_SSE42             0x00100000
#define X86_BIT_x2APIC            0x00200000
#define X86_BIT_MOVBE             0x00400000
#define X86_BIT_POPCNT            0x00800000
#define X86_BIT_TSCDeadline       0x01000000
#define X86_BIT_AESNI             0x02000000
#define X86_BIT_XSAVE             0x04000000
#define X86_BIT_OSXSAVE           0x08000000
#define X86_BIT_AVX               0x10000000
#define X86_BIT_RDRND             0x40000000

/* X86 Features in %edx for level 1 */
#define X86_BIT_FPU               0x00000001
#define X86_BIT_VME               0x00000002
#define X86_BIT_DE                0x00000004
#define X86_BIT_PSE               0x00000008
#define X86_BIT_TSC               0x00000010
#define X86_BIT_MSR               0x00000020
#define X86_BIT_PAE               0x00000040
#define X86_BIT_MCE               0x00000080
#define X86_BIT_CX8               0x00000100
#define X86_BIT_APIC              0x00000200
#define X86_BIT_SEP               0x00000800
#define X86_BIT_MTRR              0x00001000
#define X86_BIT_PGE               0x00002000
#define X86_BIT_MCA               0x00004000
#define X86_BIT_CMOV              0x00008000
#define X86_BIT_PAT               0x00010000
#define X86_BIT_PSE36             0x00020000
#define X86_BIT_PSN               0x00040000
#define X86_BIT_CLFSH             0x00080000
#define X86_BIT_DS                0x00200000
#define X86_BIT_ACPI              0x00400000
#define X86_BIT_MMX               0x00800000
#define X86_BIT_FXSR              0x01000000
#define X86_BIT_SSE               0x02000000
#define X86_BIT_SSE2              0x04000000
#define X86_BIT_SS                0x08000000
#define X86_BIT_HTT               0x10000000
#define X86_BIT_TM                0x20000000
#define X86_BIT_PBE               0x80000000

/* X86 Features in %ebx for level 7 sub-leaf 0 */
#define X86_BIT_FSGSBASE          0x00000001
#define X86_BIT_SMEP              0x00000080
#define X86_BIT_ENH_MOVSB         0x00000200

enum x86_vendor_type {
	X86_VENDOR_UNKNOWN,
	X86_VENDOR_INTEL,
	X86_VENDOR_AMD,
	X86_VENDOR_CYRIX,
	X86_VENDOR_VIA,
	X86_VENDOR_NEXGEN,
	X86_VENDOR_RISE,
	X86_VENDOR_SIS,
	X86_VENDOR_NSC,
	X86_VENDOR_VORTEX,
};

enum x86_hypervisor_type {
	X86_HYPERVISOR_UNKNOWN,
	X86_HYPERVISOR_VMWARE,
	X86_HYPERVISOR_XEN,
	X86_HYPERVISOR_KVM,
	X86_HYPERVISOR_MICROSOFT,
};

struct x86_vendor {
	u32 idx, ebx, ecx, edx;
};

#define DEFINE_X86_VENDOR(name) \
	{ .idx = X86_VENDOR_##name, \
	  .ebx = X86_EBX_##name,\
	  .ecx = X86_ECX_##name, \
	  .edx = X86_EDX_##name }

static struct x86_vendor x86_vendor[] = {
	DEFINE_X86_VENDOR(INTEL),
	DEFINE_X86_VENDOR(AMD),
	DEFINE_X86_VENDOR(CYRIX),
	DEFINE_X86_VENDOR(VIA),
	DEFINE_X86_VENDOR(NEXGEN),
	DEFINE_X86_VENDOR(RISE),
	DEFINE_X86_VENDOR(SIS),
	DEFINE_X86_VENDOR(NSC),
	DEFINE_X86_VENDOR(VORTEX),
};

static const char * const x86_vendor_names[] = {
	[X86_VENDOR_UNKNOWN]       = "unknown",
	[X86_VENDOR_INTEL]         = "intel",
	[X86_VENDOR_AMD]           = "amd",
	[X86_VENDOR_CYRIX]         = "cyrix",
	[X86_VENDOR_VIA]           = "via",
	[X86_VENDOR_NEXGEN]        = "nexgen",
	[X86_VENDOR_RISE]          = "rise",
	[X86_VENDOR_SIS]           = "sis",
	[X86_VENDOR_NSC]           = "nsc",
	[X86_VENDOR_VORTEX]        = "vortex",
};

_unused static const char * const x86_hypervisor_names[] = {
	[X86_HYPERVISOR_UNKNOWN]   = "unknown",
	[X86_HYPERVISOR_VMWARE]    = "vmware",
	[X86_HYPERVISOR_XEN]       = "xen",
	[X86_HYPERVISOR_KVM]       = "kvm",
	[X86_HYPERVISOR_MICROSOFT] = "microsoft"
};
	
const char *
cpu_vendor(void)
{
	u32 eax, ebx, ecx, edx;
	__get_cpuid(0, &eax, &ebx, &ecx, &edx);

	for (int i = 0; i < array_size(x86_vendor); i++) {
		struct x86_vendor *cpu = &x86_vendor[i];
		if (cpu->ebx != ebx || cpu->ecx != ecx || cpu->edx != edx)
			continue;

		return x86_vendor_names[cpu->idx];
	}

	return NULL;
}

int
cpu_has_crc32c(void)
{
	u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
	__get_cpuid(1, &eax, &ebx, &ecx, &edx);    
	return ecx & X86_BIT_SSE42 ? 1 : 0;
}

int
cpu_has_cap(int capability)
{
	switch (capability) {
	case CPU_CAP_CRYPTO_CRC32C:
		return cpu_has_crc32c();
	default:
		return 0;	
	}
	return 0;
}

_unused static inline 
unsigned long long cpu_getcycles(void)
{
	unsigned hi, lo;
	__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
	return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

void
cpu_info(void)
{
	u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
	__get_cpuid(1, &eax, &ebx, &ecx, &edx);    
/*
	debug("cpu.stepping %d", eax & 0xF);
	debug("cpu.model %d", (eax >> 4) & 0xF);
	debug("cpu.family %d", (eax >> 8) & 0xF);
	debug("cpu.processor type %d", (eax >> 12) & 0x3);
	debug("cpu.extended model %d", (eax >> 16) & 0xF);
	debug("cpu.extended family %d", (eax >> 20) & 0xFF);
*/
	debug1("cpu.vendor=%s", cpu_vendor());
	debug1("cpu.arch=%s", CONFIG_ARCH);
	debug1("cpu.bits=%d", sizeof(void *) == 8 ? 64 : 32);
	debug1("cpu.pagesize=%d", CPU_PAGE_SIZE);
	debug1("cpu.cacheline=%d",  L1_CACHE_BYTES);

	debug1("cpu.has.crc32c=%d", cpu_has_crc32c());

	debug1("cpu.has.sse4.2=%s", ecx & X86_BIT_SSE42 ? "yes" : "no");
	if (ecx & X86_BIT_SSE42)
		return;

	debug1("cpu.has.sse4.1=%s", ecx & X86_BIT_SSE41 ? "yes" : "no");
	if (ecx & X86_BIT_SSE41)
		return;
	
	debug1("cpu.has.sse3=%s",   ecx & X86_BIT_SSE3  ? "yes" : "no");
	if (ecx & X86_BIT_SSE3)
		return;
	
	debug1("cpu.has.sse2=%s",   ecx & X86_BIT_SSE2  ? "yes" : "no");
	if (ecx & X86_BIT_SSE2)
		return;
	
	debug1("cpu.has.sse=%s", ecx & X86_BIT_SSE ? "yes" : "no");
	if (ecx & X86_BIT_SSE)
		return;
}
