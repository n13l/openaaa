
#include <sys/compiler.h>
#include <sys/cpu.h>
#include <sys/mman.h>
#include <asm/udis86.h>
#include <asm/atomic_mov64.h>
#include <asm/cache.h>
#include <asm/instr.h>
#include <mem/page.h>

#include <mach-o/dyld.h>
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#include <mach/error.h>
#include <mach/mach_error.h>

#include <CoreServices/CoreServices.h>

// 64-bit ASLR is in bits 13-28                                         
#define ASLR_FIRST(addr) \
	((u64)addr & ~( (0xFUL << 28) | (PAGE_SIZE - 1) ) ) | (0x1UL << 31)
#define ASLR_LAST(addr) \
	((u64)addr & ~((0x1UL << 32) - 1))

#define BRANCH_SIZE 32
#define BRANCH_JMP_ADDR    BRANCH_SIZE + 6

static byte branch_head[] = {
	I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, 
	I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, I_NOP,
	I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, 
	I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, I_NOP, I_NOP,
	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
};

struct trampoline {
	char instrs[sizeof(branch_head)];
	int dummy;
};

struct trampoline *
mach_tramp_alloc(void *addr);

mach_error_t
mach_tramp_free(struct trampoline *island);

mach_error_t                                                                    
mach_tramp_branch(struct trampoline *island, const void *to, char *instructions);

int
x86_prologue(                                                           
u8 *code,                                                                       
u64 *ninstr,                                                            
int *eaten,                                                              
s8 *instr,                                                       
int *count,                                                  
u8 *sizes );

static void                                                                     
fixupInstr(                                                              
void *originalFunction,                                                         
void *escape,                                                             
void *instructionsToFix,                                                        
int instructionCount,                                                           
u8 *instructionSizes);

struct arch_trampoline *                                                        
mach_trampoline(void *org, void *act)
{
	void *addr = org;
	void *overrideFunctionAddress = act;

	for(;;) {
		if(*(u16*)addr==0x25FF)    // jmp qword near [rip+0x????????]
			addr=*(void**)((char*)addr+6+*(u32*)((u16*)addr+1));
		else break;
	}

	long *originalFunctionPtr = (long*) addr;
	
	int eatenCount = 0;
	int count = 0;
	char instr[BRANCH_SIZE];
	u8 sizes[BRANCH_SIZE];
	u64 instr_jmp_rel = 0; // JMP
	int err;

	struct x86_prologue prologue;

	x86_branch_prologue(&prologue, (u8 *)originalFunctionPtr, 5);

	if ((x86_prologue ((u8*)originalFunctionPtr, &instr_jmp_rel, 
	    &eatenCount, instr, &count, sizes )))
		return NULL;

	if (eatenCount > BRANCH_SIZE)
		return NULL;

	err = vm_protect( mach_task_self(),
				(vm_address_t) originalFunctionPtr, 8, false,
				(VM_PROT_ALL | VM_PROT_COPY) );
	if( err )
	err = vm_protect( mach_task_self(),
					(vm_address_t) originalFunctionPtr, 8, false,
					(VM_PROT_DEFAULT | VM_PROT_COPY) );
	
	struct trampoline *escape = mach_tramp_alloc(addr);
	err = mach_tramp_branch(escape, overrideFunctionAddress, 0 );
 
	u32 addr_off = ((u8*)escape - (u8*)originalFunctionPtr - 5);
	addr_off = bswap32(addr_off);
		
	instr_jmp_rel |= 0xE900000000000000LL; 
	instr_jmp_rel |= ((u64)addr_off & 0xffffffff) << 24;
	instr_jmp_rel = bswap64(instr_jmp_rel);		
	
	struct trampoline *reentry = NULL;
	reentry = mach_tramp_alloc(escape);
	
	fixupInstr(originalFunctionPtr, reentry, instr,
	                  count, sizes );
	
	if( reentry )
		err = mach_tramp_branch( reentry,
		(void*)((u8*)originalFunctionPtr+eatenCount), instr );

	if ((err = page_addr_protect(escape, PROT_EXEC | PROT_READ)))
		goto cleanup;

	if ((err = page_addr_protect(reentry, PROT_EXEC | PROT_READ)))
		goto cleanup;

	atomic_mov64((u64*)originalFunctionPtr, instr_jmp_rel);
	mach_error_t prot_err = err_none;
	prot_err = vm_protect(mach_task_self(),
	                      (vm_address_t) originalFunctionPtr, 8, false,
	                      (VM_PROT_READ | VM_PROT_EXECUTE) );

	return (struct arch_trampoline *)reentry;

cleanup:
	if( reentry )
		mach_tramp_free( reentry );
	if( escape )
		mach_tramp_free( escape );

	return NULL;
}

struct trampoline *
mach_tramp_alloc(void *addr)
{
	__build_bug_on(sizeof (struct trampoline) > PAGE_SIZE);

	mach_error_t err = err_none;
	vm_address_t first = ASLR_FIRST(addr);
	vm_address_t last  = ASLR_LAST(addr);
	vm_address_t page  = first;

	int allocated = 0;
	vm_map_t self = mach_task_self();

	while( !err && !allocated && page != last ) {
		err = vm_allocate(self, &page, PAGE_SIZE, 0 );
		if (err == err_none)
			allocated = 1;
		else if (err == KERN_NO_SPACE) {
			page -= PAGE_SIZE;
			err = err_none;
		}
	}

	if (!allocated || err)
		return NULL;

	return (struct trampoline*) page;
}

mach_error_t
mach_tramp_free(struct trampoline *island )
{
	mach_error_t err = err_none;
	err = vm_deallocate(mach_task_self(), (vm_address_t)island, PAGE_SIZE);
	
	return err;
}

mach_error_t
mach_tramp_branch(struct trampoline *island, const void *to, char *instrs)
{
    memcpy(island->instrs, branch_head, sizeof(branch_head));

    if (instrs)
        memcpy(island->instrs, instrs, BRANCH_SIZE);

    *((u64*)(island->instrs + BRANCH_JMP_ADDR)) = (u64)to; 
    msync(island->instrs, sizeof(branch_head), MS_INVALIDATE );

    return err_none;
}

int
x86_prologue(u8 *code, u64 *ninstr, int *eaten, s8 *instr, int *count, u8 *sizes)
{
	assert(!(*count));
	assert(!(*eaten));

	int total = 0, index = 0, remains = 5; // a JMP instruction takes 5 bytes

	ud_t ud_obj;
	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 64);
	ud_set_input_buffer(&ud_obj, code, 64);

	while (remains > 0) {
		if (!ud_disassemble(&ud_obj))
		    return -1;
		
		int eaten = ud_insn_len(&ud_obj);
		remains -= eaten;
		total += eaten;
		
		if (sizes) sizes[index] = eaten;
		index += 1;
		if (count) *count = index;
	}


	if (eaten) *eaten = total;

	if (instr) {
		if ((total < BRANCH_SIZE)) {
			memset(instr, I_NOP /* NOP */, BRANCH_SIZE); 
			memcpy(instr, code, total);
		} else {
			return -1;
		}
	}
	
	// save last 3 bytes of first 64bits of codre we'll replace
	u64 head = *((u64*)code);
	head = bswap64(head); // back to memory representation
	head &= 0x0000000000FFFFFFLL; 
		
	// keep only last 3 instructions bytes, first 5 will be replaced by JMP instr
	*ninstr &= 0xFFFFFFFFFF000000LL; // clear last 3 bytes
	*ninstr |= (head & 0x0000000000FFFFFFLL); // set last 3 bytes

	return 0;
}

struct arch_instr {
	void *code;
	u8 len;
};

static void
fixupInstr(
void *originalFunction,
void *escape,
void *instructionsToFix,
int instructionCount,
u8 *instructionSizes)
{
	for (int i = 0;i < instructionCount; i++) {
		if (*(u8*)instructionsToFix == 0xE9) {
			u32 offset = (uintptr_t)originalFunction - (uintptr_t)escape;
			u32 *jmp_offset = (u32*)((uintptr_t)instructionsToFix + 1);
			*jmp_offset += offset;
		}
		
		originalFunction = (void*)((uintptr_t)originalFunction + instructionSizes[i]);
		escape = (void*)((uintptr_t)escape + instructionSizes[i]);
		instructionsToFix = (void*)((uintptr_t)instructionsToFix + instructionSizes[i]);
    }
}

