#include <sys/compiler.h>                                                       
#include <sys/cpu.h>                                                            
#include <sys/mman.h>                                                           
#include <asm/udis86.h>                                                         
#include <asm/cache.h>                                                          
#include <asm/instr.h>                                                          
#include <mem/page.h>                                                           

#include <mach-o/dyld.h>                                                        
#include <mach/mach_init.h>                                                     
#include <mach/vm_map.h>                                                        
#include <mach/error.h>                                                         
#include <mach/mach_error.h>                                                    

#include <CoreServices/CoreServices.h>

mach_error_t
mach_page_copy(void *addr, int len)
{
	vm_address_t page = (vm_address_t)addr;
	vm_map_t self = mach_task_self();
	mach_error_t e;

	if ((e = vm_protect(self, page, 8, false, (VM_PROT_ALL | VM_PROT_COPY) )))
		return e;

	return vm_protect(self, page, 8, false, (VM_PROT_DEFAULT | VM_PROT_COPY) );
}
