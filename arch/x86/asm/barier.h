#ifndef __X86_BARIER_H__                                                         
#define __X86_BARIER_H__ 

/* Compile read-write barrier */                                                
#define mem_barrier() asm volatile("": : :"memory")                                
/* Pause instruction to prevent excess processor bus usage */                   
#define cpu_relax() asm volatile("pause\n": : :"memory")

#endif
