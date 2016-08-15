#include <sys/compiler.h>

void 
page_set_key(unsigned long addr, unsigned char key)
{                                                                                  
/*	__asm ("sske %0, %1" : "d"(key) , "a"(addr));  */
}                                                                                  
                                                                                   
unsigned char 
page_get_key(unsigned long addr)               
{                                                                                  
        unsigned char key = 0;
/*	__asm__ ("iske %0,%1" : "=d"(key) : "a"(addr)); */
        return key;
}                                                                                  
                                                                                   
int 
page_reset_ref(unsigned long addr)                        
{                                                                                  
        unsigned int ipm = 0;                                                          
/*
        asm (                                                              
                "       rrbe    0,%1\n"                                            
                "       ipm     %0\n"                                              
                : "=d" (ipm) : "a" (addr) : "cc");                                 
*/
        return !!(ipm & 0x20000000);                                               
}                                                                                  
                                                                                   
/* Bits int the storage key */                                                     
#define S390_PAGE_CHANGED           0x02    /* changed bit               */         
#define S390_PAGE_REFERENCED        0x04    /* referenced bit            */         
#define S390_PAGE_BIT_FP            0x08    /* fetch protection bit      */         
#define S390_PAGE_BIT_ACC           0xf0    /* access control bits       */ 
