config CC_FEATURES
	bool "Enable compiler features"
	help
	Say Y if you want to enable specific compiler features, such as
	stack protector.
	If you say N here, those features are not available.

config CC_PP_OUTPUT
	bool "Enable pre-processing output" 
	depends on CC_FEATURES
	default n
	help
	Say Y If you want to enable pre-processing output with extension .i

config CC_STACKPROTECTOR
	def_bool n
	depends on CC_FEATURES
	help
	Set when a stack-protector mode is enabled, so that the build
	can enable support for the GCC feature.

choice
	prompt "Stack Protector buffer overflow detection"
	depends on HAVE_CC_STACKPROTECTOR
	depends on CC_FEATURES
	default CC_STACKPROTECTOR_NONE
	help
	This option turns on the "stack-protector" GCC feature. This
	feature puts, at the beginning of functions, a canary value on
	the stack just before the return address, and validates
	the value just before actually returning.  Stack based buffer
	overflows (that need to overwrite this return address) now also
	overwrite the canary, which gets detected and the attack is then      
	neutralized via a kernel panic.                                       

config CC_STACKPROTECTOR_NONE                                                   
	bool "None"                                                             
	help                                                                    
	Disable "stack-protector" GCC feature.                                

config CC_STACKPROTECTOR_REGULAR                                                
	bool "Regular"                                                          
	select CC_STACKPROTECTOR                                                
	help                                                                    
	Functions will have the stack-protector canary logic added if they    
	have an 8-byte or larger character array on the stack.                

	This feature requires gcc version 4.2 or above, or a distribution     
	gcc with the feature backported ("-fstack-protector").                

	On an x86 "defconfig" build, this feature adds canary checks to       
	about 3% of all kernel functions, which increases kernel code size    
	by about 0.3%.

config CC_STACKPROTECTOR_STRONG                                                 
	bool "Strong"                                                           
	select CC_STACKPROTECTOR                                                
	help                                                                    
	Functions will have the stack-protector canary logic added in any     
	of the following conditions:                                          
					                                                                                    
	- local variable's address used as part of the right hand side of an  
	assignment or function argument                                     
	- local variable is an array (or union containing an array),          
	regardless of array type or length                                  
	- uses register local variables                                       

	This feature requires gcc version 4.9 or above, or a distribution     
	gcc with the feature backported ("-fstack-protector-strong").         

	On an x86 "defconfig" build, this feature adds canary checks to       
	about 20% of all package functions, which increases the code    
	size by about 2%.                                                     
	
endchoice

config CC_OPTIMIZE
	bool "Enable compiler optimizations"
	default y if !DEBUG
	depends on CC_FEATURES
	help
          Say Y if you want to enable debug functions, such as
          sys_dbg.
          If you say N here, those functions are not compiled.

choice
	prompt "Optimize "
	depends on CC_OPTIMIZE

config CC_OPTIMIZE_FOR_SPEED
        bool "for speed"
        depends on CC_OPTIMIZE
        help                                                                    
          Enabling this option will pass "-O2" instead of "-Os" to              
          your compiler resulting in a faster code.
                                                                                
          If unsure, say N

config CC_OPTIMIZE_FOR_SIZE
	bool "for size"
	depends on CC_OPTIMIZE
	help
	Enabling this option will pass "-Os" instead of "-O2" to
	your compiler resulting in a smaller code.

	If unsure, say N

endchoice


