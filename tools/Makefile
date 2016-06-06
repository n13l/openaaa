#objs-y += tools/sysconfig
objs-y += tools/aaa

progs += aaa                                                                    
                                                                                
aaa-dirs := $(package-dirs) lib/aaa/
aaa-objs := $(patsubst %,%/built-in.o, $(objs-y))
aaa-libs := $(patsubst %,%/lib.a, $(libs-y)) 
aaa-all  := $(aaa-objs) $(aaa-libs)

quiet_cmd_aaa = LD      tools/$@
	cmd_aaa = $(CC) $(EXE_LDFLAGS) $(LDFLAGS) -o $@ $(aaa-libs) $(aaa-objs) $(KBUILD_LIBS)

$(obj)/aaa: $(aaa-all) FORCE
	$(call if_changed,aaa)

PHONY += $(aaa-dirs)
$(aaa-dirs): scripts_basic
	$(Q)$(MAKE) $(build)=$@

clean-files  += tools/aaa
