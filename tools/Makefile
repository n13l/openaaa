objs-y += tools/sysconfig

progs += sysconfig

sysconfig-dirs := $(package-dirs) 
sysconfig-objs := $(patsubst %,%/built-in.o, $(objs-y))
sysconfig-libs := $(patsubst %,%/lib.a, $(libs-y)) 
sysconfig-all  := $(sysconfig-objs) $(sysconfig-libs)

quiet_cmd_sysconfig = LD      tools/$@
	cmd_sysconfig = $(CC) $(EXE_LDFLAGS) $(LDFLAGS) -o $@ $(sysconfig-libs)\
	                      $(sysconfig-objs) $(KBUILD_LIBS)

$(obj)/sysconfig: $(sysconfig-all) FORCE
	$(call if_changed,sysconfig)

PHONY += $(sysconfig-dirs)
$(sysconfig-dirs): scripts_basic
	$(Q)$(MAKE) $(build)=$@

clean-files  += tools/sysconfig
