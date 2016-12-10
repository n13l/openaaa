# 
# toolprogs-y := example
# Will compile example.c and create an executable named example
#
# toolprogs-y := tool1
# tool1-y := main.o helper.o

__toolprogs := $(sort $(toolprogs-y))

# Executables compiled from a single .c file
tool-csingle := $(foreach m,$(__toolprogs),$(if $($(m)-y),,$(m)))

# Executables linked based on several .o files
tool-cmulti := $(foreach m,$(__toolprogs), $(if $($(m)-y),$(m)))

# Object (.o) files compiled from .c files
tool-cobjs := $(sort $(foreach m,$(__toolprogs),$($(m)-y)))

__obj_fixed := $(patsubst %/,%,$(obj))
__src_fixed := $(patsubst %/,%,$(src))

# Add $(obj) prefix to all paths
tool-csingle := $(addprefix $(__obj_fixed)/,$(tool-csingle))
tool-cmulti  := $(addprefix $(__obj_fixed)/,$(tool-cmulti))
tool-cobjs   := $(addprefix $(__obj_fixed)/,$(tool-cobjs))

# Options to toolcc.
toolc_flags = -Wp,-MD,$(depfile) $(KBUILD_CFLAGS) $(KBUILD_CPPFLAGS) \
	      $(USERINCLUDE) $(tool_CFLAGS) -I. -I../ \
	      -include $(srctree)/sys/$(PLATFORM)/platform.h

toolld_flags = 
toolld_builtin = sys/built-in.o \
		 posix/built-in.o mem/built-in.o arch/$(SRCARCH)/built-in.o
toolld_libs = $(KBUILD_LIBS)

# tool-csingle -> executable
quiet_cmd_tool-csingle = CC      $@
      cmd_tool-csingle = $(CC) $(toolc_flags) -o $@ $< $(toolld_builtin) \
                               $(toolld_libs)
#$(tool-csingle): $(obj)/%: $(src)/%.c FORCE
#	echo "tool-csingle: $@ $< $@.c $*"
#	$(call if_changed_dep,tool-csingle)

$(tool-csingle): $(__obj_fixed)/%: $(__src_fixed)/%.c FORCE
	$(call if_changed_dep,tool-csingle)

# tool-cobjs -> .o
quiet_cmd_tool-cobjs	= CC      $@
      cmd_tool-cobjs	= $(CC) $(toolc_flags) -c -o $@ $< 

$(tool-cobjs): $(__obj_fixed)/%.o: $(__src_fixed)/%.c FORCE
	$(call if_changed_dep,tool-cobjs)

# Link an executable based on list of .o files
quiet_cmd_tool-cmulti	= CC      $@
      cmd_tool-cmulti	= $(CC) $(toolld_flags) -o $@ \
			  $(addprefix $(obj)/,$($(@F)-y)) $(toolld_builtin) \
      			  $(toolld_libs)
$(tool-cmulti): $(__obj_fixed)/%: $(tool-cobjs) FORCE
	$(call if_changed,tool-cmulti)

# clean support
targets += $(tool-csingle) $(tool-cmulti) $(tool-cobjs)
always += $(tool-csingle) $(tool-cmulti)
