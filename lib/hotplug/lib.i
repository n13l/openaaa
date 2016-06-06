%module(package="sys.plugable", jniclassname="Module",
        docstring="Bindings for hotplug library") "Device"

%javaconst(1);

%include "java/ctor.i"
%include "typemaps.i"
%include "cpointer.i"

%rename(HotPlug) hotplug;


%nodefaultctor hotplug;
%ignore hotplug_init;
%ignore hotplug_fini;
%ignore hotplug_wait;

%{
struct hotplug {} ;
#include "lib.h"
#include "jnu.h"
%}

struct hotplug { 
%extend {
                hotplug(int type, const char *name) { 
                        struct hotplug *hotplug = hotplug_init(); 
                        jnu_set_jclass((void *)hotplug, name);
                        return hotplug;
                }
                int
                event_wait() {
                        return hotplug_wait(self);
                }
                ~hotplug() { 
                        hotplug_fini(self);    
                }
}

};

%include "lib.h"
