%module(package="com.openaaa", 
        jniclassname="Module",
        docstring="Bindings for AAA library") "Device"

%include "typemaps.i"
%include "cpointer.i"

%rename(aaa) AAA;

%nodefaultctor aaa;
%ignore aaa_init;
%ignore aaa_fini;
%ignore aaa_wait;

%{
struct aaa {} ;
#include "lib.h"
%}

struct aaa { 
        %extend {
                aaa(int type) { 
                        struct aaa *aaa = aaa_new(type); 
                        return aaa;
                }
                ~aaa() { 
                        aaa_free(self);    
                }
        }

};

%include "..//lib.h"
